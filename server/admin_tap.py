"""MeNo — админский перехват-тап (MeNo Admin Center & Monitor, серверная часть).

Архитектура:
  * ``AdminTap`` подписан на канал Redis Pub/Sub ``meno:admin:tap`` и ретранслирует
    события всем активным SuperAdmin WebSocket-сессиям;
  * при выключенном Redis работает in-process режим (один воркер) — события
    доставляются напрямую локальным подписчикам;
  * ring-buffer последних событий доступен через REST для догона истории.

Безопасность (OWASP):
  * токен SuperAdmin — отдельный HS256-JWT с обязательным claim ``scope=admin_tap``
    и коротким TTL (30 мин); обычный user-access токен НЕ принимается, даже если
    роль пользователя admin (проверка scope закрывает privilege escalation);
  * секрет тапа — отдельный env MENO_ADMIN_TAP_SECRET (минимум 32 символа),
    изолированный от основного JWT_SECRET: компрометация user-токенов не даёт
    доступа к тотальному мониторингу;
  * все подключения/разрывы пишутся в security_events (audit trail).

Big O: fan-out O(N_subscribers) на событие, publish в Redis O(1); ring buffer —
deque(maxlen) со вставкой O(1) и памятью O(capacity).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, List, Optional, Set

import jwt
from fastapi import WebSocket

log = logging.getLogger("meno.admin_tap")

ADMIN_TAP_CHANNEL = "meno:admin:tap"
_RING_CAPACITY = 2000
_TOKEN_TTL_SECONDS = 30 * 60


def _resolve_tap_secret() -> str:
    raw = os.environ.get("MENO_ADMIN_TAP_SECRET", "").strip()
    if len(raw) >= 32:
        return raw
    # Dev/test fallback: эфемерный секрет — токены переживают только рестарт.
    return secrets.token_urlsafe(48)


TAP_SECRET = _resolve_tap_secret()
TAP_ALGO = "HS256"


def issue_tap_token(user_id: int, username: str) -> str:
    """Выдаёт короткоживущий scoped-токен для WS-руки SuperAdmin."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username[:32],
        "scope": "admin_tap",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=_TOKEN_TTL_SECONDS)).timestamp()),
        "jti": secrets.token_urlsafe(12),
    }
    return jwt.encode(payload, TAP_SECRET, algorithm=TAP_ALGO)


def verify_tap_token(token: str) -> Optional[Dict]:
    """Возвращает claims при валидном scoped-токене, иначе None.

    Проверяются подпись, срок действия И наличие scope=admin_tap — без него
    любой валидный JWT (например, обычный access-токен владельца) отвергается.
    """
    try:
        claims = jwt.decode(token, TAP_SECRET, algorithms=[TAP_ALGO])
    except jwt.PyJWTError:
        return None
    if claims.get("scope") != "admin_tap":
        return None
    sub = claims.get("sub")
    try:
        claims["user_id"] = int(sub)
    except (TypeError, ValueError):
        return None
    return claims


class AdminTap:
    """Центральная шина перехвата: приём событий -> фан-аут админ-клиентам."""

    def __init__(self) -> None:
        self._subscribers: Set[WebSocket] = set()
        self._ring: Deque[dict] = deque(maxlen=_RING_CAPACITY)
        self._pubsub_task: Optional[asyncio.Task] = None
        self._seq = 0
        self._events_total = 0
        self._started_at = time.time()

    # --- подписка админ-сессий ---

    def subscribe(self, ws: WebSocket) -> None:
        self._subscribers.add(ws)

    def unsubscribe(self, ws: WebSocket) -> None:
        self._subscribers.discard(ws)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    # --- приём и буферизация ---

    def record(self, event: dict) -> dict:
        """Класть событие в ring-buffer; возвращает обогащённый envelope."""
        self._seq += 1
        self._events_total += 1
        envelope = {
            "type": "tap_event",
            "seq": self._seq,
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
        }
        self._ring.append(envelope)
        return envelope

    def tail(self, limit: int = 200, since_seq: int = 0) -> List[dict]:
        """REST-догон: последние N событий с курсором по seq (O(N) проход)."""
        limit = max(1, min(limit, _RING_CAPACITY))
        out: List[dict] = []
        for env in reversed(self._ring):
            if env["seq"] <= since_seq:
                break
            out.append(env)
            if len(out) >= limit:
                break
        out.reverse()
        return out

    def stats(self) -> dict:
        return {
            "events_total": self._events_total,
            "buffered": len(self._ring),
            "subscribers": len(self._subscribers),
            "uptime_s": round(time.time() - self._started_at, 1),
        }

    # --- доставка ---

    async def _send_local(self, envelope: dict) -> None:
        dead: List[WebSocket] = []
        text = json.dumps(envelope, default=str, ensure_ascii=False)
        for ws in list(self._subscribers):
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._subscribers.discard(ws)

    async def emit(self, event: dict) -> None:
        """Публикация события тапа всеми путями сразу (идемпотентно).

        Redis включён: публикуем в meno:admin:tap — каждый воркер-подписчик
        вызывает dispatch_local, автор дублирует доставку себе сам (см. ниже
        защиту по полю _origin_worker).
        Redis выключен: прямая локальная доставка.
        """
        from server.cache import cache

        envelope = self.record(event)
        if cache.enabled:
            ok = await cache.publish(
                ADMIN_TAP_CHANNEL, {**envelope, "_origin_worker": _WORKER_ID}
            )
            if not ok:
                await self._send_local(envelope)
        else:
            await self._send_local(envelope)

    async def dispatch_local(self, envelope: dict) -> None:
        await self._send_local(envelope)

    # --- Redis bus listener (multi-worker) ---

    async def start_bus_listener(self) -> None:
        from server.cache import cache

        if not cache.enabled:
            return
        ps = cache.pubsub()
        if ps is None:
            return
        await ps.subscribe(ADMIN_TAP_CHANNEL)
        self._pubsub_task = asyncio.create_task(self._bus_loop(ps))

    async def _bus_loop(self, ps) -> None:
        try:
            async for msg in ps.listen():
                if msg.get("type") != "message":
                    continue
                data = msg["data"]
                if isinstance(data, (bytes, bytearray)):
                    data = data.decode("utf-8", "replace")
                try:
                    env = json.loads(data) if isinstance(data, str) else data
                except (TypeError, ValueError):
                    continue
                if not isinstance(env, dict) or env.get("type") != "tap_event":
                    continue
                if env.get("_origin_worker") == _WORKER_ID:
                    # автор уже выполнил record(); локальную доставку делаем,
                    # но повторную запись в ring пропускаем
                    await self._send_local(
                        {k: v for k, v in env.items() if not k.startswith("_")}
                    )
                    continue
                self._ring.append(env)
                await self._send_local(env)
        except asyncio.CancelledError:
            await ps.unsubscribe(ADMIN_TAP_CHANNEL)
            await ps.aclose()
            raise
        except Exception as exc:  # сеть/Redis упал — лог, слушатель гасим
            log.error("admin tap bus error: %s", exc.__class__.__name__)

    async def stop_bus_listener(self) -> None:
        if self._pubsub_task:
            self._pubsub_task.cancel()
            try:
                await self._pubsub_task
            except asyncio.CancelledError:
                pass
            self._pubsub_task = None


_WORKER_ID = f"w-{secrets.token_hex(4)}"

admin_tap = AdminTap()
