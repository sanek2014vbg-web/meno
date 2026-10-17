"""MeNo v2.0 — Пункт 9: Индикатор «Печатает...» (Typing Indicator).

Zero DB-touch: обработка статуса печати не выполняет ни одного запроса к
PostgreSQL. Единственные источники данных:

1. Redis TTL-ключ ``typing:{chat_id}:{user_id}`` (SETEX, TTL 6 секунд) —
   кластер-безопасное состояние "пользователь печатает", видимое всем
   воркерам и переживающее переподключения клиентов.
2. Redis Pub/Sub канал ``meno:ws`` — fan-out события ``user_typing`` на все
   воркеры, обслуживающие участников чата (через существующую WS-шину
   ws_manager.WSManager.send_to_user, Этап 5.1 ТЗ v1.1).

Каскад деградации (self-hosted без Redis):
- Redis доступен   -> SETEX + publish в meno:ws (multi-worker корректно).
- Redis недоступен -> локальный dict с monotonic-deadline (single worker).

Серверный rate limiting (защита от флуда, зеркалит клиентский debounce):
не более одного broadcast-события на TYPING_RATE_LIMIT_SECONDS между
событиями одного пользователя в одном чате. Событие stop («перестал
печатать», пустой текст) проходит всегда — оно дешёвое и улучшает UX.

Совместимость: импорты в едином стиле проекта (``server.*``), полный async.
Низкоуровневые Redis-операции идут через синглтон ``server.cache.cache``
(Этап 1.4); свой клиент модуль не создаёт.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Dict, Iterable, List, Optional, Tuple

log = logging.getLogger("meno.typing")

# --- Протокольные константы (должны совпадать с client/chat_ui.py) -----------
TYPING_TTL_SECONDS = 6            # TTL ключа и окно отображения на клиенте
TYPING_RATE_LIMIT_SECONDS = 2.0   # серверный anti-flood (зеркалит debounce клиента)
TYPING_KEY_PREFIX = "typing"      # typing:{chat_id}:{user_id}
TYPING_CHANNEL = "meno:typing"    # служебный канал для observability/тестов
STOP_SENTINELS = ("", None)       # пустой текст == "перестал печатать"


def typing_key(chat_id: int, user_id: int) -> str:
    """Канонический ключ состояния печати в Redis."""
    return f"{TYPING_KEY_PREFIX}:{int(chat_id)}:{int(user_id)}"


class TypingService:
    """Cluster-safe сервис статусов «печатает».

    Все методы идемпотентны и никогда не бросают исключений наружу —
    статусы печати это best-effort UX, они не должны ронять WS-сессию.
    """

    def __init__(self) -> None:
        # Локальный fallback: {(chat_id, user_id): deadline_monotonic}
        self._local: Dict[Tuple[int, int], float] = {}
        self._last_emit: Dict[Tuple[int, int], float] = {}

    # ---------------------------------------------------------------- #
    # Обработка входящего WS-события client_typing                       #
    # ---------------------------------------------------------------- #
    async def handle_client_event(
        self,
        *,
        chat_id: int,
        sender_user_id: int,
        member_ids: Iterable[int],
        text: Optional[str],
    ) -> dict:
        """Обрабатывает событие ``client_typing`` / ``typing`` от клиента.

        1. Ставит/снимает TTL-ключ в Redis (SETEX/DEL) либо локальный fallback.
        2. Транслирует событие ``user_typing`` всем участникам чата, кроме
           автора, через WS-шину: при включённом cache — публикация в канал
           ``meno:ws`` (fan-out на все воркеры), иначе — in-process доставка.

        Возвращает протокольный ack {"handled": bool, "reason": str}.
        """
        from server.ws_manager import manager  # ленивый импорт: нет циклов

        chat_id = int(chat_id)
        sender_user_id = int(sender_user_id)
        is_stop = text in STOP_SENTINELS

        # --- Серверный rate-limit (stop-события не лимитируются) ----------
        now = time.monotonic()
        pair = (chat_id, sender_user_id)
        if not is_stop:
            last = self._last_emit.get(pair, 0.0)
            if now - last < TYPING_RATE_LIMIT_SECONDS:
                # Молча гасим флуд, но продлеваем TTL, чтобы индикатор не мигал.
                await self._set_state(chat_id, sender_user_id, TYPING_TTL_SECONDS)
                return {"handled": True, "reason": "rate_limited"}
            self._last_emit[pair] = now

        # --- Состояние: Redis SETEX / DEL, либо локальный fallback ---------
        if is_stop:
            await self._clear_state(chat_id, sender_user_id)
        else:
            await self._set_state(chat_id, sender_user_id, TYPING_TTL_SECONDS)

        # --- Fan-out участникам чата (кроме автора) ------------------------
        payload = {
            "type": "user_typing",
            "chat_id": chat_id,
            "user_id": sender_user_id,
            "typing": not is_stop,
            "ttl": TYPING_TTL_SECONDS,
        }
        recipients = [int(uid) for uid in member_ids if int(uid) != sender_user_id]
        await manager.send_to_users(recipients, payload)

        # --- Служебная публикация в meno:typing (observability/тесты) ------
        await self._publish_debug(payload)

        return {"handled": True, "reason": "stopped" if is_stop else "broadcast"}

    # ---------------------------------------------------------------- #
    # Чтение состояния (REST /api/chats/{id}/typing, тесты)              #
    # ---------------------------------------------------------------- #
    async def active_typists(self, chat_id: int, user_ids: Iterable[int]) -> List[int]:
        """Id пользователей, которые «печатают сейчас» в чате.

        При доступном Redis читает TTL-ключи EXISTS (кластер-безопасно);
        иначе — локальный fallback со сравнением monotonic-deadline.
        Zero DB-touch.
        """
        from server.cache import cache

        chat_id = int(chat_id)
        result: List[int] = []
        for uid in user_ids:
            uid = int(uid)
            checked_remote = False
            if cache.enabled and cache.client is not None:
                try:
                    if await cache.client.exists(typing_key(chat_id, uid)):
                        result.append(uid)
                    checked_remote = True
                except Exception as exc:  # сетевой сбой — деградируем в local
                    log.debug("typing EXISTS failed: %s", exc.__class__.__name__)
            if not checked_remote:
                deadline = self._local.get((chat_id, uid))
                if deadline is not None and deadline > time.monotonic():
                    result.append(uid)
        return result

    async def is_typing(self, chat_id: int, user_id: int) -> bool:
        return bool(await self.active_typists(chat_id, [user_id]))

    # ---------------------------------------------------------------- #
    # Внутренняя реализация                                              #
    # ---------------------------------------------------------------- #
    async def _set_state(self, chat_id: int, user_id: int, ttl: int) -> None:
        """SETEX typing:{chat}:{user} ttl 1 — атомарная установка с TTL."""
        from server.cache import cache

        key = typing_key(chat_id, user_id)
        if cache.enabled and cache.client is not None:
            try:
                await cache.client.set(key, "1", ex=ttl)
                return
            except Exception as exc:
                log.warning("typing SETEX failed (%s) — local fallback", exc.__class__.__name__)
        self._local[(chat_id, user_id)] = time.monotonic() + ttl

    async def _clear_state(self, chat_id: int, user_id: int) -> None:
        from server.cache import cache

        key = typing_key(chat_id, user_id)
        self._local.pop((chat_id, user_id), None)
        self._last_emit.pop((chat_id, user_id), None)
        if cache.enabled and cache.client is not None:
            try:
                await cache.client.delete(key)
            except Exception as exc:
                log.debug("typing DEL failed: %s", exc.__class__.__name__)

    async def _publish_debug(self, payload: dict) -> None:
        """Дублирует событие в meno:typing для мониторинга/тестов.

        Основная доставка клиентам идёт через канал meno:ws
        (manager.send_to_users). Эта публикация — чисто observability:
        подписчики видят поток событий, не трогая WS-сеансы.
        """
        from server.cache import cache

        if not (cache.enabled and cache.client is not None):
            return
        try:
            await cache.client.publish(TYPING_CHANNEL, json.dumps(payload, default=str))
        except Exception as exc:
            log.debug("typing debug publish failed: %s", exc.__class__.__name__)

    def prune_local(self) -> int:
        """Чистка протухших записей локального fallback (вызывается janitor-ом)."""
        now = time.monotonic()
        stale = [k for k, dl in self._local.items() if dl <= now]
        for k in stale:
            self._local.pop(k, None)
        stale_em = [k for k in self._last_emit if k not in self._local]
        for k in stale_em:
            self._last_emit.pop(k, None)
        return len(stale)


# Синглтон сервиса (как cache / manager)
typing_service = TypingService()

__all__ = [
    "TypingService",
    "typing_service",
    "typing_key",
    "TYPING_TTL_SECONDS",
    "TYPING_RATE_LIMIT_SECONDS",
    "TYPING_CHANNEL",
    "STOP_SENTINELS",
]
