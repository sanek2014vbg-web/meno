"""MeNo — DevMode: панель владельца (мониторинг, модерация, глобальные настройки).

Только async-доступ к БД (SQLAlchemy 2.0), tz-aware UTC, audit-лог действий.

Безопасность SuperAdmin WS (hardening v2): соединение открывается ОДНОРАЗОВЫМ
5-секундным билетом (POST /api/admin/ws-ticket -> UUID в Redis, GETDEL за O(1)).
Долгоживущий scoped-JWT тапа больше не покидает HTTPS-тело и не светится в
query-string/логах прокси; перехваченный билет переиспользовать нельзя
(one-time), replay закрывается TTL=5s. Fallback in-process (dev без Redis) —
с тем же контрактом one-time + TTL.
"""

import asyncio
import hashlib
import json
import logging
import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, WebSocket
from pydantic import BaseModel, Field
from sqlalchemy import text as sql_text

from server import auth, config, database
from server.admin_tap import admin_tap, issue_tap_token, verify_tap_token
from server.cache import cache
from server.db.concurrency import conditional_update
from server.deps import get_current_user
from server import messages_errors as texts
from server.ws_manager import manager

log = logging.getLogger("meno.admin")

router = APIRouter(prefix="/api/admin", tags=["admin"])

# One-time WS-билет: короткое окно между выдачей и handshake.
TICKET_TTL_SECONDS = 5
_TICKET_PREFIX = "meno:admin:ws-ticket:"

# Скоупы тотального мониторинга (MeNo Admin Center & Monitor).
SCOPE_SESSIONS = "sessions"
SCOPE_MESSAGES = "messages"
SCOPE_FILES = "files"
SCOPE_JANITOR = "janitor"
# v2.0 корпоративного DLP-аудита: отдельный скоуп комплаенса — события
# compliance_read_audit шлются только сессиям, явно подписанным на него (по
# умолчанию подписан весь контур, т.к. TapSession стартует со ALL_SCOPES).
SCOPE_COMPLIANCE = "compliance"
ALL_SCOPES = frozenset(
    {SCOPE_SESSIONS, SCOPE_MESSAGES, SCOPE_FILES, SCOPE_JANITOR, SCOPE_COMPLIANCE}
)


class TapSession:
    """Одна активная SuperAdmin WS-сессия с её скоупами."""

    def __init__(self, ws: WebSocket, user_id: int, username: str) -> None:
        self.ws = ws
        self.user_id = user_id
        self.username = username
        self.scopes: set[str] = set(ALL_SCOPES)
        self.connected_at = time.time()
        self.events_sent = 0


_tap_sessions: set[TapSession] = set()

# In-process реестр one-time-билетов — fallback для dev-режима без Redis.
# Ключ: sha256(ticket), значение: (user_id, expires_at). Замки потокобезопасны
# (WS-handshake может обслуживаться вне того же потока, что HTTP-выдача).
_local_tickets: dict[str, tuple[int, float]] = {}
_local_tickets_lock = threading.Lock()


def _require_admin(user: dict) -> dict:
    if user["role"] != "admin":
        raise HTTPException(403, texts.t(texts.ADMIN_ONLY))
    return user


def _ticket_key(ticket: str) -> str:
    """Redis-ключ по хешу билета: сырой билет не попадает ни в логи, ни в
    листинг ключей мониторинга Redis."""
    digest = hashlib.sha256(ticket.encode("utf-8")).hexdigest()
    return f"{_TICKET_PREFIX}{digest}"


def _local_issue(user_id: int) -> str:
    ticket = uuid4_hex()
    with _local_tickets_lock:
        now = time.time()
        # Компакция просроченных записей при выдаче — словарь не растёт O(N).
        expired = [k for k, (_, exp) in _local_tickets.items() if exp <= now]
        for k in expired:
            _local_tickets.pop(k, None)
        _local_tickets[_hash_ticket(ticket)] = (user_id, now + TICKET_TTL_SECONDS)
    return ticket


def _local_consume(ticket: str) -> Optional[int]:
    """One-time чтение+удаление под одним замком (атомарно против переиспользования)."""
    key = _hash_ticket(ticket)
    with _local_tickets_lock:
        entry = _local_tickets.pop(key, None)
    if entry is None:
        return None
    user_id, expires_at = entry
    if expires_at <= time.time():
        return None
    return user_id


def _hash_ticket(ticket: str) -> str:
    return hashlib.sha256(ticket.encode("utf-8")).hexdigest()


def uuid4_hex() -> str:
    """Криптографически случайный билет формата uuid4().hex (32 hex, без
    дефисов; version/variant RFC-4122 выставлены вручную через secrets —
    тот же класс энтропии, что uuid.UUID(bytes=...), но CSPRNG-источник)."""
    b = bytearray(secrets.token_bytes(16))
    b[6] = (b[6] & 0x0F) | 0x40  # version 4
    b[8] = (b[8] & 0x3F) | 0x80  # variant RFC-4122
    return bytes(b).hex()


async def issue_ws_ticket(user_id: int) -> str:
    """Сохраняет one-time билет в Redis (SETEX 5s); без Redis — local fallback."""
    ticket = uuid4_hex()
    rclient = cache.client
    if rclient is not None:
        try:
            await rclient.set(_ticket_key(ticket), str(user_id), ex=TICKET_TTL_SECONDS)
            return ticket
        except Exception as exc:
            log.error("ticket store failed: %s", exc.__class__.__name__)
            raise HTTPException(503, texts.t(texts.TAP_REDIS_UNAVAILABLE)) from exc
    return _local_issue(user_id)


async def consume_ws_ticket(ticket: str) -> Optional[int]:
    """Проверка и ОДНОВРЕМЕННОЕ удаление билета.

    Redis >= 6.2: GETDEL — атомарные read+delete за O(1), переиспользование
    невозможно даже при гонке двух handshake'ов.
    Redis < 6.2: Lua EVAL (GET+DEL в одном скрипте — та же атомарность).
    Без Redis: pop под локальным замком.
    """
    if not ticket or len(ticket) > 64:
        return None
    rclient = cache.client
    if rclient is not None:
        key = _ticket_key(ticket)
        try:
            value = await rclient.getdel(key)
        except Exception:
            try:
                value = await rclient.eval(
                    "local v = redis.call('GET', KEYS[1]); "
                    "if v then redis.call('DEL', KEYS[1]) end; return v",
                    1,
                    key,
                )
            except Exception as exc:
                log.error("ticket consume failed: %s", exc.__class__.__name__)
                raise HTTPException(503, texts.t(texts.TAP_REDIS_UNAVAILABLE)) from exc
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return _local_consume(ticket)


_COMPLIANCE_TABLE_OK: Optional[bool] = None


def _compliance_table_present(sync_conn) -> bool:
    """Наличие compliance_audit_logs (run_sync-колбэк; кэш результата на процесс).

    Колбэк получает синхронный Connection в greenlet-контексте пула —
    безопасно и на aiosqlite, и на asyncpg. Вызывается как
    ``await db.run_sync(_compliance_table_present)``. Таблица создаётся миграцией
    c8d9e0f1a2b3; в БД из старых дампов её может не быть — эндпоинт отвечает
    честным 503 вместо 500 'no such table'. Кэш: схема меняется только с
    миграцией (тот же приём, что janitor._SCHEMA_EXPIRES_AT).
    """
    global _COMPLIANCE_TABLE_OK
    if _COMPLIANCE_TABLE_OK is None:
        try:
            from sqlalchemy import inspect as sa_inspect

            _COMPLIANCE_TABLE_OK = (
                "compliance_audit_logs" in sa_inspect(sync_conn).get_table_names()
            )
        except Exception:
            _COMPLIANCE_TABLE_OK = False
    return _COMPLIANCE_TABLE_OK


@router.get("/stats")
async def stats(user: dict = Depends(get_current_user)):
    _require_admin(user)
    async with database.get_db() as db:
        users_n = (await database.aq1(db, "SELECT COUNT(*) AS c FROM users"))["c"]
        chats_n = (await database.aq1(db, "SELECT COUNT(*) AS c FROM chats"))["c"]
        msgs_n = (await database.aq1(db, "SELECT COUNT(*) AS c FROM messages"))["c"]
        reports_n = (
            await database.aq1(
                db, "SELECT COUNT(*) AS c FROM reports WHERE status='open'"
            )
        )["c"]
    return {
        "users": users_n,
        "chats": chats_n,
        "messages": msgs_n,
        "open_reports": reports_n,
        "online_now": manager.online_count,
    }


@router.get("/reports")
async def reports(user: dict = Depends(get_current_user)):
    _require_admin(user)
    async with database.get_db() as db:
        rows = await database.aq(
            db,
            "SELECT r.*, m.content AS msg_content, m.type AS msg_type, "
            "u.display_name AS reporter_name, c.title AS chat_title "
            "FROM reports r "
            "JOIN messages m ON m.id=r.message_id "
            "JOIN users u ON u.id=r.reporter_id "
            "JOIN chats c ON c.id=r.chat_id "
            "WHERE r.status='open' ORDER BY r.id DESC",
        )
        return rows


class ModerationAction(BaseModel):
    report_id: int
    action: str = Field(..., pattern="^(resolve|delete_message)$")


@router.post("/moderation")
async def moderation(body: ModerationAction, user: dict = Depends(get_current_user)):
    _require_admin(user)
    async with database.get_db() as db:
        report = await database.aq1(
            db, "SELECT * FROM reports WHERE id=:id", {"id": body.report_id}
        )
        if not report:
            raise HTTPException(404, texts.t(texts.ADMIN_REPORT_NOT_FOUND))
        if body.action == "resolve":
            await db.execute(
                sql_text("UPDATE reports SET status='resolved' WHERE id=:id"),
                {"id": report["id"]},
            )
            await auth.log_security_event(
                "report_resolved", user_id=user["id"], detail=f"report={report['id']}"
            )
            return {"ok": True, "message": "Жалоба закрыта"}
        if body.action == "delete_message":
            msg = await database.aq1(
                db, "SELECT * FROM messages WHERE id=:id", {"id": report["message_id"]}
            )
            if not msg:
                raise HTTPException(404, texts.t(texts.ADMIN_MSG_NOT_FOUND))
            await db.execute(
                sql_text("DELETE FROM messages WHERE id=:id"), {"id": msg["id"]}
            )
            await db.execute(
                sql_text("UPDATE reports SET status='resolved' WHERE id=:id"),
                {"id": report["id"]},
            )
            members = [
                r["user_id"]
                for r in await database.aq(
                    db,
                    "SELECT user_id FROM chat_members WHERE chat_id=:cid",
                    {"cid": msg["chat_id"]},
                )
            ]
        else:
            return {"ok": False}
    await manager.send_to_users(
        members,
        {"type": "message_deleted", "message_id": msg["id"], "chat_id": msg["chat_id"]},
    )
    await auth.log_security_event(
        "message_deleted_by_admin", user_id=user["id"], detail=f"message={msg['id']}"
    )
    return {"ok": True, "message": "Сообщение удалено, жалоба закрыта"}


@router.get("/settings")
async def get_settings(user: dict = Depends(get_current_user)):
    _require_admin(user)
    async with database.get_db() as db:
        rows = await database.aq(db, "SELECT key, value FROM settings")
    return {r["key"]: r["value"] for r in rows}


class SettingUpdate(BaseModel):
    key: str = Field(..., min_length=1, max_length=60)
    value: str = Field(default="")


@router.put("/settings")
async def set_setting(body: SettingUpdate, user: dict = Depends(get_current_user)):
    _require_admin(user)
    key, value = body.key.strip(), body.value
    async with database.get_db() as db:
        existing = await database.aq1(
            db, "SELECT key FROM settings WHERE key=:k", {"k": key}
        )
        if existing:
            await db.execute(
                sql_text("UPDATE settings SET value=:v WHERE key=:k"),
                {"v": value, "k": key},
            )
        else:
            await db.execute(
                sql_text("INSERT INTO settings (key, value) VALUES (:k, :v)"),
                {"k": key, "v": value},
            )
    await auth.log_security_event(
        "setting_changed", user_id=user["id"], detail=f"{key}={value!r}"
    )
    return {"ok": True, "key": key, "value": value}


@router.get("/audit")
async def audit_log(limit: int = 100, user: dict = Depends(get_current_user)):
    """Просмотр audit-лога значимых событий (Этап 2.3 ТЗ)."""
    _require_admin(user)
    limit = max(1, min(limit, 500))
    async with database.get_db() as db:
        rows = await database.aq(
            db,
            "SELECT * FROM security_events ORDER BY id DESC LIMIT :n",
            {"n": limit},
        )
    return rows


# ---------------------------------------------------------------------------
# MeNo Admin Center & Monitor: тотальный мониторинг (SuperAdmin tap)
# ---------------------------------------------------------------------------


async def broadcast_tap(event: dict) -> None:
    """Точка врезки для бизнес-кода: событие уходит в шину тапа и админ-сессиям.

    Никогда не бросает исключений в вызывающий путь — мониторинг не должен
    ронять пользовательскую операцию (fail-open, с логом).
    """
    try:
        await admin_tap.emit(event)
    except Exception as exc:
        log.error("tap emit failed: %s", exc.__class__.__name__)
    scope = event.get("scope")
    if scope:
        dead: list[TapSession] = []
        text = json.dumps(
            {
                "type": "tap_event",
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": event,
            },
            default=str,
            ensure_ascii=False,
        )
        for sess in list(_tap_sessions):
            if scope not in sess.scopes:
                continue
            try:
                await sess.ws.send_text(text)
                sess.events_sent += 1
            except Exception:
                dead.append(sess)
        for sess in dead:
            _tap_sessions.discard(sess)


@router.post("/tap-token")
async def tap_token(user: dict = Depends(get_current_user)):
    """Выдаёт короткоживущий scoped-токен для WS /api/admin/ws/tap.

    Двойная проверка: роль admin из JWT + повторное чтение актуальной роли из
    кеша пользователей — понижение прав «на лету» мгновенно блокирует выдачу.

    NOTE (hardening v2): токен нужен только для подписания служебных payload'ов
    и обратной совместимости старых клиентов; живой handshake тапа выполняется
    ИСКЛЮЧИТЕЛЬНО по one-time билету POST /api/admin/ws-ticket.
    """
    _require_admin(user)
    fresh = await auth.get_user_by_id(user["id"])
    if fresh is None or fresh.get("role") != "admin":
        raise HTTPException(403, texts.t(texts.ADMIN_ROLE_REVOKED))
    token = issue_tap_token(user["id"], user.get("username", ""))
    await auth.log_security_event(
        "admin_tap_token_issued", user_id=user["id"], detail="tap session token"
    )
    expires_in = 30 * 60
    return {"token": token, "expires_in": expires_in, "scopes": sorted(ALL_SCOPES)}


@router.post("/ws-ticket")
async def ws_ticket(user: dict = Depends(get_current_user)):
    """One-time билет для SuperAdmin WebSocket (POST /api/admin/ws-ticket).

    Генерирует криптографический UUID4, кладёт sha256(билет) -> user_id в Redis
    c TTL 5 секунд. Билет одноразовый: consume_ws_ticket удаляет его за O(1)
    (GETDEL / Lua), поэтому перехват трафика или лог прокси не даёт переиспользуемого
      секрета — окно replay ограничено 5 секундами.
    Выдача требует полноценного admin-JWT (Depends get_current_user) и повторной
    проверки актуальной роли — понижение прав мгновенно блокирует новые билеты.
    """
    _require_admin(user)
    fresh = await auth.get_user_by_id(user["id"])
    if fresh is None or fresh.get("role") != "admin":
        raise HTTPException(403, texts.t(texts.ADMIN_ROLE_REVOKED))
    ticket = await issue_ws_ticket(user["id"])
    await auth.log_security_event(
        "admin_ws_ticket_issued", user_id=user["id"],
        detail=f"ttl={TICKET_TTL_SECONDS}s",
    )
    return {
        "ticket": ticket,
        "expires_in": TICKET_TTL_SECONDS,
        "ws_path": "/api/admin/ws/tap",
    }


@router.get("/users")
async def admin_users(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: dict = Depends(get_current_user),
):
    """Таблица пользователей + онлайн-статус (O(N) по странице, индекс по id).

    Флаг ban вычисляется от существующего столбца lockout_until (временная
    блокировка за серии неверных паролей): в модели User нет колонки is_active,
    и SELECT с ней падал с 'no such column' — дефект-фикс аудита.
    """
    _require_admin(user)
    async with database.get_db() as db:
        rows = await database.aq(
            db,
            "SELECT id, username, display_name, role, created_at, last_seen, "
            "(CASE WHEN lockout_until IS NOT NULL AND lockout_until > "
            "CURRENT_TIMESTAMP THEN 1 ELSE 0 END) AS banned "
            "FROM users ORDER BY id LIMIT :n OFFSET :o",
            {"n": limit, "o": offset},
        )
    online_ids = set(manager._connections.keys())
    for r in rows:
        r["online"] = r["id"] in online_ids
    return rows


@router.get("/sessions")
async def admin_sessions(
    user_id: Optional[int] = Query(None, ge=1),
    include_revoked: bool = Query(False),
    limit: int = Query(500, ge=1, le=2000),
    user: dict = Depends(get_current_user),
):
    """Активные refresh-сессии (без хешей токенов — только метаданные)."""
    _require_admin(user)
    where = ""
    params: dict = {"n": limit}
    conds = []
    if not include_revoked:
        conds.append("revoked=0")
    if user_id is not None:
        conds.append("user_id=:uid")
        params["uid"] = user_id
    if conds:
        where = "WHERE " + " AND ".join(conds)
    async with database.get_db() as db:
        rows = await database.aq(
            db,
            # PK refresh_tokens — строковый token (числового id нет): отдаём
            # token как идентификатор сессии + метаданные family/created_at.
            "SELECT s.token, s.user_id, u.username, s.family, s.created_at, "
            "s.expires_at, s.revoked FROM refresh_tokens s "
            "JOIN users u ON u.id=s.user_id "
            f"{where} ORDER BY s.created_at DESC LIMIT :n",
            params,
        )
    return rows


class KillSessionsBody(BaseModel):
    user_id: int = Field(..., ge=1)
    reason: str = Field(default="admin_kill", max_length=120)


@router.post("/sessions/kill")
async def kill_sessions(body: KillSessionsBody, user: dict = Depends(get_current_user)):
    """Принудительный разрыв всех сессий пользователя.

    Оптимистичная блокировка (db/concurrency.conditional_update): отзыв
    выполняется условным UPDATE revoked=0 -> revoked=1; параллельный отзыв
    тем же или другим админом теряет гонку (rowcount меньше фактического
    числа строк) и получает честный счётчик, без lost update.
    """
    _require_admin(user)
    target = await auth.get_user_by_id(body.user_id)
    if target is None:
        raise HTTPException(404, texts.t(texts.ADMIN_USER_NOT_FOUND))
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    async with database.get_db() as db:
        affected = await conditional_update(
            db,
            table="refresh_tokens",
            set_assignments={"revoked": True, "expires_at": now},
            where_assignments={"user_id": body.user_id, "revoked": False},
        )
        await db.commit()
    await auth._invalidate_user_cache(body.user_id)
    await manager.send_to_user(
        body.user_id, {"type": "session_killed", "reason": body.reason}
    )
    await auth.log_security_event(
        "admin_kill_sessions",
        user_id=user["id"],
        detail=f"target={body.user_id} revoked={affected} reason={body.reason!r}",
    )
    await broadcast_tap(
        {
            "scope": SCOPE_SESSIONS,
            "kind": "sessions_killed",
            "actor_id": user["id"],
            "target_user_id": body.user_id,
            "revoked_count": affected,
            "reason": body.reason,
        }
    )
    return {"ok": True, "revoked": affected}


class RoleUpdateBody(BaseModel):
    role: str = Field(..., pattern="^(user|admin)$")


@router.put("/users/{user_id}/role")
async def set_role(
    user_id: int, body: RoleUpdateBody, user: dict = Depends(get_current_user)
):
    """Изменение прав модерации на лету (CAS по предыдущей роли)."""
    _require_admin(user)
    if user_id == user["id"]:
        raise HTTPException(400, texts.t(texts.ADMIN_SELF_ROLE))
    current = await auth.get_user_by_id(user_id)
    if current is None:
        raise HTTPException(404, texts.t(texts.ADMIN_USER_NOT_FOUND))
    old_role = current["role"]
    async with database.get_db() as db:
        won = await conditional_update(
            db,
            table="users",
            set_assignments={"role": body.role},
            where_assignments={"id": user_id, "role": old_role},
        )
        await db.commit()
    if not won:
        raise HTTPException(409, texts.t(texts.ADMIN_ROLE_RACE))
    await auth._invalidate_user_cache(user_id)
    await auth.log_security_event(
        "admin_role_change",
        user_id=user["id"],
        detail=f"target={user_id} {old_role}->{body.role}",
    )
    await broadcast_tap(
        {
            "scope": SCOPE_SESSIONS,
            "kind": "role_changed",
            "actor_id": user["id"],
            "target_user_id": user_id,
            "old_role": old_role,
            "new_role": body.role,
        }
    )
    return {"ok": True, "user_id": user_id, "role": body.role}


@router.get("/messages/recent")
async def recent_messages(
    before_id: Optional[int] = Query(None, ge=1),
    limit: int = Query(100, ge=1, le=500),
    user: dict = Depends(get_current_user),
):
    """Курсорная лента всех сообщений (перехват chat history).

    O(log M + N): seek по PK-индексу messages.id, никакого сканирования;
    JOIN users/chats даёт имена за один round-trip (N+1 исключён).
    """
    _require_admin(user)
    params: dict = {"n": limit}
    cursor = ""
    if before_id is not None:
        cursor = "AND m.id < :before"
        params["before"] = before_id
    async with database.get_db() as db:
        rows = await database.aq(
            db,
            "SELECT m.id, m.chat_id, m.sender_id, m.type, m.content, m.created_at, "
            "m.expires_at, u.username AS sender_name, c.title AS chat_title "
            "FROM messages m "
            "LEFT JOIN users u ON u.id=m.sender_id "
            "LEFT JOIN chats c ON c.id=m.chat_id "
            f"WHERE 1=1 {cursor} ORDER BY m.id DESC LIMIT :n",
            params,
        )
    return rows


@router.get("/compliance-logs")
async def compliance_logs(
    chat_id: Optional[int] = Query(None, ge=1),
    author_id: Optional[int] = Query(None, ge=1),
    before: Optional[str] = Query(
        None, max_length=64, description="Курсор logged_at (ISO-8601): страницы строго назад"
    ),
    limit: int = Query(100, ge=1, le=500),
    meno_ticket: Optional[str] = Header(
        default=None,
        alias="X-Meno-Ticket",
        description="Одноразовый superadmin-билет POST /api/admin/ws-ticket",
    ),
    user: dict = Depends(get_current_user),
):
    """Пагинированный список записей журнала корпоративного DLP-аудита.

    Журнал фиксирует исчезающие сообщения (ttl_seconds), которые дворник
    физически стирает из основной таблицы по expires_at; копия остаётся здесь
    в соответствии с политикой хранения, объявленной в пользовательском
    соглашении (Privacy Policy).

    Доступ (двойной контур): роль admin из JWT (Depends get_current_user +
    _require_admin) И ОДНОРАЗОВЫЙ билет ws-ticket, предъявленный заголовком
    ``X-Meno-Ticket`` — тот же consume_ws_ticket (Redis GETDEL/Lua, O(1)),
    что и для handshake тапа. Чтение журнала комплаенса подтверждается
    свежим секретом разового использования: украденный long-lived access-JWT
    сам по себе список не отдаст; повторное предъявление билета -> 401.

    Курсорная пагинация by logged_at DESC (составной индекс
    idx_compliance_logs_chat_logged покрывает путь с фильтром по чату):
    O(log N + limit), без OFFSET-скана. Каждое чтение пишется в
    security_events и транслируется в тап — аудит доступа к журналу полон.
    """
    _require_admin(user)
    if not meno_ticket:
        raise HTTPException(401, texts.t(texts.ADMIN_TICKET_REQUIRED))
    ticket_owner = await consume_ws_ticket(meno_ticket)
    if ticket_owner is None or ticket_owner != user["id"]:
        # Единый ответ для «неверный / просрочен / уже использован / чужой» —
        # без oracle'а перебора (anti-enumeration, как в WS-handshake).
        await auth.log_security_event(
            "admin_compliance_ticket_rejected", user_id=user["id"], detail="invalid/expired/used"
        )
        raise HTTPException(401, texts.t(texts.ADMIN_TICKET_INVALID))

    async with database.get_db() as db:
        if not await db.run_sync(_compliance_table_present):
            raise HTTPException(503, texts.t(texts.COMPLIANCE_TABLE_MISSING))
        conds, params = [], {"n": limit}
        if chat_id is not None:
            conds.append("s.chat_id = :cid")
            params["cid"] = chat_id
        if author_id is not None:
            conds.append("s.author_id = :aid")
            params["aid"] = author_id
        if before:
            conds.append("s.logged_at < :before")
            params["before"] = before
        where = ("WHERE " + " AND ".join(conds)) if conds else ""
        rows = await database.aq(
            db,
            "SELECT s.id, s.message_id, s.chat_id, s.author_id, s.body, "
            "s.logged_at, u.username AS author_name, c.title AS chat_title "
            "FROM compliance_audit_logs s "
            "LEFT JOIN users u ON u.id = s.author_id "
            "LEFT JOIN chats c ON c.id = s.chat_id "
            f"{where} ORDER BY s.logged_at DESC, s.id DESC LIMIT :n",
            params,
        )
    await auth.log_security_event(
        "admin_compliance_logs_read",
        user_id=user["id"],
        detail=f"rows={len(rows)} chat={chat_id} author={author_id}",
    )
    await broadcast_tap(
        {
            "scope": SCOPE_COMPLIANCE,
            "kind": "compliance_read_audit",
            "actor_id": user["id"],
            "rows_returned": len(rows),
            "filter_chat_id": chat_id,
        }
    )
    next_cursor = str(rows[-1]["logged_at"]) if len(rows) == limit else None
    return {"items": rows, "next_cursor": next_cursor, "has_more": len(rows) == limit}


@router.get("/files/recent")
async def recent_files(
    limit: int = Query(100, ge=1, le=500),
    user: dict = Depends(get_current_user),
):
    """Последние загруженные файлы (метаданные; контент в S3/MinIO)."""
    _require_admin(user)
    async with database.get_db() as db:
        rows = await database.aq(
            db,
            "SELECT f.id, f.chat_id, f.uploader_id, f.file_name, f.size, "
            "f.mime_type, f.created_at, u.username AS uploader_name "
            "FROM files f LEFT JOIN users u ON u.id=f.uploader_id "
            "ORDER BY f.id DESC LIMIT :n",
            {"n": limit},
        )
    return rows


@router.get("/janitor/jobs")
async def janitor_jobs(user: dict = Depends(get_current_user)):
    """Состояние TTL-джоб (визуализация фоновой очистки в мониторе)."""
    _require_admin(user)
    async with database.get_db() as db:
        # Колонки строго соответствуют ORM JanitorJob (server/db/models_base):
        # status/owner/last_deleted_count/updated_at. Прежний SELECT ссылался на
        # несуществующие next_run_at/lease_*/version — 'no such column' на любом
        # движке. Псевдо-колонки раскрываем через NULL, чтобы контракт ответа
        # монитора (JOB_HEADERS) не менялся.
        rows = await database.aq(
            db,
            "SELECT job, table_name, ttl_column, grace_seconds, interval_seconds, "
            "enabled, status AS last_status, owner AS lease_owner, "
            "last_run_at, last_deleted_count AS last_rows_deleted, updated_at "
            "FROM janitor_jobs ORDER BY job",
        )
    for r in rows:
        r.setdefault("next_run_at", None)
        r.setdefault("consecutive_failures", 0)
        r.setdefault("version", 0)
    return rows


@router.get("/tap/stats")
async def tap_stats(user: dict = Depends(get_current_user)):
    _require_admin(user)
    return {
        **admin_tap.stats(),
        "tap_sessions": len(_tap_sessions),
        "server_online_users": manager.online_count,
    }


@router.get("/tap/events")
async def tap_events(
    since_seq: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=2000),
    user: dict = Depends(get_current_user),
):
    """REST-догон ring-buffer'а после реконнекта монитора."""
    _require_admin(user)
    return {"events": admin_tap.tail(limit=limit, since_seq=since_seq)}


@router.websocket("/ws/tap")
async def superadmin_ws(websocket: WebSocket):
    """SuperAdmin WebSocket: трансляция ВСЕХ событий экосистемы в реальном времени.

    Авторизация (hardening v2): ОДНОРАЗОВЫЙ 5-секундный билет, выданный
    POST /api/admin/ws-ticket — в query ``ticket`` либо в subprotocol
    ``meno-tap.<ticket>`` (совместимо с websockets-клиентами). Билет проверяется
    consume_ws_ticket(): Redis GETDEL/Lua удаляет его за O(1) — повторное
    использование невозможно; затем роль администратора перечитывается из
    кеша пользователей (мгновенный отзыв прав блокирует даже свежий билет).

    Legacy scoped-JWT (query ``token``) принимается только пока включён флаг
    MENO_ADMIN_TAP_LEGACY_TOKEN=1 — для плавной миграции старых клиентов монитора.
    """
    ticket: Optional[str] = websocket.query_params.get("ticket")
    legacy_token: Optional[str] = websocket.query_params.get("token")
    raw_protocols = websocket.headers.get("sec-webprotocol", "") or websocket.headers.get(
        "sec-websocket-protocol", ""
    )
    negotiated: Optional[str] = None
    for part in (p.strip() for p in raw_protocols.split(",")):
        if part.startswith("meno-tap."):
            value = part[len("meno-tap."):]
            if ticket is None and not legacy_token:
                ticket = value
                negotiated = part
            elif legacy_token is None:
                legacy_token = value
                negotiated = part
            break

    user_id: Optional[int] = None
    used_ticket = False
    if ticket:
        try:
            user_id = await consume_ws_ticket(ticket)
        except HTTPException:
            # Redis упал между выдачей и handshake — честный отказ, не silent miss.
            await websocket.close(code=4403)
            return
        used_ticket = True
        if user_id is None:
            # Неверный/просроченный/уже использованный билет: единый код и
            # единая причина закрытия — без oracle'а перебора (anti-enumeration).
            await auth.log_security_event(
                "admin_ws_ticket_rejected", detail="invalid/expired/used"
            )
            await websocket.close(code=4403)
            return
    elif legacy_token and getattr(config, "MENO_ADMIN_TAP_LEGACY_TOKEN", False):
        claims = verify_tap_token(legacy_token)
        if claims is None:
            await websocket.close(code=4403)
            return
        user_id = claims["user_id"]

    if user_id is None:
        await websocket.close(
            code=4401, reason=texts.t(texts.ADMIN_TICKET_REQUIRED)[:120]
        )
        return

    actor = await auth.get_user_by_id(user_id)
    if actor is None or actor.get("role") != "admin":
        await auth.log_security_event(
            "admin_ws_role_revoked_close", user_id=user_id,
            detail="ticket consumed but role not admin" if used_ticket else "legacy token",
        )
        await websocket.close(code=4403)
        return

    # accept с эхом subprotocol — иначе strict-клиенты обрывают handshake.
    await websocket.accept(subprotocol=negotiated)
    sess = TapSession(websocket, user_id, actor.get("username", ""))
    _tap_sessions.add(sess)
    # subscribe() ПОСЛЕ hello+backfill: ring-буфер глобален (переживает
    # соединения), а подписку до hello админ получал бы live tap_event'ы
    # вперемешку с бэкфиллом — контракт «hello -> backfill -> live» нарушался.
    await auth.log_security_event(
        "admin_tap_connected",
        user_id=sess.user_id,
        detail="superadmin ws open via one-time ticket" if used_ticket else "superadmin ws open via legacy token",
    )
    await websocket.send_json(
        {
            "type": "tap_hello",
            "user_id": sess.user_id,
            "scopes": sorted(sess.scopes),
            "buffered": admin_tap.stats()["buffered"],
        }
    )
    # Догонring-буфера сразу после hello: события, записанные до подключения,
    # доставляются одним кадром и только потом открывается live-поток.
    initial_backfill = admin_tap.tail(limit=200, since_seq=0)
    await websocket.send_json({"type": "backfill", "events": initial_backfill})
    admin_tap.subscribe(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            mtype = data.get("type")
            if mtype == "ping":
                await websocket.send_json({"type": "pong"})
            elif mtype == "set_scopes":
                requested = {s for s in data.get("scopes", []) if s in ALL_SCOPES}
                sess.scopes = requested or set(ALL_SCOPES)
                await websocket.send_json(
                    {"type": "scopes_ack", "scopes": sorted(sess.scopes)}
                )
            elif mtype == "backfill":
                events = admin_tap.tail(
                    limit=int(data.get("limit", 200)),
                    since_seq=int(data.get("since_seq", 0)),
                )
                await websocket.send_json({"type": "backfill", "events": events})
    except Exception:
        pass
    finally:
        _tap_sessions.discard(sess)
        admin_tap.unsubscribe(websocket)
        asyncio.ensure_future(
            auth.log_security_event(
                "admin_tap_disconnected",
                user_id=sess.user_id,
                detail=f"events_sent={sess.events_sent}",
            )
        )
