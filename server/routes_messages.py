"""MeNo — маршруты сообщений: отправка, история, поиск, исчезающие сообщения.

Ключевые свойства (ТЗ):
- курсорная пагинация истории и поиска (Этап 4.4);
- идемпотентность отправки по client_id + дедупликация (Этап 4.5);
- транзакционная запись: INSERT сообщения и commit в одной сессии, WS/push
  — только после успешного коммита;
- полнотекстовый поиск с поддержкой кириллицы: на PG используется
  to_tsvector('russian'), на SQLite — переносимый LIKE (Этап 4.2);
- антиспам-лимит по окну времени (tz-aware UTC).
"""
from datetime import timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import text as sql_text
from sqlalchemy.exc import IntegrityError

from server import auth, config, database, push as push_service
from server.deps import get_current_user, is_chat_member
from server.rate_limit import user_key, limiter
from server.utils import as_utc, utc_now
from server.ws_manager import manager

router = APIRouter(prefix="/api", tags=["messages"])


class SendMessageRequest(BaseModel):
    type: str = Field(default="text", pattern="^(text|image|file|voice|emoji)$")
    content: str = Field(default="", max_length=4000)
    media_path: str = Field(default="")
    duration: Optional[int] = Field(default=0, description="Длительность аудио в секундах")
    ttl_seconds: Optional[int] = Field(default=None, ge=5, le=86400 * 7)
    view_once: bool = False
    e2e: bool = False
    client_id: Optional[str] = Field(
        default=None, min_length=8, max_length=64,
        description="Идемпотентный ключ клиента: повторная отправка не создаст дубликат",
    )


class MessageResponse(BaseModel):
    id: int
    chat_id: int
    sender_id: int
    sender_name: str
    type: str
    content: str
    media_path: Optional[str]
    duration: Optional[int] = 0
    ttl_seconds: Optional[int]
    view_once: bool
    viewed: bool
    e2e: bool
    client_id: Optional[str] = None
    created_at: object


class MessagesListResponse(BaseModel):
    messages: List[MessageResponse]
    next_cursor: Optional[int] = None
    has_more: bool


def _serialize_msg(m: dict) -> MessageResponse:
    return MessageResponse(
        id=m["id"],
        chat_id=m["chat_id"],
        sender_id=m["sender_id"],
        sender_name=m.get("sender_name", ""),
        type=m["type"],
        content=m["content"],
        media_path=m["media_path"],
        duration=m.get("duration") or 0,
        ttl_seconds=m["ttl_seconds"],
        view_once=bool(m["view_once"]),
        viewed=bool(m["viewed"]),
        e2e=bool(m.get("e2e")),
        client_id=m.get("client_id"),
        created_at=m["created_at"],
    )


@router.get("/chats/{chat_id}/messages", response_model=MessagesListResponse)
async def list_messages(
    chat_id: int,
    limit: int = Query(default=50, ge=1, le=200),
    before_id: Optional[int] = None,
    user: dict = Depends(get_current_user),
):
    """История чата: курсорная пагинация «назад» (before_id = id самого старого
    сообщения предыдущей страницы)."""
    if not await is_chat_member(chat_id, user["id"]):
        raise HTTPException(403, "Вы не участник этого чата")
    async with database.get_db() as db:
        sql = (
            "SELECT m.*, u.display_name AS sender_name "
            "FROM messages m "
            "JOIN users u ON u.id = m.sender_id "
            "WHERE m.chat_id = :chat_id "
        )
        params = {"chat_id": chat_id, "limit": limit + 1}
        if before_id:
            sql += " AND m.id < :before_id"
            params["before_id"] = before_id
        sql += " ORDER BY m.id DESC LIMIT :limit"

        rows = await database.aq(db, sql, params)

    has_more = len(rows) > limit
    page = rows[:limit]
    if not page:
        return MessagesListResponse(messages=[], next_cursor=None, has_more=False)
    messages = [_serialize_msg(m) for m in reversed(page)]
    return MessagesListResponse(
        messages=messages,
        next_cursor=page[-1]["id"] if has_more else None,
        has_more=has_more,
    )


@router.get("/chats/{chat_id}/search", response_model=MessagesListResponse)
async def search_messages(
    chat_id: int,
    q: str = Query(..., min_length=2, max_length=100),
    limit: int = Query(default=50, ge=1, le=200),
    before_id: Optional[int] = None,
    user: dict = Depends(get_current_user),
):
    """Полнотекстовый поиск сообщений в чате.

    PostgreSQL: `to_tsvector('russian', ...)` — корректная работа с кириллицей
    (индекс из миграции 5c8d9e0f1a2b). SQLite (self-hosted без PG):
    регистронезависимый LIKE — тоже поддерживает кириллицу.
    """
    if not await is_chat_member(chat_id, user["id"]):
        raise HTTPException(403, "Вы не участник этого чата")

    q_clean = q.strip()
    if not q_clean:
        return MessagesListResponse(messages=[], next_cursor=None, has_more=False)

    async with database.get_db() as db:
        if config.IS_SQLITE:
            where = "LOWER(m.content) LIKE LOWER(:q)"
            params = {"chat_id": chat_id, "q": f"%{q_clean}%"}
        else:
            where = ("to_tsvector('russian', m.content) "
                     "@@ plainto_tsquery('russian', :q)")
            params = {"chat_id": chat_id, "q": q_clean}

        sql = (
            "SELECT m.*, u.display_name AS sender_name "
            "FROM messages m "
            "JOIN users u ON u.id = m.sender_id "
            f"WHERE m.chat_id = :chat_id AND {where} "
        )
        params["limit"] = limit + 1
        if before_id:
            sql += " AND m.id < :before_id"
            params["before_id"] = before_id
        sql += " ORDER BY m.id DESC LIMIT :limit"

        rows = await database.aq(db, sql, params)

    has_more = len(rows) > limit
    page = rows[:limit]
    if not page:
        return MessagesListResponse(messages=[], next_cursor=None, has_more=False)
    messages = [_serialize_msg(m) for m in reversed(page)]
    return MessagesListResponse(
        messages=messages,
        next_cursor=page[-1]["id"] if has_more else None,
        has_more=has_more,
    )


@router.post("/chats/{chat_id}/messages")
async def send_message(
    chat_id: int,
    body: SendMessageRequest,
    request: Request,
    user: dict = Depends(get_current_user),
):
    if not await is_chat_member(chat_id, user["id"]):
        raise HTTPException(403, "Вы не участник этого чата")

    # Антиспам: скользящее окно (Redis-лимитер cluster-safe + счётчик в БД)
    if not await limiter.allow_async(
        user_key("msg", request, user["id"]), config.SPAM_MSG_PER_MINUTE, 60
    ):
        raise HTTPException(429, "Слишком часто отправляете сообщения")

    if not body.content and not body.media_path:
        raise HTTPException(400, "Пустое сообщение")

    now = utc_now()
    async with database.get_db() as db:
        # Идемпотентность (Этап 4.5): если client_id уже есть в чате —
        # возвращаем существующее сообщение, дубликат не создаётся.
        if body.client_id:
            dup = await database.aq1(
                db,
                "SELECT m.*, u.display_name AS sender_name FROM messages m "
                "JOIN users u ON u.id=m.sender_id "
                "WHERE m.chat_id=:cid AND m.client_id=:clid",
                {"cid": chat_id, "clid": body.client_id},
            )
            if dup:
                return _serialize_msg(dup)

        try:
            await db.execute(
                sql_text(
                    "INSERT INTO messages (chat_id, sender_id, type, content, media_path, "
                    "duration, ttl_seconds, view_once, e2e, client_id, created_at) "
                    "VALUES (:chat_id, :sender_id, :type, :content, :media_path, "
                    ":duration, :ttl, :view_once, :e2e, :client_id, :created_at)"
                ),
                {
                    "chat_id": chat_id,
                    "sender_id": user["id"],
                    "type": body.type,
                    "content": body.content.strip(),
                    "media_path": body.media_path,
                    "duration": body.duration or 0,
                    "ttl": body.ttl_seconds,
                    "view_once": 1 if body.view_once else 0,
                    "e2e": 1 if body.e2e else 0,
                    "client_id": body.client_id,
                    "created_at": now,
                },
            )
        except IntegrityError:
            # Гонка двух параллельных отправок с одним client_id —
            # победитель уже записал; достаем его сообщение.
            if body.client_id:
                await db.rollback()
                dup = await database.aq1(
                    db,
                    "SELECT m.*, u.display_name AS sender_name FROM messages m "
                    "JOIN users u ON u.id=m.sender_id "
                    "WHERE m.chat_id=:cid AND m.client_id=:clid",
                    {"cid": chat_id, "clid": body.client_id},
                )
                if dup:
                    return _serialize_msg(dup)
            raise

        msg_id_row = await db.execute(
            sql_text("SELECT MAX(id) AS mid FROM messages WHERE chat_id=:cid"), {"cid": chat_id}
        )
        mid = msg_id_row.scalar()
        if mid is None:
            row = await database.aq1(
                db,
                "SELECT id FROM messages WHERE chat_id=:cid AND sender_id=:sid ORDER BY id DESC LIMIT 1",
                {"cid": chat_id, "sid": user["id"]},
            )
            mid = row["id"] if row else None
        msg = await database.aq1(
            db,
            "SELECT m.*, u.display_name AS sender_name FROM messages m "
            "JOIN users u ON u.id = m.sender_id WHERE m.id=:id",
            {"id": mid},
        )
        members = [r["user_id"] for r in await database.aq(
            db, "SELECT user_id FROM chat_members WHERE chat_id=:cid", {"cid": chat_id}
        )]
        sender_label = msg["sender_name"]

    payload = {"type": "new_message", "message": _serialize_msg(msg)}

    # Доставка ПОСЛЕ коммита транзакции (get_db делает commit на выходе):
    await manager.send_to_users(members, payload)

    # Фоновые push / outbox-fallback
    try:
        for uid in members:
            if uid == user["id"]:
                continue
            if not manager.is_online(uid):
                if body.e2e:
                    push_body = "🔒 Зашифрованное сообщение"
                elif body.type == "image":
                    push_body = "📷 Фотография"
                elif body.type == "file":
                    push_body = "📎 Файл"
                elif body.type == "voice":
                    push_body = "🎙️ Голосовое сообщение"
                else:
                    push_body = (body.content or "")[:120]
                await push_service.send_to_user(
                    uid, sender_label, push_body,
                    {"chat_id": str(chat_id), "message_id": str(msg["id"])},
                )
    except Exception as exc:  # noqa: BLE001 — push не должен ронять отправку
        from loguru import logger
        logger.warning("Push delivery failed: {}", exc.__class__.__name__)

    return payload["message"]


@router.get("/push/poll")
async def push_poll(user: dict = Depends(get_current_user)):
    """Long-polling fallback доставки уведомлений без облачных сервисов (Этап 3.3)."""
    items = await push_service.poll_outbox(user["id"])
    return {"items": items}


@router.post("/messages/{message_id}/view")
async def mark_viewed(message_id: int, user: dict = Depends(get_current_user)):
    async with database.get_db() as db:
        m = await database.aq1(db, "SELECT * FROM messages WHERE id=:id", {"id": message_id})
        if not m:
            raise HTTPException(404, "Сообщение не найдено")
        if not await is_chat_member(m["chat_id"], user["id"]):
            raise HTTPException(403, "Нет доступа")
        if m["view_once"] and not m["viewed"]:
            await db.execute(sql_text("UPDATE messages SET viewed=1 WHERE id=:id"), {"id": message_id})
            m = await database.aq1(db, "SELECT * FROM messages WHERE id=:id", {"id": message_id})

    payload = {"type": "message_viewed", "message_id": message_id, "chat_id": m["chat_id"]}
    await manager.send_to_user(m["sender_id"], payload)
    return {"ok": True}


@router.delete("/messages/{message_id}")
async def delete_message(message_id: int, user: dict = Depends(get_current_user)):
    async with database.get_db() as db:
        m = await database.aq1(db, "SELECT * FROM messages WHERE id=:id", {"id": message_id})
        if not m:
            raise HTTPException(404, "Сообщение не найдено")
        if m["sender_id"] != user["id"]:
            raise HTTPException(403, "Удалять можно только свои сообщения")
        await db.execute(sql_text("DELETE FROM messages WHERE id=:id"), {"id": message_id})
        members = [r["user_id"] for r in await database.aq(
            db, "SELECT user_id FROM chat_members WHERE chat_id=:cid", {"cid": m["chat_id"]}
        )]

    await manager.send_to_users(
        members, {"type": "message_deleted", "message_id": message_id, "chat_id": m["chat_id"]}
    )
    return {"ok": True}


class ReportRequest(BaseModel):
    message_id: int
    reason: str = Field(default="", max_length=500)


@router.post("/reports")
async def report_message(body: ReportRequest, user: dict = Depends(get_current_user)):
    async with database.get_db() as db:
        m = await database.aq1(db, "SELECT * FROM messages WHERE id=:id", {"id": body.message_id})
        if not m:
            raise HTTPException(404, "Сообщение не найдено")
        if not await is_chat_member(m["chat_id"], user["id"]):
            raise HTTPException(403, "Вы не участник этого чата")
        if m["sender_id"] == user["id"]:
            raise HTTPException(400, "Нельзя пожаловаться на своё сообщение")
        already = await database.aq1(
            db,
            "SELECT id FROM reports WHERE message_id=:mid AND reporter_id=:uid AND status='open'",
            {"mid": body.message_id, "uid": user["id"]},
        )
        if already:
            raise HTTPException(400, "Вы уже пожаловались на это сообщение")
        await db.execute(
            sql_text("INSERT INTO reports (chat_id, message_id, reporter_id, reason) "
                     "VALUES (:cid, :mid, :uid, :reason)"),
            {"cid": m["chat_id"], "mid": m["id"], "uid": user["id"], "reason": body.reason.strip()},
        )
    return {"ok": True, "message": "Жалоба отправлена модератору"}
