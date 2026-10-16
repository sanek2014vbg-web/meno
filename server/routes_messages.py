"""MeNo — маршруты сообщений: отправка, история, исчезающие сообщения."""
from datetime import datetime, timedelta
from typing import Optional

import database
from deps import get_current_user, is_chat_member
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import config
import push as push_service
from ws_manager import manager

router = APIRouter(prefix="/api", tags=["messages"])


class SendMessageRequest(BaseModel):
    type: str = Field(default="text", pattern="^(text|image|file|voice|emoji)$")
    content: str = Field(default="", max_length=4000)
    media_path: str = Field(default="")
    ttl_seconds: Optional[int] = Field(default=None, ge=5, le=86400 * 7)
    view_once: bool = False
    e2e: bool = False  # сообщение зашифровано клиентом (E2E для личных чатов)


class MarkViewedRequest(BaseModel):
    pass


class MessageResponse(BaseModel):
    id: int
    chat_id: int
    sender_id: int
    sender_name: str
    type: str
    content: str
    media_path: Optional[str]
    ttl_seconds: Optional[int]
    view_once: bool
    viewed: bool
    e2e: bool
    created_at: datetime

class MessagesListResponse(BaseModel):
    messages: List[MessageResponse]
    next_cursor: Optional[int] = None
    has_more: bool

def _serialize_msg(m: dict) -> MessageResponse:
    """Превращает строку из БД в Pydantic-модель сообщения."""
    return MessageResponse(
        id=m["id"],
        chat_id=m["chat_id"],
        sender_id=m["sender_id"],
        sender_name=m.get("sender_name", ""),
        type=m["type"],
        content=m["content"],
        media_path=m["media_path"],
        ttl_seconds=m["ttl_seconds"],
        view_once=bool(m["view_once"]),
        viewed=bool(m["viewed"]),
        e2e=bool(m.get("e2e")),
        created_at=m["created_at"],
    )


@router.get("/chats/{chat_id}/messages", response_model=MessagesListResponse)
async def list_messages(
    chat_id: int,
    limit: int = 50,
    before_id: Optional[int] = None,
    user: dict = Depends(get_current_user),
):
    if limit > 200:
        limit = 200
    async with database.get_db() as db:
        if not await is_chat_member(chat_id, user["id"]):
            raise HTTPException(403, "Вы не участник этого чата")

        sql = (
            "SELECT m.*, u.display_name AS sender_name "
            "FROM messages m "
            "JOIN users u ON u.id = m.sender_id "
            "WHERE m.chat_id = :chat_id "
        )
        params = {"chat_id": chat_id}

        if before_id:
            sql += " AND m.id < :before_id ORDER BY m.id DESC LIMIT :limit"
            params.update({"before_id": before_id, "limit": limit})
        else:
            sql += " ORDER BY m.id DESC LIMIT :limit"
            params.update({"limit": limit})

        rows = await database.aq(db, sql, params)
        
        if not rows:
            return MessagesListResponse(messages=[], next_cursor=None, has_more=False)

        # Сообщения в БД были отсортированы DESC (от новых к старым)
        # Для клиента возвращаем в порядке возрастания ID (от старых к новым)
        sorted_rows = list(reversed(rows))
        messages = [_serialize_msg(m) for m in sorted_rows]
        
        # Курсор для следующей страницы — это ID самого старого сообщения в текущем батче
        next_cursor = rows[0]["id"] 
        has_more = len(rows) == limit

        return MessagesListResponse(
            messages=messages,
            next_cursor=next_cursor,
            has_more=has_more
        )


@router.post("/chats/{chat_id}/messages")
async def send_message(
    chat_id: int, body: SendMessageRequest, user: dict = Depends(get_current_user)
):
    async with database.get_db() as db:
        if not await is_chat_member(chat_id, user["id"]):
            raise HTTPException(403, "Вы не участник этого чата")

        # Антиспам
        minute_ago = (datetime.utcnow() - timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S")
        res = await database.aq1(
            db,
            "SELECT COUNT(*) AS c FROM messages WHERE sender_id=:uid AND created_at > :time",
            {"uid": user["id"], "time": minute_ago},
        )
        if res and res["c"] >= config.SPAM_MSG_PER_MINUTE:
            raise HTTPException(429, "Слишком часто отправляете сообщения")

        if not body.content and not body.media_path:
            raise HTTPException(400, "Пустое сообщение")

        await db.execute(
            "INSERT INTO messages (chat_id, sender_id, type, content, media_path, ttl_seconds, view_once, e2e) "
            "VALUES (:chat_id, :sender_id, :type, :content, :media_path, :ttl, :view_once, :e2e)",
            {
                "chat_id": chat_id,
                "sender_id": user["id"],
                "type": body.type,
                "content": body.content.strip(),
                "media_path": body.media_path,
                "ttl": body.ttl_seconds,
                "view_once": 1 if body.view_once else 0,
                "e2e": 1 if body.e2e else 0,
            },
        )
        # Получаем сообщение вместе с именем отправителя для WebSocket-payload
        msg = await database.aq1(
            db, 
            "SELECT m.*, u.display_name AS sender_name FROM messages m "
            "JOIN users u ON u.id = m.sender_id "
            "WHERE m.id = (SELECT max(id) FROM messages WHERE chat_id=:cid AND sender_id=:sid)", 
            {"cid": chat_id, "sid": user["id"]}
        )
        payload = {"type": "new_message", "message": _serialize_msg(msg)}

    members = await _chat_member_ids(chat_id)
    await manager.send_to_users(members, payload)

    # Фоновые push
    try:
        async with database.get_db() as db_push:
            sender_row = await database.aq1(
                db_push, "SELECT display_name FROM users WHERE id=:id", {"id": user["id"]}
            )
            sender_label = (sender_row or {}).get("display_name") or "Собеседник"
        for uid in members:
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
    except Exception:
        pass

    return payload["message"]


@router.post("/messages/{message_id}/view")
async def mark_viewed(message_id: int, user: dict = Depends(get_current_user)):
    async with database.get_db() as db:
        m = await database.aq1(db, "SELECT * FROM messages WHERE id=:id", {"id": message_id})
        if not m:
            raise HTTPException(404, "Сообщение не найдено")
        if not await is_chat_member(m["chat_id"], user["id"]):
            raise HTTPException(403, "Нет доступа")
        if m["view_once"] and not m["viewed"]:
            await db.execute("UPDATE messages SET viewed=1 WHERE id=:id", {"id": message_id})
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
        await db.execute("DELETE FROM messages WHERE id=:id", {"id": message_id})

    members = await _chat_member_ids(m["chat_id"])
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
            "INSERT INTO reports (chat_id, message_id, reporter_id, reason) VALUES (:cid, :mid, :uid, :reason)",
            {"cid": m["chat_id"], "mid": m["id"], "uid": user["id"], "reason": body.reason.strip()},
        )
    return {"ok": True, "message": "Жалоба отправлена модератору"}


async def _chat_member_ids(chat_id: int) -> list:
    async with database.get_db() as db:
        rows = await database.aq(db, "SELECT user_id FROM chat_members WHERE chat_id=:cid", {"cid": chat_id})
    return [r["user_id"] for r in rows]
