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


def _serialize(db, m: dict) -> dict:
    sender = database.q1(db, "SELECT display_name FROM users WHERE id=?", (m["sender_id"],))
    return {
        "id": m["id"],
        "chat_id": m["chat_id"],
        "sender_id": m["sender_id"],
        "sender_name": sender["display_name"] if sender else "",
        "type": m["type"],
        "content": m["content"],
        "media_path": m["media_path"],
        "ttl_seconds": m["ttl_seconds"],
        "view_once": m["view_once"],
        "viewed": m["viewed"],
        "e2e": bool(m.get("e2e")),
        "created_at": m["created_at"],
    }


@router.get("/chats/{chat_id}/messages")
def list_messages(
    chat_id: int,
    limit: int = 50,
    before_id: Optional[int] = None,
    user: dict = Depends(get_current_user),
):
    if limit > 200:
        limit = 200
    with database.get_db() as db:
        if not is_chat_member(chat_id, user["id"]):
            raise HTTPException(403, "Вы не участник этого чата")
        if before_id:
            rows = database.q(
                db,
                "SELECT * FROM messages WHERE chat_id=? AND id<? "
                "ORDER BY id DESC LIMIT ?",
                (chat_id, before_id, limit),
            )
        else:
            rows = database.q(
                db,
                "SELECT * FROM messages WHERE chat_id=? ORDER BY id DESC LIMIT ?",
                (chat_id, limit),
            )
        # Возвращаем в хронологическом порядке
        return [_serialize(db, m) for m in reversed(rows)]


@router.post("/chats/{chat_id}/messages")
async def send_message(
    chat_id: int, body: SendMessageRequest, user: dict = Depends(get_current_user)
):
    with database.get_db() as db:
        if not is_chat_member(chat_id, user["id"]):
            raise HTTPException(403, "Вы не участник этого чата")

        # Антиспам: не более N сообщений в минуту
        minute_ago = (datetime.utcnow() - timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S")
        cnt = database.q1(
            db,
            "SELECT COUNT(*) AS c FROM messages WHERE sender_id=? AND created_at > ?",
            (user["id"], minute_ago),
        )["c"]
        if cnt >= config.SPAM_MSG_PER_MINUTE:
            raise HTTPException(429, "Слишком часто отправляете сообщения")

        if not body.content and not body.media_path:
            raise HTTPException(400, "Пустое сообщение")

        cur = db.execute(
            "INSERT INTO messages (chat_id, sender_id, type, content, media_path, ttl_seconds, view_once, e2e) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (
                chat_id,
                user["id"],
                body.type,
                body.content.strip(),
                body.media_path,
                body.ttl_seconds,
                1 if body.view_once else 0,
                1 if body.e2e else 0,
            ),
        )
        msg = database.q1(db, "SELECT * FROM messages WHERE id=?", (cur.lastrowid,))
        payload = {"type": "new_message", "message": _serialize(db, msg)}

    members = _chat_member_ids(chat_id)
    await manager.send_to_users(members, payload)

    # Фоновые push для участников, которые сейчас НЕ в сети (WebSocket закрыт).
    # Для E2E-сообщений текст не раскрывается — только метка.
    try:
        with database.get_db() as db_push:
            sender_row = database.q1(
                db_push, "SELECT display_name FROM users WHERE id=?", (user["id"],)
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
        pass  # push не критичен для доставки сообщения

    return payload["message"]


@router.post("/messages/{message_id}/view")
async def mark_viewed(message_id: int, user: dict = Depends(get_current_user)):
    """Отметить сообщение просмотренным (для view_once)."""
    with database.get_db() as db:
        m = database.q1(db, "SELECT * FROM messages WHERE id=?", (message_id,))
        if not m:
            raise HTTPException(404, "Сообщение не найдено")
        if not is_chat_member(m["chat_id"], user["id"]):
            raise HTTPException(403, "Нет доступа")
        if m["view_once"] and not m["viewed"]:
            db.execute("UPDATE messages SET viewed=1 WHERE id=?", (message_id,))
            m = database.q1(db, "SELECT * FROM messages WHERE id=?", (message_id,))

    # Уведомляем отправителя, что сообщение просмотрено
    payload = {"type": "message_viewed", "message_id": message_id, "chat_id": m["chat_id"]}
    await manager.send_to_user(m["sender_id"], payload)
    return {"ok": True}


@router.delete("/messages/{message_id}")
async def delete_message(message_id: int, user: dict = Depends(get_current_user)):
    with database.get_db() as db:
        m = database.q1(db, "SELECT * FROM messages WHERE id=?", (message_id,))
        if not m:
            raise HTTPException(404, "Сообщение не найдено")
        if m["sender_id"] != user["id"]:
            raise HTTPException(403, "Удалять можно только свои сообщения")
        db.execute("DELETE FROM messages WHERE id=?", (message_id,))

    members = _chat_member_ids(m["chat_id"])
    await manager.send_to_users(
        members, {"type": "message_deleted", "message_id": message_id, "chat_id": m["chat_id"]}
    )
    return {"ok": True}


class ReportRequest(BaseModel):
    message_id: int
    reason: str = Field(default="", max_length=500)


@router.post("/reports")
def report_message(body: ReportRequest, user: dict = Depends(get_current_user)):
    """Жалоба на сообщение (идёт в очередь модерации DevMode)."""
    with database.get_db() as db:
        m = database.q1(db, "SELECT * FROM messages WHERE id=?", (body.message_id,))
        if not m:
            raise HTTPException(404, "Сообщение не найдено")
        if not is_chat_member(m["chat_id"], user["id"]):
            raise HTTPException(403, "Вы не участник этого чата")
        if m["sender_id"] == user["id"]:
            raise HTTPException(400, "Нельзя пожаловаться на своё сообщение")
        already = database.q1(
            db,
            "SELECT id FROM reports WHERE message_id=? AND reporter_id=? AND status='open'",
            (body.message_id, user["id"]),
        )
        if already:
            raise HTTPException(400, "Вы уже пожаловались на это сообщение")
        db.execute(
            "INSERT INTO reports (chat_id, message_id, reporter_id, reason) VALUES (?,?,?,?)",
            (m["chat_id"], m["id"], user["id"], body.reason.strip()),
        )
    return {"ok": True, "message": "Жалоба отправлена модератору"}


def _chat_member_ids(chat_id: int) -> list:
    with database.get_db() as db:
        rows = database.q(db, "SELECT user_id FROM chat_members WHERE chat_id=?", (chat_id,))
    return [r["user_id"] for r in rows]