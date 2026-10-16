"""MeNo — DevMode: панель владельца (мониторинг, модерация, глобальные настройки)."""
import database
import auth
from deps import get_current_user
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ws_manager import manager

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _require_admin(user: dict) -> dict:
    if user["role"] != "admin":
        raise HTTPException(403, "Доступ только для владельца (DevMode)")
    return user


@router.get("/stats")
def stats(user: dict = Depends(get_current_user)):
    _require_admin(user)
    with database.get_db() as db:
        return {
            "users": database.q1(db, "SELECT COUNT(*) AS c FROM users")["c"],
            "chats": database.q1(db, "SELECT COUNT(*) AS c FROM chats")["c"],
            "messages": database.q1(db, "SELECT COUNT(*) AS c FROM messages")["c"],
            "open_reports": database.q1(db, "SELECT COUNT(*) AS c FROM reports WHERE status='open'")["c"],
            "online_now": manager.online_count,
        }


@router.get("/reports")
def reports(user: dict = Depends(get_current_user)):
    _require_admin(user)
    with database.get_db() as db:
        rows = database.q(
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
    with database.get_db() as db:
        report = database.q1(db, "SELECT * FROM reports WHERE id=?", (body.report_id,))
        if not report:
            raise HTTPException(404, "Жалоба не найдена")
        if body.action == "resolve":
            db.execute("UPDATE reports SET status='resolved' WHERE id=?", (report["id"],))
            return {"ok": True, "message": "Жалоба закрыта"}
        if body.action == "delete_message":
            msg = database.q1(db, "SELECT * FROM messages WHERE id=?", (report["message_id"],))
            if not msg:
                raise HTTPException(404, "Сообщение не найдено")
            db.execute("DELETE FROM messages WHERE id=?", (msg["id"],))
            db.execute("UPDATE reports SET status='resolved' WHERE id=?", (report["id"],))
            members = [
                r["user_id"]
                for r in database.q(db, "SELECT user_id FROM chat_members WHERE chat_id=?", (msg["chat_id"],))
            ]
            await manager.send_to_users(
                members,
                {"type": "message_deleted", "message_id": msg["id"], "chat_id": msg["chat_id"]},
            )
            return {"ok": True, "message": "Сообщение удалено, жалоба закрыта"}
    return {"ok": False}


@router.get("/settings")
def get_settings(user: dict = Depends(get_current_user)):
    _require_admin(user)
    with database.get_db() as db:
        rows = database.q(db, "SELECT key, value FROM settings")
    return {r["key"]: r["value"] for r in rows}


class SettingUpdate(BaseModel):
    key: str = Field(..., min_length=1, max_length=60)
    value: str = Field(default="")


@router.put("/settings")
def set_setting(body: SettingUpdate, user: dict = Depends(get_current_user)):
    _require_admin(user)
    with database.get_db() as db:
        db.execute(
            "INSERT INTO settings (key, value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (body.key.strip(), body.value),
        )
    return {"ok": True, "key": body.key, "value": body.value}