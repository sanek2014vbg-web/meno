"""MeNo — DevMode: панель владельца (мониторинг, модерация, глобальные настройки).

Только async-доступ к БД (SQLAlchemy 2.0), tz-aware UTC, audit-лог действий.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text as sql_text

from server import auth, database
from server.deps import get_current_user
from server.ws_manager import manager

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _require_admin(user: dict) -> dict:
    if user["role"] != "admin":
        raise HTTPException(403, "Доступ только для владельца (DevMode)")
    return user


@router.get("/stats")
async def stats(user: dict = Depends(get_current_user)):
    _require_admin(user)
    async with database.get_db() as db:
        users_n = (await database.aq1(db, "SELECT COUNT(*) AS c FROM users"))["c"]
        chats_n = (await database.aq1(db, "SELECT COUNT(*) AS c FROM chats"))["c"]
        msgs_n = (await database.aq1(db, "SELECT COUNT(*) AS c FROM messages"))["c"]
        reports_n = (await database.aq1(
            db, "SELECT COUNT(*) AS c FROM reports WHERE status='open'"))["c"]
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
        report = await database.aq1(db, "SELECT * FROM reports WHERE id=:id", {"id": body.report_id})
        if not report:
            raise HTTPException(404, "Жалоба не найдена")
        if body.action == "resolve":
            await db.execute(sql_text("UPDATE reports SET status='resolved' WHERE id=:id"),
                             {"id": report["id"]})
            await auth.log_security_event("report_resolved", user_id=user["id"],
                                          detail=f"report={report['id']}")
            return {"ok": True, "message": "Жалоба закрыта"}
        if body.action == "delete_message":
            msg = await database.aq1(db, "SELECT * FROM messages WHERE id=:id",
                                     {"id": report["message_id"]})
            if not msg:
                raise HTTPException(404, "Сообщение не найдено")
            await db.execute(sql_text("DELETE FROM messages WHERE id=:id"), {"id": msg["id"]})
            await db.execute(sql_text("UPDATE reports SET status='resolved' WHERE id=:id"),
                             {"id": report["id"]})
            members = [r["user_id"] for r in await database.aq(
                db, "SELECT user_id FROM chat_members WHERE chat_id=:cid", {"cid": msg["chat_id"]}
            )]
        else:
            return {"ok": False}
    await manager.send_to_users(
        members,
        {"type": "message_deleted", "message_id": msg["id"], "chat_id": msg["chat_id"]},
    )
    await auth.log_security_event("message_deleted_by_admin", user_id=user["id"],
                                  detail=f"message={msg['id']}")
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
        existing = await database.aq1(db, "SELECT key FROM settings WHERE key=:k", {"k": key})
        if existing:
            await db.execute(sql_text("UPDATE settings SET value=:v WHERE key=:k"),
                             {"v": value, "k": key})
        else:
            await db.execute(sql_text("INSERT INTO settings (key, value) VALUES (:k, :v)"),
                             {"k": key, "v": value})
    await auth.log_security_event("setting_changed", user_id=user["id"], detail=f"{key}={value!r}")
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
