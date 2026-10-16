"""MeNo — маршруты чатов: список, создание, участники."""
from typing import List

import auth
import database
from deps import get_current_user
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api", tags=["chats"])


class CreateChatRequest(BaseModel):
    type: str = Field(..., pattern="^(personal|group)$")
    title: str = Field(default="", max_length=60)
    user_ids: List[int] = Field(default_factory=list)


class AddMembersRequest(BaseModel):
    user_ids: List[int] = Field(default_factory=list)


def _serialize_chat(db, chat: dict, me_id: int) -> dict:
    members = database.q(
        db,
        "SELECT u.* FROM chat_members cm JOIN users u ON u.id=cm.user_id WHERE cm.chat_id=?",
        (chat["id"],),
    )
    pub_members = [auth.user_to_public(m) for m in members]

    title = chat["title"]
    if chat["type"] == "personal":
        other = next((m for m in pub_members if m["id"] != me_id), None)
        title = other["display_name"] if other and other["display_name"] else "Собеседник"

    last = database.q1(
        db,
        "SELECT m.*, u.display_name AS sender_name FROM messages m "
        "JOIN users u ON u.id=m.sender_id WHERE m.chat_id=? ORDER BY m.id DESC LIMIT 1",
        (chat["id"],),
    )
    last_message = None
    if last:
        # E2E-шифротекст не отдаём в превью списка чатов — только метку
        if last.get("e2e"):
            preview_content, is_e2e = "🔒 Зашифрованное сообщение", True
        else:
            preview_content, is_e2e = last["content"], False
        last_message = {
            "id": last["id"],
            "sender_id": last["sender_id"],
            "sender_name": last["sender_name"],
            "type": last["type"],
            "content": preview_content,
            "e2e": is_e2e,
            "created_at": last["created_at"],
        }
    return {
        "id": chat["id"],
        "type": chat["type"],
        "title": title,
        "created_at": chat["created_at"],
        "members": pub_members,
        "last_message": last_message,
    }


@router.get("/users/search")
def search_users(
    q: str = Query(default="", max_length=50),
    user: dict = Depends(get_current_user),
):
    """Поиск пользователей по номеру или имени (для создания чатов)."""
    q = q.strip()
    if not q:
        return []
    with database.get_db() as db:
        rows = database.q(
            db,
            "SELECT * FROM users WHERE (phone LIKE ? OR display_name LIKE ?) AND id != ? LIMIT 20",
            (f"%{q}%", f"%{q}%", user["id"]),
        )
        return [auth.user_to_public(r) for r in rows]


@router.get("/chats")
def list_chats(user: dict = Depends(get_current_user)):
    with database.get_db() as db:
        rows = database.q(
            db,
            "SELECT c.* FROM chats c JOIN chat_members cm ON cm.chat_id=c.id "
            "WHERE cm.user_id=? ORDER BY c.id DESC",
            (user["id"],),
        )
        return [_serialize_chat(db, r, user["id"]) for r in rows]


@router.post("/chats")
def create_chat(body: CreateChatRequest, user: dict = Depends(get_current_user)):
    with database.get_db() as db:
        if body.type == "personal":
            if len(body.user_ids) != 1:
                raise HTTPException(400, "Личный чат создаётся с одним собеседником")
            other_id = body.user_ids[0]
            if other_id == user["id"]:
                raise HTTPException(400, "Нельзя создать чат с самим собой")
            if not database.q1(db, "SELECT id FROM users WHERE id=?", (other_id,)):
                raise HTTPException(404, "Пользователь не найден")

            # Если личный чат уже существует — возвращаем его
            existing = database.q1(
                db,
                "SELECT c.id FROM chats c "
                "JOIN chat_members a ON a.chat_id=c.id AND a.user_id=? "
                "JOIN chat_members b ON b.chat_id=c.id AND b.user_id=? "
                "WHERE c.type='personal'",
                (user["id"], other_id),
            )
            if existing:
                chat = database.q1(db, "SELECT * FROM chats WHERE id=?", (existing["id"],))
                return _serialize_chat(db, chat, user["id"])

            cur = db.execute(
                "INSERT INTO chats (type, title, created_by) VALUES ('personal','',?)",
                (user["id"],),
            )
            chat_id = cur.lastrowid
            db.execute(
                "INSERT INTO chat_members (chat_id, user_id, role) VALUES (?,?,'member'),(?,?,'member')",
                (chat_id, user["id"], chat_id, other_id),
            )
        else:
            # Группа: создатель + участники
            member_ids = [user["id"]] + [uid for uid in body.user_ids if uid != user["id"]]
            if len(member_ids) < 2:
                raise HTTPException(400, "В группе должно быть минимум два участника")
            cur = db.execute(
                "INSERT INTO chats (type, title, created_by) VALUES ('group',?,?)",
                (body.title.strip() or "Новая группа", user["id"]),
            )
            chat_id = cur.lastrowid
            for uid in member_ids:
                if auth.get_user_by_id(uid):
                    db.execute(
                        "INSERT INTO chat_members (chat_id, user_id, role) VALUES (?,?,'member')",
                        (chat_id, uid),
                    )
        chat = database.q1(db, "SELECT * FROM chats WHERE id=?", (chat_id,))
        return _serialize_chat(db, chat, user["id"])


@router.get("/chats/{chat_id}")
def get_chat(chat_id: int, user: dict = Depends(get_current_user)):
    with database.get_db() as db:
        if not database.q1(
            db, "SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?", (chat_id, user["id"])
        ):
            raise HTTPException(403, "Вы не участник этого чата")
        chat = database.q1(db, "SELECT * FROM chats WHERE id=?", (chat_id,))
        if not chat:
            raise HTTPException(404, "Чат не найден")
        return _serialize_chat(db, chat, user["id"])


@router.post("/chats/{chat_id}/members")
def add_members(chat_id: int, body: AddMembersRequest, user: dict = Depends(get_current_user)):
    with database.get_db() as db:
        chat = database.q1(db, "SELECT * FROM chats WHERE id=?", (chat_id,))
        if not chat:
            raise HTTPException(404, "Чат не найден")
        if chat["type"] != "group":
            raise HTTPException(400, "Участников можно добавлять только в группу")
        added = []
        for uid in body.user_ids:
            if auth.get_user_by_id(uid) and not database.q1(
                db, "SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?", (chat_id, uid)
            ):
                db.execute(
                    "INSERT INTO chat_members (chat_id, user_id, role) VALUES (?,?,'member')",
                    (chat_id, uid),
                )
                added.append(uid)
        return {"ok": True, "added": added}


@router.delete("/chats/{chat_id}/members/{user_id}")
def remove_member(chat_id: int, user_id: int, user: dict = Depends(get_current_user)):
    with database.get_db() as db:
        chat = database.q1(db, "SELECT * FROM chats WHERE id=?", (chat_id,))
        if not chat:
            raise HTTPException(404, "Чат не найден")
        if chat["type"] != "group":
            raise HTTPException(400, "Только для групп")
        me_role = database.q1(
            db, "SELECT role FROM chat_members WHERE chat_id=? AND user_id=?", (chat_id, user["id"])
        )
        if not me_role or me_role["role"] != "admin":
            raise HTTPException(403, "Удалять участников может только админ группы")
        db.execute(
            "DELETE FROM chat_members WHERE chat_id=? AND user_id=?", (chat_id, user_id)
        )
        return {"ok": True}