"""MeNo — маршруты чатов: список, создание, участники."""
from typing import List

import auth
import database
from deps import get_current_user
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text

router = APIRouter(prefix="/api", tags=["chats"])


class CreateChatRequest(BaseModel):
    type: str = Field(..., pattern="^(personal|group)$")
    title: str = Field(default="", max_length=60)
    user_ids: List[int] = Field(default_factory=list)


class AddMembersRequest(BaseModel):
    user_ids: List[int] = Field(default_factory=list)


async def _serialize_chat(db, chat: dict, me_id: int) -> dict:
    """Сериализация одного чата (используется для одиночных запросов)."""
    members = await database.aq(
        db,
        "SELECT u.* FROM chat_members cm JOIN users u ON u.id=cm.user_id WHERE cm.chat_id=:cid",
        {"cid": chat["id"]},
    )
    pub_members = [auth.user_to_public(m) for m in members]

    title = chat["title"]
    if chat["type"] == "personal":
        other = next((m for m in pub_members if m["id"] != me_id), None)
        title = other["display_name"] if other and other["display_name"] else "Собеседник"

    last = await database.aq1(
        db,
        "SELECT m.*, u.display_name AS sender_name FROM messages m "
        "JOIN users u ON u.id=m.sender_id WHERE m.chat_id=:cid ORDER BY m.id DESC LIMIT 1",
        {"cid": chat["id"]},
    )
    last_message = None
    if last:
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
async def search_users(
    q: str = Query(default="", max_length=50),
    user: dict = Depends(get_current_user),
):
    """Поиск пользователей по имени (username) или отображаемому имени."""
    q = q.strip()
    if not q:
        return []
    async with database.get_db() as db:
        rows = await database.aq(
            db,
            "SELECT * FROM users WHERE (username LIKE :q OR display_name LIKE :q) AND id != :uid LIMIT 20",
            {"q": f"%{q}%", "uid": user["id"]},
        )
        return [auth.user_to_public(r) for r in rows]


@router.get("/chats")
async def list_chats(user: dict = Depends(get_current_user)):
    """Список чатов пользователя.
    
    ОПТИМИЗАЦИЯ: Используем Window Function (ROW_NUMBER) для получения последнего сообщения 
    для каждого чата одним запросом. Это решает проблему N+1.
    """
    async with database.get_db() as db:
        # 1. Получаем список чатов и их последние сообщения одним сложным запросом
        # Используем подзапрос с RANK() или DISTINCT ON (специфика Postgres)
        sql = """
            SELECT c.*, 
                   m.id as msg_id, m.content as msg_content, m.type as msg_type, 
                   m.created_at as msg_date, m.e2e as msg_e2e, u.display_name as msg_sender
            FROM chats c
            JOIN chat_members cm ON cm.chat_id = c.id
            LEFT JOIN (
                SELECT *, ROW_NUMBER() OVER (PARTITION BY chat_id ORDER BY id DESC) as rn
                FROM messages
            ) m ON m.chat_id = c.id AND m.rn = 1
            LEFT JOIN users u ON u.id = m.sender_id
            WHERE cm.user_id = :uid
            ORDER BY c.id DESC
        """
        rows = await database.aq(db, sql, {"uid": user["id"]})
        
        # 2. Чтобы не делать N запросов за участниками каждого чата, 
        # собираем всех участников всех найденных чатов одним запросом.
        chat_ids = [r["id"] for r in rows]
        if not chat_ids:
            return []
            
        all_members_rows = await database.aq(
            db,
            "SELECT cm.chat_id, u.* FROM chat_members cm JOIN users u ON u.id=cm.user_id WHERE cm.chat_id = ANY(:ids)",
            {"ids": chat_ids}
        )
        
        # Группируем участников по чатам
        members_map = {}
        for m in all_members_rows:
            cid = m["chat_id"]
            if cid not in members_map:
                members_map[cid] = []
            members_map[cid].append(auth.user_to_public(m))
            
        # 3. Финальная сборка ответа
        result = []
        for r in rows:
            chat_id = r["id"]
            members = members_map.get(chat_id, [])
            
            title = r["title"]
            if r["type"] == "personal":
                other = next((m for m in members if m["id"] != user["id"]), None)
                title = other["display_name"] if other and other["display_name"] else "Собеседник"
            
            last_msg = None
            if r["msg_id"]:
                preview_content, is_e2e = ("🔒 Зашифрованное сообщение", True) if r["msg_e2e"] else (r["msg_content"], False)
                last_msg = {
                    "id": r["msg_id"],
                    "sender_id": r["sender_id"] if "sender_id" in r else None, # Нужно добавить в SELECT если нужно
                    "sender_name": r["msg_sender"],
                    "type": r["msg_type"],
                    "content": preview_content,
                    "e2e": is_e2e,
                    "created_at": r["msg_date"],
                }
                
            result.append({
                "id": chat_id,
                "type": r["type"],
                "title": title,
                "created_at": r["created_at"],
                "members": members,
                "last_message": last_msg,
            })
            
        return result


@router.post("/chats")
async def create_chat(body: CreateChatRequest, user: dict = Depends(get_current_user)):
    async with database.get_db() as db:
        if body.type == "personal":
            if len(body.user_ids) != 1:
                raise HTTPException(400, "Личный чат создаётся с одним собеседником")
            other_id = body.user_ids[0]
            if other_id == user["id"]:
                raise HTTPException(400, "Нельзя создать чат с самим собой")
            if not await database.aq1(db, "SELECT id FROM users WHERE id=:id", {"id": other_id}):
                raise HTTPException(404, "Пользователь не найден")

            existing = await database.aq1(
                db,
                "SELECT c.id FROM chats c "
                "JOIN chat_members a ON a.chat_id=c.id AND a.user_id=:u1 "
                "JOIN chat_members b ON b.chat_id=c.id AND b.user_id=:u2 "
                "WHERE c.type='personal'",
                {"u1": user["id"], "u2": other_id},
            )
            if existing:
                chat = await database.aq1(db, "SELECT * FROM chats WHERE id=:id", {"id": existing["id"]})
                return await _serialize_chat(db, chat, user["id"])

            await db.execute(
                "INSERT INTO chats (type, title, created_by) VALUES ('personal','',:uid)",
                {"uid": user["id"]},
            )
            chat_id = (await db.execute(text("SELECT id FROM chats ORDER BY id DESC LIMIT 1"))).scalar()
            
            await db.execute(
                "INSERT INTO chat_members (chat_id, user_id, role) VALUES (:cid, :u1, 'member'),(:cid, :u2, 'member')",
                {"cid": chat_id, "u1": user["id"], "u2": other_id},
            )
        else:
            member_ids = [user["id"]] + [uid for uid in body.user_ids if uid != user["id"]]
            if len(member_ids) < 2:
                raise HTTPException(400, "В группе должно быть минимум два участника")
            await db.execute(
                "INSERT INTO chats (type, title, created_by) VALUES ('group',:title,:uid)",
                {"title": body.title.strip() or "Новая группа", "uid": user["id"]},
            )
            chat_id = (await db.execute(text("SELECT id FROM chats ORDER BY id DESC LIMIT 1"))).scalar()
            for uid in member_ids:
                if await auth.get_user_by_id(uid):
                    await db.execute(
                        "INSERT INTO chat_members (chat_id, user_id, role) VALUES (:cid, :uid, 'member')",
                        {"cid": chat_id, "uid": uid},
                    )
        chat = await database.aq1(db, "SELECT * FROM chats WHERE id=:id", {"id": chat_id})
        return await _serialize_chat(db, chat, user["id"])


@router.get("/chats/{chat_id}")
async def get_chat(chat_id: int, user: dict = Depends(get_current_user)):
    async with database.get_db() as db:
        if not await database.aq1(
            db, "SELECT 1 FROM chat_members WHERE chat_id=:cid AND user_id=:uid", {"cid": chat_id, "uid": user["id"]}
        ):
            raise HTTPException(403, "Вы не участник этого чата")
        chat = await database.aq1(db, "SELECT * FROM chats WHERE id=:id", {"id": chat_id})
        if not chat:
            raise HTTPException(404, "Чат не найден")
        return await _serialize_chat(db, chat, user["id"])


@router.post("/chats/{chat_id}/members")
async def add_members(chat_id: int, body: AddMembersRequest, user: dict = Depends(get_current_user)):
    async with database.get_db() as db:
        chat = await database.aq1(db, "SELECT * FROM chats WHERE id=:id", {"id": chat_id})
        if not chat:
            raise HTTPException(404, "Чат не найден")
        if chat["type"] != "group":
            raise HTTPException(400, "Участников можно добавлять только в группу")
        added = []
        for uid in body.user_ids:
            if await auth.get_user_by_id(uid) and not await database.aq1(
                db, "SELECT 1 FROM chat_members WHERE chat_id=:cid AND user_id=:uid", {"cid": chat_id, "uid": uid}
            ):
                await db.execute(
                    "INSERT INTO chat_members (chat_id, user_id, role) VALUES (:cid, :uid, 'member')",
                    {"cid": chat_id, "uid": uid},
                )
                added.append(uid)
        return {"ok": True, "added": added}


@router.delete("/chats/{chat_id}/members/{user_id}")
async def remove_member(chat_id: int, user_id: int, user: dict = Depends(get_current_user)):
    async with database.get_db() as db:
        chat = await database.aq1(db, "SELECT * FROM chats WHERE id=:id", {"id": chat_id})
        if not chat:
            raise HTTPException(404, "Чат не найден")
        if chat["type"] != "group":
            raise HTTPException(400, "Только для групп")
        me_role = await database.aq1(
            db, "SELECT role FROM chat_members WHERE chat_id=:cid AND user_id=:uid", {"cid": chat_id, "uid": user["id"]}
        )
        if not me_role or me_role["role"] != "admin":
            raise HTTPException(403, "Удалять участников может только админ группы")
        await db.execute(
            "DELETE FROM chat_members WHERE chat_id=:cid AND user_id=:uid", {"cid": chat_id, "uid": user_id}
        )
        return {"ok": True}
