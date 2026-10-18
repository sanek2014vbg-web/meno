"""MeNo — маршруты чатов: список, создание, участники.

Все запросы диалект-безопасны (SQLite + PostgreSQL): никаких `= ANY(:ids)`
и window-функций, требующих PG; вместо них — два простых запроса с IN.
Списания используют курсорную пагинацию (Этап 4.4 ТЗ).
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text as sql_text

from server import auth, database
from server.db.models_base import Chat
from server.deps import get_current_user

router = APIRouter(prefix="/api", tags=["chats"])


class CreateChatRequest(BaseModel):
    type: str = Field(..., pattern="^(personal|group)$")
    title: str = Field(default="", max_length=60)
    user_ids: List[int] = Field(default_factory=list)


class AddMembersRequest(BaseModel):
    user_ids: List[int] = Field(default_factory=list)


async def _members_of(db, chat_id: int) -> list:
    rows = await database.aq(
        db,
        "SELECT u.* FROM chat_members cm JOIN users u ON u.id=cm.user_id WHERE cm.chat_id=:cid",
        {"cid": chat_id},
    )
    return [auth.user_to_public(m) for m in rows]


async def _serialize_chat(db, chat: dict, me_id: int) -> dict:
    """Сериализация одного чата (используется для одиночных запросов)."""
    pub_members = await _members_of(db, chat["id"])

    title = chat["title"]
    if chat["type"] == "personal":
        other = next((m for m in pub_members if m["id"] != me_id), None)
        title = (
            other["display_name"] if other and other["display_name"] else "Собеседник"
        )

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
    cursor: int = Query(
        default=0, ge=0, description="Курсор пагинации (id последнего результата)"
    ),
    limit: int = Query(default=20, ge=1, le=50),
    user: dict = Depends(get_current_user),
):
    """Поиск пользователей по username / display_name с курсорной пагинацией."""
    q = q.strip()
    if not q:
        return {"items": [], "next_cursor": None, "has_more": False}
    like = f"%{q}%"
    async with database.get_db() as db:
        rows = await database.aq(
            db,
            "SELECT * FROM users "
            "WHERE (username LIKE :q OR display_name LIKE :q) AND id != :uid AND id > :cursor "
            "ORDER BY id LIMIT :lim",
            {"q": like, "uid": user["id"], "cursor": cursor, "lim": limit + 1},
        )
    has_more = len(rows) > limit
    page = rows[:limit]
    items = [auth.user_to_public(r) for r in page]
    return {
        "items": items,
        "next_cursor": page[-1]["id"] if page and has_more else None,
        "has_more": has_more,
    }


@router.get("/chats")
async def list_chats(
    cursor: int = Query(
        default=0, ge=0, description="id самого старого чата из предыдущей страницы"
    ),
    limit: int = Query(default=30, ge=1, le=100),
    user: dict = Depends(get_current_user),
):
    """Список чатов пользователя (курсорная пагинация, N+1 устранён батч-запросами)."""
    async with database.get_db() as db:
        chats = await database.aq(
            db,
            "SELECT c.* FROM chats c JOIN chat_members cm ON cm.chat_id=c.id "
            "WHERE cm.user_id=:uid AND (:cursor = 0 OR c.id < :cursor) "
            "ORDER BY c.id DESC LIMIT :lim",
            {"uid": user["id"], "cursor": cursor, "lim": limit + 1},
        )
        has_more = len(chats) > limit
        chats = chats[:limit]
        if not chats:
            return {"items": [], "next_cursor": None, "has_more": False}

        chat_ids = [c["id"] for c in chats]
        placeholders = ", ".join(f":cid{i}" for i in range(len(chat_ids)))
        params = {f"cid{i}": cid for i, cid in enumerate(chat_ids)}

        # Участники всех чатов одним запросом
        member_rows = await database.aq(
            db,
            f"SELECT cm.chat_id, u.* FROM chat_members cm JOIN users u ON u.id=cm.user_id "
            f"WHERE cm.chat_id IN ({placeholders})",
            params,
        )
        members_map: dict[int, list] = {}
        for m in member_rows:
            members_map.setdefault(m["chat_id"], []).append(auth.user_to_public(m))

        # Последние сообщения всех чатов одним запросом (MAX(id) GROUP BY chat_id)
        last_rows = await database.aq(
            db,
            f"SELECT m.*, u.display_name AS sender_name FROM messages m "
            f"JOIN (SELECT chat_id, MAX(id) AS mid FROM messages GROUP BY chat_id) lm "
            f"  ON lm.chat_id = m.chat_id AND lm.mid = m.id "
            f"JOIN users u ON u.id = m.sender_id "
            f"WHERE m.chat_id IN ({placeholders})",
            params,
        )
        last_map = {r["chat_id"]: r for r in last_rows}

    result = []
    for c in chats:
        members = members_map.get(c["id"], [])
        title = c["title"]
        if c["type"] == "personal":
            other = next((m for m in members if m["id"] != user["id"]), None)
            title = (
                other["display_name"]
                if other and other["display_name"]
                else "Собеседник"
            )
        last = last_map.get(c["id"])
        last_msg = None
        if last:
            preview_content, is_e2e = (
                ("🔒 Зашифрованное сообщение", True)
                if last["e2e"]
                else (last["content"], False)
            )
            last_msg = {
                "id": last["id"],
                "sender_id": last["sender_id"],
                "sender_name": last["sender_name"],
                "type": last["type"],
                "content": preview_content,
                "e2e": is_e2e,
                "created_at": last["created_at"],
            }
        result.append(
            {
                "id": c["id"],
                "type": c["type"],
                "title": title,
                "created_at": c["created_at"],
                "members": members,
                "last_message": last_msg,
            }
        )

    return {
        "items": result,
        "next_cursor": result[-1]["id"] if result and has_more else None,
        "has_more": has_more,
    }


async def _insert_chat(db, chat_type: str, title: str, uid: int) -> int:
    """INSERT чата с атомарным возвратом id.

    Используется SQLAlchemy Core ``insert().returning(Chat.id)``:
      * PostgreSQL → ``INSERT ... RETURNING id`` (один round-trip);
      * SQLite (aiosqlite) → диалект не поддерживает RETURNING, SQLAlchemy сам
        подставляет ``cursor.lastrowid`` — контракт одинаковый для обоих
        движков, race-condition с ``MAX(id)`` исключена.
    """
    stmt = (
        Chat.__table__.insert()
        .values(type=chat_type, title=title, created_by=uid)
        .returning(Chat.id)
    )
    result = await db.execute(stmt)
    new_id = result.scalar()
    if new_id is None:  # страховка для нестандартных диалектов
        row = await database.aq1(db, "SELECT MAX(id) AS mid FROM chats")
        new_id = row["mid"]
    return int(new_id)


@router.post("/chats")
async def create_chat(body: CreateChatRequest, user: dict = Depends(get_current_user)):
    async with database.get_db() as db:
        if body.type == "personal":
            if len(body.user_ids) != 1:
                raise HTTPException(400, "Личный чат создаётся с одним собеседником")
            other_id = body.user_ids[0]
            if other_id == user["id"]:
                raise HTTPException(400, "Нельзя создать чат с самим собой")
            if not await database.aq1(
                db, "SELECT id FROM users WHERE id=:id", {"id": other_id}
            ):
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
                chat = await database.aq1(
                    db, "SELECT * FROM chats WHERE id=:id", {"id": existing["id"]}
                )
                return await _serialize_chat(db, chat, user["id"])

            chat_id = await _insert_chat(db, "personal", "", user["id"])
            for uid in (user["id"], other_id):
                await db.execute(
                    sql_text(
                        "INSERT INTO chat_members (chat_id, user_id, role) VALUES (:cid, :uid, 'member')"
                    ),
                    {"cid": chat_id, "uid": uid},
                )
        else:
            member_ids = [user["id"]] + [
                uid for uid in body.user_ids if uid != user["id"]
            ]
            if len(member_ids) < 2:
                raise HTTPException(400, "В группе должно быть минимум два участника")
            chat_id = await _insert_chat(
                db, "group", body.title.strip() or "Новая группа", user["id"]
            )
            for uid in member_ids:
                if await auth.get_user_by_id(uid):
                    await db.execute(
                        sql_text(
                            "INSERT INTO chat_members (chat_id, user_id, role) VALUES (:cid, :uid, 'member')"
                        ),
                        {"cid": chat_id, "uid": uid},
                    )
        chat = await database.aq1(
            db, "SELECT * FROM chats WHERE id=:id", {"id": chat_id}
        )
        return await _serialize_chat(db, chat, user["id"])


@router.get("/chats/{chat_id}")
async def get_chat(chat_id: int, user: dict = Depends(get_current_user)):
    async with database.get_db() as db:
        if not await database.aq1(
            db,
            "SELECT 1 FROM chat_members WHERE chat_id=:cid AND user_id=:uid",
            {"cid": chat_id, "uid": user["id"]},
        ):
            raise HTTPException(403, "Вы не участник этого чата")
        chat = await database.aq1(
            db, "SELECT * FROM chats WHERE id=:id", {"id": chat_id}
        )
        if not chat:
            raise HTTPException(404, "Чат не найден")
        return await _serialize_chat(db, chat, user["id"])


@router.post("/chats/{chat_id}/members")
async def add_members(
    chat_id: int, body: AddMembersRequest, user: dict = Depends(get_current_user)
):
    async with database.get_db() as db:
        chat = await database.aq1(
            db, "SELECT * FROM chats WHERE id=:id", {"id": chat_id}
        )
        if not chat:
            raise HTTPException(404, "Чат не найден")
        if chat["type"] != "group":
            raise HTTPException(400, "Участников можно добавлять только в группу")
        added = []
        for uid in body.user_ids:
            if await auth.get_user_by_id(uid) and not await database.aq1(
                db,
                "SELECT 1 FROM chat_members WHERE chat_id=:cid AND user_id=:uid",
                {"cid": chat_id, "uid": uid},
            ):
                await db.execute(
                    sql_text(
                        "INSERT INTO chat_members (chat_id, user_id, role) VALUES (:cid, :uid, 'member')"
                    ),
                    {"cid": chat_id, "uid": uid},
                )
                added.append(uid)
        from server.cache import cache

        await cache.delete(f"chat:members:{chat_id}")
    return {"ok": True, "added": added}


@router.delete("/chats/{chat_id}/members/{user_id}")
async def remove_member(
    chat_id: int, user_id: int, user: dict = Depends(get_current_user)
):
    async with database.get_db() as db:
        chat = await database.aq1(
            db, "SELECT * FROM chats WHERE id=:id", {"id": chat_id}
        )
        if not chat:
            raise HTTPException(404, "Чат не найден")
        if chat["type"] != "group":
            raise HTTPException(400, "Только для групп")
        me_role = await database.aq1(
            db,
            "SELECT role FROM chat_members WHERE chat_id=:cid AND user_id=:uid",
            {"cid": chat_id, "uid": user["id"]},
        )
        if not me_role or me_role["role"] != "admin":
            raise HTTPException(403, "Удалять участников может только админ группы")
        await db.execute(
            sql_text("DELETE FROM chat_members WHERE chat_id=:cid AND user_id=:uid"),
            {"cid": chat_id, "uid": user_id},
        )
        from server.cache import cache

        await cache.delete(f"chat:members:{chat_id}")
    return {"ok": True}
