"""MeNo — общие зависимости для маршрутов."""
from typing import Optional

from fastapi import Header, HTTPException

import auth
import database
from server.cache import cache

async def get_current_user(authorization: str = Header(default="")) -> dict:
    """Извлекает пользователя из Bearer-токена (асинхронно)."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    token = authorization[len("Bearer "):]
    user_id = auth.decode_token(token)
    user = await auth.get_user_by_id(user_id) if user_id is not None else None
    if user is None:
        raise HTTPException(status_code=401, detail="Токен недействителен")
    return user


def require_admin(user: dict = ...) -> dict:
    """Проверяет, что пользователь — владелец (DevMode)."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Доступ только для владельца")
    return user


async def chat_member_ids(chat_id: int) -> list:
    cache_key = f"chat:members:{chat_id}"
    cached = await cache.get(cache_key)
    if cached:
        return cached

    async with database.get_db() as db:
        rows = await database.aq(db, "SELECT user_id FROM chat_members WHERE chat_id=:cid", {"cid": chat_id})
        ids = [r["user_id"] for r in rows]
        await cache.set(cache_key, ids, ttl=60) # кешируем состав чата на 1 минуту
        return ids


async def is_chat_member(chat_id: int, user_id: int) -> bool:
    # Используем кешированный список участников для мгновенной проверки
    members = await chat_member_ids(chat_id)
    return user_id in members
