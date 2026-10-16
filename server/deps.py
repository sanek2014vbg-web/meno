"""MeNo — общие зависимости для маршрутов."""
from typing import Optional

from fastapi import Header, HTTPException

import auth


def get_current_user(authorization: str = Header(default="")) -> dict:
    """Извлекает пользователя из Bearer-токена."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    token = authorization[len("Bearer "):]
    user_id = auth.decode_token(token)
    user = auth.get_user_by_id(user_id) if user_id is not None else None
    if user is None:
        raise HTTPException(status_code=401, detail="Токен недействителен")
    return user


def require_admin(user: dict = ...) -> dict:
    """Проверяет, что пользователь — владелец (DevMode)."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Доступ только для владельца")
    return user


def chat_member_ids(chat_id: int) -> list:
    import database
    with database.get_db() as db:
        rows = database.q(db, "SELECT user_id FROM chat_members WHERE chat_id=?", (chat_id,))
    return [r["user_id"] for r in rows]


def is_chat_member(chat_id: int, user_id: int) -> bool:
    return user_id in chat_member_ids(chat_id)