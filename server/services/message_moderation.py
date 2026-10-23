"""MeNo — сервис удаления и жалоб на сообщения (Пункт 1 аудита).

DELETE /api/messages/{id} и POST /api/reports вынесены из god-route.

Гонки (Пункт 3 аудита):
- удаление чужого/уже удалённого: условный DELETE ... WHERE id = :id AND
  sender_id = :uid, rowcount == 0 -> 404/409 без отдельного SELECT-защитника;
- двойная жалоба: предпроверка открытой жалобы + UNIQUE-индекс не заведён
  (исторически), поэтому повторная проверка выполняется в той же транзакции;
  редкая гонка двух вкладок даст дубликат open-жалобы — админский UI их
  дедуплицирует по (message_id, reporter_id); сознательный trade-off,
  зафиксированный здесь, а не скрытый в коде.

Big O: PK-seek + индекс chat_members — O(log N) на операцию.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncSession

from server.db.session_manager import aq, aq1

log = logging.getLogger("meno.services.moderation")


async def load_message(session: AsyncSession, message_id: int) -> Optional[Dict[str, Any]]:
    return await aq1(
        session, "SELECT * FROM messages WHERE id = :id", {"id": message_id}
    )


async def delete_own_message_atomically(
    session: AsyncSession, message_id: int, user_id: int
) -> bool:
    """DELETE с предикатом владельца в WHERE: ровно один вызов гонки что-то сотрёт."""
    result = await session.execute(
        sql_text("DELETE FROM messages WHERE id = :id AND sender_id = :uid"),
        {"id": message_id, "uid": user_id},
    )
    return bool(result.rowcount)


async def chat_members(session: AsyncSession, chat_id: int) -> List[int]:
    rows = await aq(
        session,
        "SELECT user_id FROM chat_members WHERE chat_id = :cid",
        {"cid": chat_id},
    )
    return [r["user_id"] for r in rows]


async def publish_delete_event(message: Dict[str, Any], members: List[int]) -> None:
    from server.routes_admin import broadcast_tap
    from server.ws_manager import manager

    await broadcast_tap(
        {
            "scope": "messages",
            "kind": "message_deleted_by_owner",
            "chat_id": message["chat_id"],
            "message_id": message["id"],
            "actor_id": message.get("sender_id"),
        }
    )
    await manager.send_to_users(
        members,
        {
            "type": "message_deleted",
            "message_id": message["id"],
            "chat_id": message["chat_id"],
        },
    )


async def has_open_report(session: AsyncSession, message_id: int, reporter_id: int) -> bool:
    row = await aq1(
        session,
        "SELECT id FROM reports "
        "WHERE message_id = :mid AND reporter_id = :uid AND status = 'open'",
        {"mid": message_id, "uid": reporter_id},
    )
    return row is not None


async def insert_report(
    session: AsyncSession, *, chat_id: int, message_id: int, reporter_id: int, reason: str
) -> None:
    await session.execute(
        sql_text(
            "INSERT INTO reports (chat_id, message_id, reporter_id, reason) "
            "VALUES (:cid, :mid, :uid, :reason)"
        ),
        {"cid": chat_id, "mid": message_id, "uid": reporter_id, "reason": reason.strip()},
    )
