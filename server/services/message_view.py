"""MeNo — сервис «прочитано/самоудаление» view-once сообщений (Пункт 1 аудита).

Доменная логика POST /api/messages/{id}/view: проверка существования,
TTL-мертвость, доступность чата и атомарный переход unseen -> seen.

Ключевой fix гонки (Пункт 3 аудита): вместо read-modify-write
(`SELECT viewed` -> `UPDATE SET viewed=1`) используется условный UPDATE
``SET viewed = 1 WHERE id = :id AND viewed = 0`` — предикат состояния живёт в
WHERE, поэтому ровно ОДИН из параллельных запросов получает rowcount == 1 и
только он инициирует событие message_delete. На SQLite это безопасно без
SELECT FOR UPDATE: UPDATE блокирует строку внутри транзакции движка, а
проигравший видит уже изменённое состояние (rowcount 0) и не дублирует событие.

Big O: два PK-seek (загрузка строки + условный UPDATE) — O(log N), один
commit; WS-события вне транзакции (post-commit invariant проекта).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from server.db.concurrency import conditional_update
from server.db.session_manager import aq, aq1
from server.utils import as_utc, utc_now

log = logging.getLogger("meno.services.viewed")


@dataclass(frozen=True)
class ViewOutcome:
    """Результат отметки прочтения для слоя маршрута."""

    message: Dict[str, Any]
    first_view_of_view_once: bool


async def load_live_message(
    session: AsyncSession, message_id: int, *, has_expires_at: bool
) -> Optional[Dict[str, Any]]:
    """Строка сообщения или None; истёкшие по expires_at считаются несуществующими.

    Окно видимости мёртвого сообщения = 0: контент не отдаётся даже до того,
    как janitor физически сотрёт строку (v2.0 Пункт 2).
    """
    m = await aq1(
        session, "SELECT * FROM messages WHERE id = :id", {"id": message_id}
    )
    if m is None:
        return None
    if has_expires_at and m.get("expires_at") is not None:
        if as_utc(m["expires_at"]) <= utc_now():
            return None
    return m


async def mark_viewed_atomically(session: AsyncSession, message_id: int) -> bool:
    """CAS unseen->seen. True == именно этот вызов стал первым просмотром."""
    changed = await conditional_update(
        session,
        table="messages",
        set_assignments={"viewed": 1},
        where_assignments={"id": message_id, "viewed": 0},
    )
    return changed > 0


async def chat_members(session: AsyncSession, chat_id: int) -> List[int]:
    rows = await aq(
        session,
        "SELECT user_id FROM chat_members WHERE chat_id = :cid",
        {"cid": chat_id},
    )
    return [r["user_id"] for r in rows]


async def publish_view_events(message: Dict[str, Any], members: List[int]) -> None:
    """Post-commit WS-события: уведомление автора + самоудаление всем чату."""
    from server.routes_admin import broadcast_tap
    from server.ws_manager import manager

    await manager.send_to_user(
        message["sender_id"],
        {
            "type": "message_viewed",
            "message_id": message["id"],
            "chat_id": message["chat_id"],
        },
    )
    await broadcast_tap(
        {
            "scope": "messages",
            "kind": "message_viewed",
            "chat_id": message["chat_id"],
            "message_id": message["id"],
            "viewer_notified": message["sender_id"],
        }
    )
    if message["view_once"]:
        await broadcast_tap(
            {
                "scope": "messages",
                "kind": "self_destruct",
                "chat_id": message["chat_id"],
                "message_id": message["id"],
            }
        )
        await manager.send_to_users(
            members,
            {
                "type": "message_delete",
                "chat_id": message["chat_id"],
                "message_ids": [message["id"]],
            },
        )
