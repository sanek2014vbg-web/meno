"""MeNo — WebSocket-менеджер для реалтайм-доставки."""
from collections import defaultdict
from typing import Dict, Set

from fastapi import WebSocket


class WSManager:
    """Держит открытые WebSocket-соединения по пользователям."""

    def __init__(self) -> None:
        self._connections: Dict[int, Set[WebSocket]] = defaultdict(set)

    async def connect(self, user_id: int, ws: WebSocket) -> None:
        await ws.accept()
        self._connections[user_id].add(ws)

    def disconnect(self, user_id: int, ws: WebSocket) -> None:
        self._connections[user_id].discard(ws)
        if not self._connections[user_id]:
            self._connections.pop(user_id, None)

    async def send_to_user(self, user_id: int, payload: dict) -> None:
        for ws in list(self._connections.get(user_id, ())):
            try:
                await ws.send_json(payload)
            except Exception:
                self.disconnect(user_id, ws)

    async def send_to_users(self, user_ids, payload: dict) -> None:
        for uid in set(user_ids):
            await self.send_to_user(uid, payload)

    def is_online(self, user_id: int) -> bool:
        return user_id in self._connections

    @property
    def online_count(self) -> int:
        return len(self._connections)


manager = WSManager()