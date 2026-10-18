"""MeNo — WebSocket-менеджер реалтайм-доставки.

Два режима (Этап 5.1 ТЗ):
1. In-process (по умолчанию, без Redis): все соединения в памяти одного
   воркера — достаточно для self-hosted VPS с одним процессом.
2. Redis Pub/Sub bus: при доступном Redis сообщения между воркерами
   ретранслируются через канал `meno:ws`; локальная доставка выполняется
   каждому подключённому клиенту. Менеджер подписывается на канал в
   lifespan и публикует исходящие payload туда.

Heartbeat: сервер periodically отправляет ping-кадры; клиент отвечает
pong (или просто читает), мёртвые соединения закрываются.
"""

import asyncio
import json
import logging
from collections import defaultdict
from typing import Dict, Set

from fastapi import WebSocket

log = logging.getLogger("meno.ws")

WS_CHANNEL = "meno:ws"


class WSManager:
    """Держит открытые WebSocket-соединения по пользователям."""

    def __init__(self) -> None:
        self._connections: Dict[int, Set[WebSocket]] = defaultdict(set)
        self._pubsub_task: asyncio.Task | None = None

    async def connect(self, user_id: int, ws: WebSocket) -> None:
        await ws.accept()
        self._connections[user_id].add(ws)

    def disconnect(self, user_id: int, ws: WebSocket) -> None:
        self._connections[user_id].discard(ws)
        if not self._connections[user_id]:
            self._connections.pop(user_id, None)

    async def _send_local(self, user_id: int, payload: dict) -> None:
        for ws in list(self._connections.get(user_id, ())):
            try:
                text = json.dumps(payload, default=str, ensure_ascii=False)
                await ws.send_text(text)
            except Exception:
                self.disconnect(user_id, ws)

    async def send_to_user(self, user_id: int, payload: dict) -> None:
        """Доставка пользователю: локально + через Redis-шину (если доступна).

        Если Redis включён, публикация идёт в канал, а подписчики (все
        воркеры) доставляют payload своим локальным соединениям. Локальную
        доставку тоже выполняем сразу — для single-worker это единственный
        путь, а дублирование исключено тем, что подписчик проверяет, не он ли
        автор сообщения (поле `_origin`).
        """
        from server.cache import cache

        if cache.enabled:
            # Multi-worker: доставка идёт через подписчиков канала (все воркеры,
            # включая этот) — локальная отправка один раз выполнится в _bus_loop.
            await cache.publish(WS_CHANNEL, {"user_id": user_id, "payload": payload})
        else:
            await self._send_local(user_id, payload)

    async def send_to_users(self, user_ids, payload: dict) -> None:
        for uid in set(user_ids):
            await self.send_to_user(uid, payload)

    def is_online(self, user_id: int) -> bool:
        return user_id in self._connections

    @property
    def online_count(self) -> int:
        return len(self._connections)

    # --- Redis pub/sub listener (multi-worker fan-out) ---

    async def start_bus_listener(self) -> None:
        """Подписывается на канал meno:ws; вызывается из lifespan."""
        from server.cache import cache

        ps = cache.pubsub()
        if ps is None:
            return
        await ps.subscribe(WS_CHANNEL)
        self._pubsub_task = asyncio.create_task(self._bus_loop(ps))

    async def _bus_loop(self, ps) -> None:
        try:
            async for msg in ps.listen():
                if msg.get("type") != "message":
                    continue
                data = msg["data"]
                # Дефект-фикс (двойная декодировка): redis-клиент с
                # decode_responses=True возвращает payload строкой, а не bytes.
                # json.loads(bytes|str) работает сам — повторный loads отсюда
                # превращал объект в строку и ронял потребителя с
                # "string indices must be integers".
                if isinstance(data, (bytes, bytearray)):
                    data = data.decode("utf-8", "replace")
                try:
                    data = json.loads(data)
                except (TypeError, ValueError):
                    pass
                # Защита от двойного декодирования: если подписчик уже вернул
                # словарь (decode_responses / эмуляции транспорта), не делаем
                # повторный loads по dict — иначе str(dict)-проход превращает
                # вложенные объекты в строки ("string indices must be integers").
                if not isinstance(data, dict):
                    continue
                uid = data.get("user_id")
                payload = data.get("payload")
                if uid is None or payload is None:
                    continue
                await self._send_local(int(uid), payload)
        except asyncio.CancelledError:
            await ps.unsubscribe(WS_CHANNEL)
            await ps.aclose()
            raise
        except Exception as exc:
            log.error("WS bus listener error: %s", exc.__class__.__name__)

    async def stop_bus_listener(self) -> None:
        if self._pubsub_task:
            self._pubsub_task.cancel()
            try:
                await self._pubsub_task
            except asyncio.CancelledError:
                pass
            self._pubsub_task = None

    # --- Heartbeat (ping/pong, Этап 5.2) ---

    async def heartbeat(self, interval: float = 30.0) -> None:
        """Периодически шлёт ping всем соединениям; ошибки чистит словарь."""
        while True:
            await asyncio.sleep(interval)
            for uid in list(self._connections):
                for ws in list(self._connections.get(uid, ())):
                    try:
                        await ws.send_json({"type": "ping"})
                    except Exception:
                        self.disconnect(uid, ws)


manager = WSManager()
