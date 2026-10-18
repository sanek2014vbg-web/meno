"""MeNo — слой кеширования на базе Redis (опциональный).

Используется для часто запрашиваемых, но редко меняющихся данных:
профили пользователей, состав чатов. Если MENO_REDIS_URL не задан или
Redis недоступен — все операции молча деградируют в no-op (cache miss),
сервер работает без кеша.

Метод connect() вызывается из lifespan приложения (см. main.py).
"""
import json
import logging
from typing import Any, Optional

import redis.asyncio as aioredis

from server.config import REDIS_URL

logger = logging.getLogger("meno.cache")


class Cache:
    def __init__(self):
        self._redis: Optional[aioredis.Redis] = None

    @property
    def enabled(self) -> bool:
        return self._redis is not None

    @property
    def client(self):
        """Нижний Redis-клиент (или None). Для низкоуровневых операций:
        SETEX/EXISTS/PUBLISH в сервисах typing/rate_limit. Не кэшируйте ссылку —
        клиент может быть пересоздан при reconnect."""
        return self._redis

    async def connect(self) -> None:
        """Инициализирует соединение с Redis (best-effort)."""
        if self._redis is not None or not REDIS_URL:
            if not REDIS_URL:
                logger.info("MENO_REDIS_URL not set — cache disabled (in-process mode).")
            return
        try:
            client = aioredis.from_url(REDIS_URL, decode_responses=True)
            await client.ping()
            self._redis = client
            logger.info("Connected to Redis cache successfully.")
        except Exception as e:
            logger.warning("Failed to connect to Redis (%s) — cache disabled.", e.__class__.__name__)
            self._redis = None

    async def get(self, key: str) -> Optional[Any]:
        if not self._redis:
            return None
        try:
            data = await self._redis.get(key)
            return json.loads(data) if data else None
        except Exception as e:
            logger.error("Cache get error for %s: %s", key, e)
            return None

    async def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        if not self._redis:
            return
        try:
            await self._redis.set(key, json.dumps(value, default=str), ex=ttl)
        except Exception as e:
            logger.error("Cache set error for %s: %s", key, e)

    async def delete(self, key: str) -> None:
        if not self._redis:
            return
        try:
            await self._redis.delete(key)
        except Exception as e:
            logger.error("Cache delete error for %s: %s", key, e)

    async def delete_by_prefix(self, prefix: str) -> None:
        if not self._redis:
            return
        try:
            async for key in self._redis.scan_iter(match=f"{prefix}*", count=200):
                await self._redis.delete(key)
        except Exception as e:
            logger.error("Cache delete_by_prefix error for %s: %s", prefix, e)

    # --- Pub/Sub (для WebSocket-шины между воркерами, Этап 5.1) ---

    async def publish(self, channel: str, payload) -> bool:
        if not self._redis:
            return False
        try:
            # Дефект-фикс (Этап 5.1, интеграционный тест pub/sub fan-out):
            # сериализация через default=str превращала Pydantic-модели внутри
            # payload (new_message.message) в repr-строку — получатель на другом
            # воркере падал с "string indices must be integers". model_dump()
            # приводит модели к dict ДО json.dumps; datetime остаётся на default=str.
            if isinstance(payload, dict):
                payload = {
                    k: (v.model_dump(mode="json") if hasattr(v, "model_dump") else v)
                    for k, v in payload.items()
                }
            await self._redis.publish(channel, json.dumps(payload, default=str))
            return True
        except Exception as e:
            logger.error("Cache publish error on %s: %s", channel, e)
            return False

    def pubsub(self):
        """Возвращает PubSub-объект Redis или None, если Redis недоступен."""
        if not self._redis:
            return None
        return self._redis.pubsub()

    async def ping(self) -> bool:
        """Проверка живости Redis (для /health)."""
        if not self._redis:
            return False
        try:
            return bool(await self._redis.ping())
        except Exception:
            return False

    async def close(self) -> None:
        if self._redis:
            await self._redis.aclose()
            self._redis = None


# Синглтон кеша для всего приложения
cache = Cache()
