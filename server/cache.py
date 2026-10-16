"""MeNo — слой кеширования на базе Redis.

Используется для хранения часто запрашиваемых, но редко меняющихся данных:
- Профили пользователей (public_user)
- Статусы членства в чатах
- Глобальные настройки сервера

Кеширование позволяет сократить количество запросов к PostgreSQL и снизить задержки (latency).
"""
import logging
import json
import redis.asyncio as redis
from typing import Any, Optional
from server.config import REDIS_URL

logger = logging.getLogger("meno.cache")

class Cache:
    def __init__(self):
        self._redis: Optional[redis.Redis] = None

    async def connect(self):
        """Инициализирует соединение с Redis."""
        if self._redis is None:
            try:
                self._redis = redis.from_url(
                    REDIS_URL, 
                    decode_responses=True
                )
                # Проверка соединения
                await self._redis.ping()
                logger.info("Connected to Redis cache successfully.")
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}")
                self._redis = None

    async def get(self, key: str) -> Optional[Any]:
        """Получает значение из кеша."""
        if not self._redis:
            return None
        try:
            data = await self._redis.get(key)
            return json.loads(data) if data else None
        except Exception as e:
            logger.error(f"Cache get error for {key}: {e}")
            return None

    async def set(self, key: str, value: Any, ttl: int = 3600):
        """Сохраняет значение в кеше с указанным TTL (в секундах)."""
        if not self._redis:
            return
        try:
            await self._redis.set(key, json.dumps(value), ex=ttl)
        except Exception as e:
            logger.error(f"Cache set error for {key}: {e}")

    async def delete(self, key: str):
        """Удаляет запись из кеша."""
        if not self._redis:
            return
        try:
            await self._redis.delete(key)
        except Exception as e:
            logger.error(f"Cache delete error for {key}: {e}")

    async def close(self):
        """Закрывает соединение."""
        if self._redis:
            await self._redis.close()

# Синглтон кеша для всего приложения
cache = Cache()
