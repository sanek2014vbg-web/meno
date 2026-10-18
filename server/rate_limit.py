"""MeNo — защита от брутфорса: rate limiting по связке IP + идентификатор.

Ключ лимита = "scope:IP:идентификатор" (username для авторизации,
user_id для авторизованных действий). Связка с IP нужна, чтобы ограничить
перебор именно этого аккаунта, но НЕ блокировать сотни мобильных устройств
за общим NAT оператора связи.

Два режима (Этап 2.6 ТЗ):
1. Redis (если MENO_REDIS_URL доступен) — атомарный счётчик через Lua-скрипт,
   корректно работает в кластере из нескольких воркеров uvicorn;
2. In-process скользящее окно в памяти — деградация для одиночного процесса.

Выбор режима происходит асинхронно (limiter.allow_async); синхронный allow()
оставлен для фолбэка и тестов.
"""

import threading
import time
from collections import defaultdict, deque
from typing import Deque, Optional

from fastapi import Request

from server import config

# Атомарное «скользящее» окно в Redis: sorted set с TTL.
# Возвращает 1 (разрешить) или 0 (отказать).
_LUA_ALLOW = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
if count >= limit then
  return 0
end
redis.call('ZADD', key, now, ARGV[4])
redis.call('PEXPIRE', key, window)
return 1
"""


class RateLimiter:
    """Rate limiter: Redis (cluster-safe) с in-process фолбэком."""

    def __init__(self) -> None:
        self._hits: dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._script_sha: Optional[str] = None

    # --- Асинхронный интерфейс (используется маршрутами) ---

    async def allow_async(self, key: str, limit: int, window: float) -> bool:
        from server.cache import cache

        if cache.enabled:
            try:
                redis = cache._redis
                if self._script_sha is None:
                    self._script_sha = await redis.script_load(_LUA_ALLOW)
                ok = await redis.evalsha(
                    self._script_sha,
                    1,
                    f"rl:{key}",
                    str(time.time()),
                    str(int(window * 1000)),
                    str(limit),
                    f"{time.monotonic_ns()}",
                )
                return bool(ok)
            except Exception as exc:  # noqa: BLE001 — деградация до локального окна
                from loguru import logger

                logger.warning(
                    "Redis rate limiter unavailable ({}), local fallback",
                    exc.__class__.__name__,
                )
                self._script_sha = None
        return self.allow(key, limit, window)

    async def reset_async(self, key: str) -> None:
        from server.cache import cache

        if cache.enabled:
            try:
                await cache._redis.delete(f"rl:{key}")
            except Exception:
                pass
        self.reset(key)

    # --- Синхронный in-process фолбек ---

    def allow(self, key: str, limit: int, window: float) -> bool:
        """Разрешает запрос, если за окно ещё не исчерпан лимит (память процесса)."""
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def reset(self, key: str) -> None:
        """Сбрасывает счётчик (например, после успешного входа)."""
        with self._lock:
            self._hits.pop(key, None)

    def cleanup(self, older_than: float = 3600.0) -> None:
        """Удаляет устаревшие ключи (фоновая задача)."""
        now = time.monotonic()
        with self._lock:
            for k in list(self._hits):
                q = self._hits[k]
                while q and q[0] <= now - older_than:
                    q.popleft()
                if not q:
                    del self._hits[k]

    def size(self) -> int:
        """Количество учитываемых на данный момент запросов."""
        with self._lock:
            return sum(len(q) for q in self._hits.values())


limiter = RateLimiter()


def client_ip(request: Request) -> str:
    """IP клиента с учётом заголовков обратного прокси (nginx).

    Берём ПЕРВЫЙ адрес из X-Forwarded-For — это реальный клиент,
    а не адрес прокси. Если прокси не настроен — берём socket peer.
    """
    if config.RL_TRUST_PROXY:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            first = xff.split(",")[0].strip()
            if first:
                return first
    host = request.client.host if request.client else "unknown"
    return host or "unknown"


def auth_key(scope: str, request: Request, identifier: str) -> str:
    """Ключ лимита для эндпоинтов аутентификации: IP + username."""
    return f"{scope}:{client_ip(request)}:{identifier.strip().lower()}"


def user_key(scope: str, request: Request, user_id: int) -> str:
    """Ключ лимита для авторизованных действий: IP + user_id."""
    return f"{scope}:{client_ip(request)}:{user_id}"
