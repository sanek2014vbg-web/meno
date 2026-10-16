"""MeNo — защита от брутфорса: rate limiting по связке IP + идентификатор.

Ключ лимита = "scope:IP:идентификатор" (номер телефона для авторизации,
user_id для авторизованных действий). Связка с IP нужна, чтобы ограничить
перебор именно этого аккаунта, но НЕ блокировать сотни мобильных устройств
за общим NAT оператора связи (у каждого устройства свой телефон).

Реализация — скользящее окно в памяти (без внешних зависимостей),
потокобезопасно, пригодно для одного процесса uvicorn.
"""
import threading
import time
from collections import defaultdict, deque
from typing import Deque

import config
from fastapi import Request


class RateLimiter:
    """Скользящее окно запросов по ключу (в памяти)."""

    def __init__(self) -> None:
        self._hits: dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float) -> bool:
        """Разрешает запрос, если за окно ещё не исчерпан лимит."""
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


def auth_key(scope: str, request: Request, phone: str) -> str:
    """Ключ лимита для эндпоинтов аутентификации: IP + телефон."""
    return f"{scope}:{client_ip(request)}:{phone.strip()}"


def user_key(scope: str, request: Request, user_id: int) -> str:
    """Ключ лимита для авторизованных действий: IP + user_id."""
    return f"{scope}:{client_ip(request)}:{user_id}"