"""MeNo — доменные сервисы (v2.0).

typing: индикатор «Печатает...» с нулевой нагрузкой на PostgreSQL
(SETEX typing:{chat}:{user} 6 + fan-out через Redis Pub/Sub канал meno:ws).
"""
from server.services.typing import (
    STOP_SENTINELS,
    TYPING_CHANNEL,
    TYPING_RATE_LIMIT_SECONDS,
    TYPING_TTL_SECONDS,
    TypingService,
    typing_key,
    typing_service,
)

__all__ = [
    "TypingService",
    "typing_service",
    "typing_key",
    "TYPING_TTL_SECONDS",
    "TYPING_RATE_LIMIT_SECONDS",
    "TYPING_CHANNEL",
    "STOP_SENTINELS",
]
