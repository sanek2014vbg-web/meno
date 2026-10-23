"""MeNo — доменные сервисы (v2.0 + архитектурный аудит Пункт 1/5).

Слой бизнес-логики между HTTP-маршрутами и адаптерами инфраструктуры
(server.db.*, ws_manager, cache, push). Маршруты содержат только
HTTP-зависимости; SQL и правила домена живут здесь.

- typing:           индикатор «Печатает...» с нулевой нагрузкой на PostgreSQL
                    (SETEX typing:{chat}:{user} 6 + fan-out через Redis
                    Pub/Sub канал meno:ws);
- janitor:          фоновый удалитель истёкших сообщений + registry-волны TTL;
- message_history:  курсорная история и диалект-адаптивный полнотекст;
- message_send:     идемпотентная отправка + post-commit WS/push доставка;
- message_view:     атомарный CAS «прочитано» для view-once;
- message_moderation: условное удаление по владельцу и жалобы;
- ttl_registry:     реестр janitor_jobs: регистрация, advisory-lock, телеметрия.
"""

from server.services import (
    janitor,
    message_history,
    message_moderation,
    message_send,
    message_view,
    ttl_registry,
)
from server.services.janitor import DELETE_EVENT_TYPE, JanitorService, janitor_service
from server.services.ttl_registry import (
    DEFAULT_JOBS,
    JOB_MESSAGES_TTL,
    JOB_REFRESH_TOKENS,
    TtlJob,
)
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
    "janitor",
    "message_history",
    "message_moderation",
    "message_send",
    "message_view",
    "ttl_registry",
    "JanitorService",
    "janitor_service",
    "DELETE_EVENT_TYPE",
    "TtlJob",
    "DEFAULT_JOBS",
    "JOB_MESSAGES_TTL",
    "JOB_REFRESH_TOKENS",
    "TypingService",
    "typing_service",
    "typing_key",
    "TYPING_TTL_SECONDS",
    "TYPING_RATE_LIMIT_SECONDS",
    "TYPING_CHANNEL",
    "STOP_SENTINELS",
]
