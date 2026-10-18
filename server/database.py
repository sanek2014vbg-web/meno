"""MeNo — модуль базы данных (фасад совместимости).

Исторический god-module разбит на атомарные пакеты `server.db.*`:

    server/db/models_base.py     — Declarative Base + ORM-модели;
    server/db/connection.py      — движок, пул, фабрика сессий, PRAGMA/SET hooks;
    server/db/session_manager.py — get_db(), init_db(), aq/aq1, TTL-cleanup.

Этот файл сохранён как тонкий реэкспорт, чтобы весь существующий код
(`from server import database`, `from server.database import Base`, миграции
Alembic в migrations/env.py, тесты) работал без единой правки импортов.

Новый код обязан импортировать конкретные модули пакета `server.db`, а не фасад.
"""
from sqlalchemy import text  # noqa: F401 (реэкспорт для совместимости auth/routes)

from server.config import DATABASE_URL, IS_SQLITE  # noqa: F401 (совместимость фасада)
from server.db.connection import AsyncSessionLocal, engine
from server.db.models_base import (
    MESSAGE_STATUS_ENUM,
    Base,
    Chat,
    MessageStatus,
    ChatMember,
    Message,
    PushOutbox,
    PushToken,
    Reaction,  # noqa: F401 (реэкспорт модели для тестов/сервисов через фасад)
    RefreshToken,
    Report,
    SecurityEvent,
    Setting,
    User,
    VerifyCode,
)
from server.db.session_manager import (
    aq,
    aq1,
    cleanup_expired_refresh_tokens,
    delete_expired_messages,
    get_db,
    init_db,
)
from server.db.connection import close_pool  # noqa: F401 (совместимость фасада)

__all__ = [
    "AsyncSessionLocal",
    "MESSAGE_STATUS_ENUM",
    "MessageStatus",
    "Base",
    "DATABASE_URL",
    "IS_SQLITE",
    "Chat",
    "ChatMember",
    "Message",
    "PushOutbox",
    "PushToken",
    "RefreshToken",
    "Report",
    "SecurityEvent",
    "Setting",
    "User",
    "VerifyCode",
    "aq",
    "aq1",
    "cleanup_expired_refresh_tokens",
    "close_pool",
    "delete_expired_messages",
    "engine",
    "get_db",
    "init_db",
]
