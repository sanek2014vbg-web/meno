"""MeNo — пакет слоя работы с БД (рефакторинг god-module `database.py`).

Структура (Этап P1 рефакторинга архитектурного отчёта):

    server/db/models_base.py     — Declarative Base + все ORM-модели;
    server/db/connection.py      — движок, пул соединений, фабрика сессий;
    server/db/session_manager.py — get_db(), init_db(), TTL-cleanup, хелперы aq/aq1.

Модуль `server.database` сохранён как тонкий фасад-реэкспорт: весь существующий
код (`from server import database`, миграции Alembic, тесты) продолжает работать
без правок. Новый код должен импортировать атомарные модули напрямую.
"""
from server.db.connection import AsyncSessionLocal, close_pool, engine
from server.db.models_base import (
    Base,
    Chat,
    ChatMember,
    Message,
    PushOutbox,
    PushToken,
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

__all__ = [
    "AsyncSessionLocal",
    "Base",
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
