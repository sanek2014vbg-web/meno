"""MeNo — модуль базы данных (PostgreSQL, SQLAlchemy + asyncpg).

Переход на PostgreSQL обеспечивает:
- Полноценную многопользовательскую работу без блокировок файлов;
- Строгую типизацию данных через SQLAlchemy модели;
- Асинхронность (asyncpg), что критично для FastAPI сервера под нагрузкой;
- Масштабируемость и надежность хранения данных.
"""
import os
import logging
from typing import Any, Dict, List, Optional, Tuple, Sequence
from contextlib import asynccontextmanager

from sqlalchemy import (
    Column, Integer, String, Text, Boolean,
    ForeignKey, DateTime, Index, text, select
)

from sqlalchemy.ext.asyncio import (
    create_async_engine, 
    AsyncSession, 
    async_sessionmaker, 
    AsyncAttrs
)
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.sql import text as sql_text

from server.config import DATABASE_URL, IS_SQLITE

logger = logging.getLogger("meno.database")

# --- SQLAlchemy Base ---
class Base(AsyncAttrs, DeclarativeBase):
    """Базовый класс для всех моделей БД."""
    pass

# --- Models ---

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    # Уникальный username вместо телефона: регистрация без номера телефона.
    # Колонка `phone` сохранена (nullable) только для совместимости со старыми БД.
    username = Column(String(32), unique=True, index=True, nullable=True)
    phone = Column(String, unique=True, nullable=True)
    password_hash = Column(String, nullable=False)
    display_name = Column(String, server_default='')
    role = Column(String, server_default='user')
    totp_secret = Column(String)
    twofa_enabled = Column(Integer, server_default='0')
    avatar_path = Column(String)
    e2e_pub = Column(Text)
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))
    last_seen = Column(DateTime)
    failed_attempts = Column(Integer, server_default='0')
    lockout_until = Column(DateTime)

class VerifyCode(Base):
    __tablename__ = "verify_codes"
    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String, nullable=True)  # email/username (email-верификация)
    phone = Column(String, nullable=True)   # legacy
    code = Column(String, nullable=False)
    purpose = Column(String, server_default='register')
    expires_at = Column(DateTime, nullable=False)
    used = Column(Integer, server_default='0')
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

class Chat(Base):
    __tablename__ = "chats"
    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String, nullable=False)
    title = Column(String, server_default='')
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

class ChatMember(Base):
    __tablename__ = "chat_members"
    chat_id = Column(Integer, ForeignKey("chats.id"), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    role = Column(String, server_default='member')
    joined_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, autoincrement=True)
    chat_id = Column(Integer, ForeignKey("chats.id"), nullable=False)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    type = Column(String, server_default='text')
    content = Column(Text, server_default='')
    media_path = Column(String)
    duration = Column(Integer, server_default='0')
    ttl_seconds = Column(Integer)
    view_once = Column(Integer, server_default='0')
    viewed = Column(Integer, server_default='0')
    e2e = Column(Integer, server_default='0')
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

    __table_args__ = (
        Index("idx_messages_chat_id_id_desc", "chat_id", text("id DESC") if not IS_SQLITE else "id"),
    )

class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, autoincrement=True)
    chat_id = Column(Integer, ForeignKey("chats.id"), nullable=False)
    message_id = Column(Integer, ForeignKey("messages.id"), nullable=False)
    reporter_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    reason = Column(Text, server_default='')
    status = Column(String, server_default='open')
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))
    
    __table_args__ = (
        Index("idx_reports_status", "status"),
    )

class Setting(Base):
    __tablename__ = "settings"
    key = Column(String, primary_key=True)
    value = Column(String)

class PushToken(Base):
    __tablename__ = "push_tokens"
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token = Column(String, primary_key=True)
    platform = Column(String, server_default='android')
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))
    
    __table_args__ = (
        Index("idx_push_tokens_user", "user_id"),
    )

# --- Engine & Session ---

# pool_size=8 matches original POOL_SIZE
# max_overflow=2 allows brief spikes
engine = create_async_engine(
    DATABASE_URL, 
    echo=False, 
    pool_size=8, 
    max_overflow=2
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine, 
    class_=AsyncSession, 
    expire_on_commit=False
)

@asynccontextmanager
async def get_db():
    """Асинхронный контекстный менеджер для получения сессии БД."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

async def init_db() -> None:
    """Создаёт все таблицы в PostgreSQL на основе моделей SQLAlchemy."""
    async with engine.begin() as conn:
        # В Postgres create_all работает асинхронно через run_sync
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database schema initialized in PostgreSQL.")

async def close_pool() -> None:
    """Закрывает пул соединений."""
    await engine.dispose()

# --- Compatibility Helpers (Shim layer) ---
# Эти функции позволяют постепенно обновлять роуты, переходя от q() к aq()

async def aq(session: AsyncSession, sql: str, params: Tuple[Any, ...] = ()) -> List[Dict[str, Any]]:
    """Асинхронный аналог q(): выполняет SELECT и возвращает список словарей."""
    result = await session.execute(sql_text(sql), params)
    # Преобразуем строки SQLAlchemy в словари
    return [dict(row._mapping) for row in result.all()]

async def aq1(session: AsyncSession, sql: str, params: Tuple[Any, ...] = ()) -> Optional[Dict[str, Any]]:
    """Асинхронный аналог q1(): выполняет SELECT и возвращает одну строку или None."""
    result = await session.execute(sql_text(sql), params)
    row = result.first()
    return dict(row._mapping) if row else None
