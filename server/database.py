"""MeNo — модуль базы данных (PostgreSQL asyncpg / SQLite aiosqlite).

- Полноценная многопользовательская работа без блокировок файлов (PG);
- Строгая типизация через SQLAlchemy 2.0 ORM-модели;
- Асинхронность (AsyncSession) — критично для FastAPI под нагрузкой;
- Ядро работает и на SQLite (self-hosted без PG), все запросы диалект-безопасны.
"""
import logging
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from server.config import DATABASE_URL, IS_SQLITE

logger = logging.getLogger("meno.database")


class Base(AsyncAttrs, DeclarativeBase):
    """Базовый класс для всех моделей БД."""


# --- Models ---


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    # Уникальный username вместо телефона: регистрация без номера телефона.
    # Колонка `phone` сохранена (nullable) только для совместимости со старыми БД.
    username = Column(String(32), unique=True, index=True, nullable=True)
    phone = Column(String, unique=True, nullable=True)
    password_hash = Column(String, nullable=False)
    display_name = Column(String, server_default="")
    role = Column(String, server_default="user")
    totp_secret = Column(String)
    twofa_enabled = Column(Boolean, server_default="0", nullable=False)
    avatar_path = Column(String)
    e2e_pub = Column(Text)
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))
    last_seen = Column(DateTime)
    failed_attempts = Column(Integer, server_default="0", nullable=False)
    lockout_until = Column(DateTime)


class VerifyCode(Base):
    __tablename__ = "verify_codes"
    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String, nullable=True)  # email/username (email-верификация)
    phone = Column(String, nullable=True)   # legacy
    code = Column(String, nullable=False)
    purpose = Column(String, server_default="register")
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, server_default="0", nullable=False)
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))


class Chat(Base):
    __tablename__ = "chats"
    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String, nullable=False)
    title = Column(String, server_default="")
    created_by = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))


class ChatMember(Base):
    __tablename__ = "chat_members"
    chat_id = Column(Integer, ForeignKey("chats.id", ondelete="CASCADE"), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role = Column(String, server_default="member")
    joined_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))


class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, autoincrement=True)
    chat_id = Column(Integer, ForeignKey("chats.id", ondelete="CASCADE"), nullable=False)
    sender_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    type = Column(String, server_default="text")
    content = Column(Text, server_default="")
    media_path = Column(String)
    duration = Column(Integer, server_default="0")
    ttl_seconds = Column(Integer)
    view_once = Column(Boolean, server_default="0", nullable=False)
    viewed = Column(Boolean, server_default="0", nullable=False)
    e2e = Column(Boolean, server_default="0", nullable=False)
    # Идемпотентность отправки: клиентский idempotency-key (уникален в рамках чата)
    client_id = Column(String(64), nullable=True)
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

    __table_args__ = (
        Index("idx_messages_chat_id_id_desc", "chat_id", "id"),
        Index("idx_messages_sender_created", "sender_id", "created_at"),
        Index("idx_messages_ttl", "ttl_seconds"),
        # Идемпотентность отправки: один client_id не может повториться в чате
        Index("uq_messages_chat_client", "chat_id", "client_id", unique=True),
    )


class PushOutbox(Base):
    """Автономная очередь push-событий (long-polling fallback, Этап 3.3 ТЗ)."""

    __tablename__ = "push_outbox"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(200), server_default="")
    body = Column(String(500), server_default="")
    data = Column(Text, server_default="{}")
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

    __table_args__ = (
        Index("idx_push_outbox_user", "user_id", "id"),
    )


class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, autoincrement=True)
    chat_id = Column(Integer, ForeignKey("chats.id", ondelete="CASCADE"), nullable=False)
    message_id = Column(Integer, ForeignKey("messages.id", ondelete="CASCADE"), nullable=False)
    reporter_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    reason = Column(Text, server_default="")
    status = Column(String, server_default="open")
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
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token = Column(String, primary_key=True)
    platform = Column(String, server_default="android")
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

    __table_args__ = (
        Index("idx_push_tokens_user", "user_id"),
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    token = Column(String, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    family = Column(String, nullable=True)      # ротация: поколение сессии
    parent = Column(String, nullable=True)      # предок (для детекции переиспользования)
    revoked = Column(Boolean, server_default="0", nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

    __table_args__ = (
        Index("idx_refresh_tokens_user", "user_id"),
    )


class SecurityEvent(Base):
    """Audit-лог значимых событий безопасности (Этап 2.3 ТЗ)."""

    __tablename__ = "security_events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"), nullable=False)
    event_type = Column(String(48), nullable=False)  # login_failed, register, refresh_reuse...
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username = Column(String(64), nullable=True)
    ip = Column(String(64), nullable=True)
    detail = Column(Text, server_default="")

    __table_args__ = (
        Index("idx_security_events_type_ts", "event_type", "ts"),
        Index("idx_security_events_user", "user_id"),
    )


# --- Engine & Session ---

_engine_kwargs: Dict[str, Any] = {"echo": False, "future": True}
if not IS_SQLITE:
    _engine_kwargs.update(pool_size=8, max_overflow=2)

engine = create_async_engine(DATABASE_URL, **_engine_kwargs)

AsyncSessionLocal = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


@asynccontextmanager
async def get_db():
    """Асинхронный контекстный менеджер сессии БД с транзакционным коммитом."""
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
    """Создаёт все таблицы на основе моделей SQLAlchemy (idempotent)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database schema initialized (%s).", "SQLite" if IS_SQLITE else "PostgreSQL")


async def close_pool() -> None:
    """Закрывает пул соединений."""
    await engine.dispose()


# --- Compatibility helpers ---


async def aq(session: AsyncSession, sql: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Выполняет SELECT и возвращает список словарей (именованные параметры)."""
    result = await session.execute(text(sql), params or {})
    return [dict(row._mapping) for row in result.all()]


async def aq1(session: AsyncSession, sql: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """SELECT на одну строку: dict или None."""
    result = await session.execute(text(sql), params or {})
    row = result.first()
    return dict(row._mapping) if row else None


# --- Диалект-безопасный TTL-cleanup (Этап 4.1 ТЗ) ---


async def delete_expired_messages(session: AsyncSession) -> int:
    """Удаляет протухшие (TTL) и просмотренные view-once сообщения.

    Работает и на PostgreSQL, и на SQLite: пороги «протухания» считаются
    на стороне Python (tz-aware UTC), поэтому никаких PG-специфичных
    конструкций вида `+ (ttl || ' seconds')::interval` в SQL нет.
    Возвращает число удалённых сообщений.
    """
    from datetime import timedelta

    from server.utils import utc_now

    now = utc_now()
    rows = await aq(
        session,
        "SELECT id, created_at, ttl_seconds, view_once, viewed FROM messages "
        "WHERE ttl_seconds IS NOT NULL OR (view_once = 1 AND viewed = 1)",
    )
    expired_ids = []
    for r in rows:
        created = r["created_at"]
        if created is not None and created.tzinfo is None:
            # БД хранит naive UTC — делаем значения сравнимыми
            from datetime import timezone

            created = created.replace(tzinfo=timezone.utc)
        if r["ttl_seconds"] is not None and created is not None:
            if now >= created + timedelta(seconds=int(r["ttl_seconds"])):
                expired_ids.append(r["id"])
                continue
        if r["view_once"] and r["viewed"]:
            expired_ids.append(r["id"])

    deleted = 0
    for mid in expired_ids:
        result = await session.execute(
            text("DELETE FROM messages WHERE id = :id"), {"id": mid}
        )
        deleted += result.rowcount or 0
    return deleted


async def cleanup_expired_refresh_tokens(session: AsyncSession) -> int:
    """Удаляет просроченные refresh-токены (переносимо между диалектами)."""
    from server.utils import utc_now

    result = await session.execute(
        text("DELETE FROM refresh_tokens WHERE expires_at < :now"),
        {"now": utc_now()},
    )
    return result.rowcount or 0
