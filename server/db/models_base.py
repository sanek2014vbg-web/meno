"""ORM-модели MeNo (атомарный модуль слоя БД).

Только определения таблиц и базовый класс — без движка, сессий и логики
доступа к данным. Это позволяет миграциям Alembic и тестам импортировать
схему, не поднимая connection pool.
"""

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase


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
    phone = Column(String, nullable=True)  # legacy
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
    chat_id = Column(
        Integer, ForeignKey("chats.id", ondelete="CASCADE"), primary_key=True
    )
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    role = Column(String, server_default="member")
    joined_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))


class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, autoincrement=True)
    chat_id = Column(
        Integer, ForeignKey("chats.id", ondelete="CASCADE"), nullable=False
    )
    sender_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    type = Column(String, server_default="text")
    content = Column(Text, server_default="")
    media_path = Column(String)
    duration = Column(Integer, server_default="0")
    ttl_seconds = Column(Integer)
    # v2.0 Пункт 2 «Сгорающие сообщения»: абсолютный момент физической
    # смерти сообщения (tz-aware UTC). Рассчитывается при отправке как
    # created_at + ttl_seconds; NULL => сообщение не сгорает. Дворник
    # (server/services/janitor.py) удаляет строки с expires_at <= now и
    # рассылает событие message_delete. Индекс idx_messages_expires_at
    # покрывает диапазонное сканирование janitor'а на больших объёмах.
    expires_at = Column(DateTime(timezone=True))
    view_once = Column(Boolean, server_default="0", nullable=False)
    viewed = Column(Boolean, server_default="0", nullable=False)
    e2e = Column(Boolean, server_default="0", nullable=False)
    # Идемпотентность отправки: клиентский idempotency-key (уникален в рамках чата)
    client_id = Column(String(64), nullable=True)
    # --- Этап 7.3: Ответы (replies) ---
    # На какое сообщение отвечает данное. SET NULL: при удалении оригинала
    # ответ остаётся, просто теряет preview (уровень приложения чипит
    # reactions-каскады вручную — см. routes_messages._cascade_delete_message).
    reply_to_id = Column(
        Integer, ForeignKey("messages.id", ondelete="SET NULL"), nullable=True
    )
    # --- Этап 7.3: Денормализованная сводка реакций ---
    # JSON-строка {"emoji": count} — читается одним SELECT вместе со строкой
    # messages без JOIN/GROUP BY (защита от N+1 на выдачах истории).
    # Обновляется ТОЛЬКО атомарным UPDATE с searched-CASE (см. routes):
    # два конкурентных toggle не могут испортить счётчик друг друга.
    reactions_summary = Column(Text, nullable=False, server_default="{}")
    # --- Этап 7.3: CAS-ранг статуса доставки (native_enum=False) ---
    # В БД лежит SMALLINT, а не PG-enum: диалект-переносимость SQLite/PG и
    # возможность атомарного UPDATE ... SET status_rank = CASE WHEN
    # status_rank < :new THEN ... через числовое сравнение рангов
    # ('sent'=0, 'delivered'=1, 'read'=2). Ранг монотонно растёт — гонка
    # двух параллельных отметок не может «откатить» статус назад.
    status_rank = Column(SmallInteger, nullable=False, server_default="0")
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

    __table_args__ = (
        Index("idx_messages_chat_id_id_desc", "chat_id", "id"),
        Index("idx_messages_sender_created", "sender_id", "created_at"),
        Index("idx_messages_ttl", "ttl_seconds"),
        Index("idx_messages_expires_at", "expires_at"),
        Index("idx_messages_reply_to", "reply_to_id"),
        # Идемпотентность отправки: один client_id не может повториться в чате
        Index("uq_messages_chat_client", "chat_id", "client_id", unique=True),
    )


class Reaction(Base):
    """Этап 7.3: E2EE-реакция на сообщение.

    Приватность по дизайну: сервер НЕ знает эмодзи — он хранит только
    AES-GCM blob (`encrypted_payload`), зашифрованный общим секретом чата
    на стороне клиента. Сервер видит лишь факт «кто и когда прореагировал»
    (метаданные доставки неизбежны), но не содержание.

    Идемпотентность обеспечивает UniqueConstraint(message_id, user_id):
    один пользователь — максимум одна реакция на сообщение; повторный
    POST того же эмодзи снимает её (toggle) на уровне приложения.
    """

    __tablename__ = "reactions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    message_id = Column(
        Integer, ForeignKey("messages.id", ondelete="CASCADE"), nullable=False
    )
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    encrypted_payload = Column(Text, nullable=False)
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

    __table_args__ = (
        UniqueConstraint("message_id", "user_id", name="uq_reactions_message_user"),
        Index("idx_reactions_message", "message_id"),
    )


class PushOutbox(Base):
    """Автономная очередь push-событий (long-polling fallback, Этап 3.3 ТЗ)."""

    __tablename__ = "push_outbox"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    title = Column(String(200), server_default="")
    body = Column(String(500), server_default="")
    data = Column(Text, server_default="{}")
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

    __table_args__ = (Index("idx_push_outbox_user", "user_id", "id"),)


class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, autoincrement=True)
    chat_id = Column(
        Integer, ForeignKey("chats.id", ondelete="CASCADE"), nullable=False
    )
    message_id = Column(
        Integer, ForeignKey("messages.id", ondelete="CASCADE"), nullable=False
    )
    reporter_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    reason = Column(Text, server_default="")
    status = Column(String, server_default="open")
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

    __table_args__ = (Index("idx_reports_status", "status"),)


class Setting(Base):
    __tablename__ = "settings"
    key = Column(String, primary_key=True)
    value = Column(String)


class PushToken(Base):
    __tablename__ = "push_tokens"
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token = Column(String, primary_key=True)
    platform = Column(String, server_default="android")
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

    __table_args__ = (Index("idx_push_tokens_user", "user_id"),)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    token = Column(String, primary_key=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    family = Column(String, nullable=True)  # ротация: поколение сессии
    parent = Column(String, nullable=True)  # предок (для детекции переиспользования)
    revoked = Column(Boolean, server_default="0", nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

    __table_args__ = (Index("idx_refresh_tokens_user", "user_id"),)


class SecurityEvent(Base):
    """Audit-лог значимых событий безопасности (Этап 2.3 ТЗ)."""

    __tablename__ = "security_events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"), nullable=False)
    event_type = Column(
        String(48), nullable=False
    )  # login_failed, register, refresh_reuse...
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    username = Column(String(64), nullable=True)
    ip = Column(String(64), nullable=True)
    detail = Column(Text, server_default="")

    __table_args__ = (
        Index("idx_security_events_type_ts", "event_type", "ts"),
        Index("idx_security_events_user", "user_id"),
    )
