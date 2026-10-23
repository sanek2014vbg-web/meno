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


class ChatInvite(Base):
    """Одноразовые инваит-ссылки в чат с TTL (каркас интеграции Пункта 5 аудита).

    Демонстрирует контракт «новая таблица с TTL подключается к дворнику
    РЕГИСТРАЦИЕЙ СТРОКИ janitor_jobs, а не правкой цикла»: джоба
    'chat_invites_ttl' вычищает строки с expires_at <= now - grace.
    """

    __tablename__ = "chat_invites"
    id = Column(Integer, primary_key=True, autoincrement=True)
    chat_id = Column(
        Integer, ForeignKey("chats.id", ondelete="CASCADE"), nullable=False
    )
    code = Column(String(64), unique=True, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    max_uses = Column(Integer, nullable=False, server_default="1")
    uses = Column(Integer, nullable=False, server_default="0")
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime, server_default=text("CURRENT_TIMESTAMP"))

    __table_args__ = (
        Index("idx_chat_invites_expires_at", "expires_at"),
        Index("idx_chat_invites_chat", "chat_id"),
    )


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


class JanitorJob(Base):
    """Реестр фоновых TTL-задач дворника (архитектурный аудит, Пункт 5).

    Каждая строка описывает ОДИН регламент очистки:
      job            — каноническое имя ('messages_ttl', 'refresh_tokens', ...);
      table_name     — обслуживаемая таблица;
      ttl_column     — колонка с абсолютным дедлайном (expires_at);
      grace_seconds  — дополнительный льготный период после дедлайна;
      interval_seconds — минимальный возраст последней успешной волны;
      enabled        — выключатель без изменения кода;
      status         — состояние advisory-лока ('idle' | 'running'):
                       атомарный UPDATE status='idle'->'running' гарантирует,
                       что на SQLite (нет SELECT FOR UPDATE) и PostgreSQL
                       волну выполняет ровно один воркер за раз;
      owner          — идентификатор воркера-локера (observability);
      last_run_at / last_deleted_count — телеметрия последнего тика.

    janitor (server/services/janitor.py) читает реестр каждый тик: новые
    таблицы с TTL подключаются РЕГИСТРАЦИЕЙ СТРОКИ (миграция/админ-команда),
    а не правкой цикла дворника.
    """

    __tablename__ = "janitor_jobs"
    job = Column(String(64), primary_key=True)
    table_name = Column(String(64), nullable=False)
    ttl_column = Column(String(64), nullable=False, server_default="expires_at")
    grace_seconds = Column(Integer, nullable=False, server_default="0")
    interval_seconds = Column(Integer, nullable=False, server_default="60")
    enabled = Column(Boolean, nullable=False, server_default="1")
    status = Column(String(16), nullable=False, server_default="idle")
    owner = Column(String(64), nullable=True)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    last_deleted_count = Column(Integer, nullable=False, server_default="0")
    updated_at = Column(
        DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP"), nullable=False
    )

    __table_args__ = (Index("idx_janitor_jobs_enabled_status", "enabled", "status"),)


class ComplianceAuditLog(Base):
    """Официальный корпоративный DLP-журнал (Data Loss Prevention / комплаенс).

    Политика хранения объявлена в пользовательском соглашении (Privacy Policy):
    все сообщения платформы журналируются для защиты интеллектуальной
    собственности и расследования инцидентов. Исчезающие сообщения
    (messages.ttl_seconds IS NOT NULL) удаляются из основной таблицы дворником
    по expires_at — ДЛИТЕЛЬНЫЙ ЖУРНАЛ является единственным легальным способом
    сохранить доказательную копию для аудита утечек и судебных разбирательств.

    Прозрачность системы обеспечивается тремя механизмами:
      1. Факт журналирования зафиксирован в пользовательском соглашении;
      2. WS-событие каждого сохраняемого сообщения содержит поле
         ``compliance_logged`` (см. server/services/message_send.deliver) —
         любой клиент может показать это пользователю;
      3. Каждое чтение журнала возможно только superadmin'ом и пишется в
         security_events + транслируется в админский тап (неизменяемый аудит
         доступа к журналу).

    Идемпотентность: UNIQUE(message_id) — повторный захват (переотправка с тем
    же client_id, рестарт транзакции) не создаёт дублей записи.
    author_id намеренно Integer БЕЗ ForeignKey: удалённый аккаунт не должен
    каскадно стирать журнал комплаенса (требование DLP — записи переживают
    субъекта). FK chat_id с ondelete="SET NULL": удаление чата тоже не должно
    уничтожать доказательства.

    Доступ к таблице — ТОЛЬКО через админский контур
    (/api/admin/compliance-logs, двойной контур: admin-JWT + one-time билет);
    ни один пользовательский роут её не читает.
    """

    __tablename__ = "compliance_audit_logs"
    id = Column(String(36), primary_key=True)  # UUID v4 (сгенерирован при INSERT)
    message_id = Column(Integer, nullable=False, unique=True)
    chat_id = Column(
        Integer, ForeignKey("chats.id", ondelete="SET NULL"), nullable=True
    )
    author_id = Column(Integer, nullable=False)
    # Колонка называется `body` (не `text`): имя `text` затенило бы
    # sqlalchemy.text в теле класса и сломало server_default ниже —
    # классический collision имён атрибутов/функций в declarative-моделях.
    body = Column(Text, nullable=False, server_default="")
    logged_at = Column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False,
    )

    __table_args__ = (
        # Основной путь выборки в панели мониторинга: страница журнала по чату,
        # newest-first (seek по составному индексу за O(log N + limit)).
        Index("idx_compliance_logs_chat_logged", "chat_id", "logged_at"),
    )

