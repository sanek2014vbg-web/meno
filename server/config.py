import os

def _normalize_db_url(url: str) -> str:
    """Приводит строку подключения к asyncpg-драйверу.

    Поддерживает форматы, которые выдают бесплатные хостинги (Neon/Supabase):
    postgresql://..., postgres://..., ?sslmode=require и т.п.
    """
    for prefix in ("postgres+asyncpg://", "postgresql+asyncpg://"):
        if url.startswith(prefix):
            return url
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url

# --- Database ---
# PostgreSQL connection string: postgresql+asyncpg://user:pass@host:port/dbname
# Локально без сервера можно использовать SQLite: sqlite+aiosqlite:///./meno.db
DATABASE_URL = _normalize_db_url(
    os.environ.get("MENO_DATABASE_URL", "sqlite+aiosqlite:///./meno.db")
)
IS_SQLITE = DATABASE_URL.startswith("sqlite")

# --- Redis ---
# Опционален: без него кеширование просто отключается (in-memory fallback).
REDIS_URL = os.environ.get("MENO_REDIS_URL", "")

# --- Sentry ---
# DSN для интеграции с Sentry (получается в панели управления Sentry)
SENTRY_DSN = os.environ.get("MENO_SENTRY_DSN", "")

# --- JWT ---
# В продакшене обязательно задать MENO_JWT_SECRET (случайная длинная строка)
JWT_SECRET = os.environ.get("MENO_JWT_SECRET", "meno-dev-secret-change-me")
JWT_ALGO = "HS256"
JWT_EXPIRE_DAYS = 30

# --- Доставка кодов (LEGACY, не используется) ---
# Аутентификация переведена на username + пароль без телефона и SMS.
# Модули sms.py / sms_ru.py удалены из проекта.
SMS_MODE = "none"

# --- Владелец проекта (DevMode) ---
# Username владельца получает роль admin автоматически при регистрации
ADMIN_USERNAME = os.environ.get("MENO_ADMIN_USERNAME", "owner")

# --- Файлы ---
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
MAX_UPLOAD_MB = 50

# --- S3 / CDN Configuration (опционально) ---
# Если MENO_S3_ENDPOINT не задан — файлы хранятся локально в UPLOAD_DIR.
# Это позволяет запускать проект бесплатно без S3/MinIO-серверов.
S3_ENABLED = bool(os.environ.get("MENO_S3_ENDPOINT", "").strip())
S3_BUCKET = os.environ.get("MENO_S3_BUCKET", "meno-uploads")
S3_ENDPOINT = os.environ.get("MENO_S3_ENDPOINT", None) # If None, uses default AWS
S3_ACCESS_KEY = os.environ.get("MENO_S3_ACCESS_KEY", "")
S3_SECRET_KEY = os.environ.get("MENO_S3_SECRET_KEY", "")
S3_REGION = os.environ.get("MENO_S3_REGION", "us-east-1")
S3_USE_SSL = os.environ.get("MENO_S3_USE_SSL", "True") == "True"

# --- Антиспам ---
SPAM_MAX_CODES_PER_HOUR = 5   # запросов кода в час с одного номера
SPAM_MSG_PER_MINUTE = 20      # сообщений в минуту на пользователя

# --- Защита от брутфорса (rate limiting) ---
# Лимиты считаются по связке IP + телефон/пользователь (см. rate_limit.py):
# это ограничивает перебор конкретного аккаунта, но не блокирует
# сотни устройств за общим NAT оператора связи.
RL_LOGIN_LIMIT = 30            # попыток входа
RL_LOGIN_WINDOW = 900          # за 15 минут на связку IP+телефон
RL_REGISTER_LIMIT = 10         # запросов кода подтверждения
RL_REGISTER_WINDOW = 3600      # за час на связку IP+телефон
RL_VERIFY_LIMIT = 20           # попыток подтверждения кода
RL_VERIFY_WINDOW = 3600        # за час на связку IP+телефон
RL_UPLOAD_LIMIT = 60           # загрузок файлов
RL_UPLOAD_WINDOW = 300         # за 5 минут на связку IP+пользователь
RL_GLOBAL_LIMIT = 900          # любых запросов к API
RL_GLOBAL_WINDOW = 60          # в минуту на IP (защита от флуда)
RL_TRUST_PROXY = True          # учитывать X-Forwarded-For (за nginx)

# --- Логирование ---
# access-лог uvicorn отключаем: в query-параметрах может оказаться токен.
# Вместо него пишем свой санитизированный лог без тел запросов,
# паролей, ключей и текстов сообщений.
LOG_ACCESS_ENABLED = os.environ.get("MENO_LOG_ACCESS", "1") == "1"

# --- CORS ---
# Для нативной сборки клиента CORS не нужен; для веб-версии Flet
# разрешаем все источники (на проде за nginx — свой домен).
CORS_ORIGINS = os.environ.get("MENO_CORS_ORIGINS", "*").split(",")

# --- Название приложения ---
# --- Push-уведомления (FCM) ---
# Для фоновой доставки на Android. Если не заданы — push отключён,
# приложение работает через WebSocket (без ошибок).
FCM_SERVER_KEY = os.environ.get("MENO_FCM_SERVER_KEY", "")
FCM_CREDENTIALS = os.environ.get("MENO_FCM_CREDENTIALS", "")  # путь к service account JSON

# --- Название приложения ---
APP_NAME = "MeNo"