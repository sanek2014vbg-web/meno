"""MeNo — конфигурация сервера (только из переменных окружения).

Принципы:
- никаких секретов в коде: MENO_JWT_SECRET обязателен вне DEBUG-режима;
- ядро работает без внешних платных сервисов (S3/FCM/Sentry опциональны);
- вся конфигурация читается один раз при импорте и валидируется.
"""
import os
import secrets


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise RuntimeError(f"{name} должен быть целым числом, получено: {raw!r}")


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name).lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


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


# --- Режим работы ---
# DEV_ENV=1 разрешает запуск с временным dev-секретом JWT (только локальная разработка).
DEV_ENV = _env_bool("MENO_DEV_ENV", False)

# --- Database ---
# PostgreSQL: postgresql+asyncpg://user:pass@host:port/dbname
# Локально без сервера можно использовать SQLite: sqlite+aiosqlite:///./meno.db
DATABASE_URL = _normalize_db_url(_env("MENO_DATABASE_URL", "sqlite+aiosqlite:///./meno.db"))
IS_SQLITE = DATABASE_URL.startswith("sqlite")

# --- Redis ---
# Опционален: кеширование и pub/sub WS автоматически деградируют до in-process режима.
REDIS_URL = _env("MENO_REDIS_URL", "")

# --- Sentry ---
# DSN для интеграции с Sentry (получается в панели управления Sentry). Пусто = отключено.
SENTRY_DSN = _env("MENO_SENTRY_DSN", "")

# --- JWT ---
_KNOWN_INSECURE_SECRETS = {
    "meno-dev-secret-change-me",
    "meno-dev-secret",
    "change-me",
    "secret",
    "your_random_long_string_here",
}


def _resolve_jwt_secret() -> tuple[str, bool]:
    """Возвращает (secret, is_ephemeral_dev).

    P0-требование: продакшен не стартует с дефолтным/известным секретом.
    """
    raw = os.environ.get("MENO_JWT_SECRET", "").strip()
    if raw and raw not in _KNOWN_INSECURE_SECRETS:
        if len(raw) < 32:
            raise RuntimeError(
                "MENO_JWT_SECRET слишком короткий (минимум 32 символа). "
                'Сгенерируйте: python -c "import secrets; print(secrets.token_urlsafe(48))"'
            )
        return raw, False
    if DEV_ENV:
        # Только для локальной разработки: одноразовый секрет, нестабильный между рестартами.
        return secrets.token_urlsafe(48), True
    raise RuntimeError(
        "MENO_JWT_SECRET не задан (или равен известному небезопасному значению).\n"
        "Это требование безопасности уровня P0: сервер отказывается стартовать.\n"
        "Сгенерируйте уникальный секрет:\n"
        '  python -c "import secrets; print(secrets.token_urlsafe(48))"\n'
        "и экспортируйте его в окружение (см. .env.example / deploy/RUNBOOK.md).\n"
        "Для локальной разработки без секрета используйте MENO_DEV_ENV=1."
    )


JWT_SECRET, JWT_SECRET_IS_EPHEMERAL = _resolve_jwt_secret()
JWT_ALGO = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = _env_int("MENO_ACCESS_TOKEN_EXPIRE_MINUTES", 15)
REFRESH_TOKEN_EXPIRE_DAYS = _env_int("MENO_REFRESH_TOKEN_EXPIRE_DAYS", 7)

# --- Владелец проекта (DevMode) ---
# Username владельца получает роль admin автоматически при регистрации
ADMIN_USERNAME = _env("MENO_ADMIN_USERNAME", "owner").lower()

# --- Файлы ---
UPLOAD_DIR = _env("MENO_UPLOAD_DIR", os.path.join(os.path.dirname(__file__), "uploads"))
MAX_UPLOAD_MB = _env_int("MENO_MAX_UPLOAD_MB", 50)

# --- S3 / MinIO (опциональный профиль объектного хранилища) ---
# Если MENO_S3_ENDPOINT не задан — файлы хранятся локально в UPLOAD_DIR.
# Это позволяет запускать проект бесплатно без S3/MinIO-серверов.
S3_ENABLED = bool(_env("MENO_S3_ENDPOINT"))
S3_BUCKET = _env("MENO_S3_BUCKET", "meno-uploads")
S3_ENDPOINT = _env("MENO_S3_ENDPOINT") or None  # None => AWS
S3_ACCESS_KEY = _env("MENO_S3_ACCESS_KEY")
S3_SECRET_KEY = _env("MENO_S3_SECRET_KEY")
S3_REGION = _env("MENO_S3_REGION", "us-east-1")
S3_USE_SSL = _env_bool("MENO_S3_USE_SSL", True)

# --- Антиспам ---
SPAM_MSG_PER_MINUTE = _env_int("MENO_SPAM_MSG_PER_MINUTE", 20)  # сообщений в минуту на пользователя

# --- Защита от брутфорса (rate limiting) ---
RL_LOGIN_LIMIT = _env_int("MENO_RL_LOGIN_LIMIT", 30)      # попыток входа
RL_LOGIN_WINDOW = _env_int("MENO_RL_LOGIN_WINDOW", 900)   # за 15 минут на связку IP+username
RL_REGISTER_LIMIT = _env_int("MENO_RL_REGISTER_LIMIT", 10)
RL_REGISTER_WINDOW = _env_int("MENO_RL_REGISTER_WINDOW", 3600)
RL_UPLOAD_LIMIT = _env_int("MENO_RL_UPLOAD_LIMIT", 60)
RL_UPLOAD_WINDOW = _env_int("MENO_RL_UPLOAD_WINDOW", 300)
RL_GLOBAL_LIMIT = _env_int("MENO_RL_GLOBAL_LIMIT", 900)   # любых запросов к API...
RL_GLOBAL_WINDOW = _env_int("MENO_RL_GLOBAL_WINDOW", 60)  # ...в минуту на IP
RL_TRUST_PROXY = _env_bool("MENO_RL_TRUST_PROXY", True)   # учитывать X-Forwarded-For (за nginx)

# --- Логирование ---
# access-лог uvicorn отключаем: в query-параметрах может оказаться токен.
LOG_ACCESS_ENABLED = _env_bool("MENO_LOG_ACCESS", True)

# --- CORS ---
# По умолчанию — пусто (без внешних origins). Для веб-клиента перечислите
# точные origins через запятую: https://chat.example.com,http://localhost:8550
CORS_ORIGINS = [o.strip() for o in _env("MENO_CORS_ORIGINS", "").split(",") if o.strip()]

# --- Push-уведомления (FCM, полностью опциональны) ---
FCM_SERVER_KEY = _env("MENO_FCM_SERVER_KEY")
FCM_CREDENTIALS = _env("MENO_FCM_CREDENTIALS")  # путь к service account JSON

# --- Название приложения ---
APP_NAME = "MeNo"


def is_production() -> bool:
    """Продакшен = НЕ локальная разработка (MENO_DEV_ENV не выставлен)."""
    return not DEV_ENV
