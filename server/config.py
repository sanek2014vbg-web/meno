import os

# --- Database ---
# PostgreSQL connection string: postgresql+asyncpg://user:pass@host:port/dbname
DATABASE_URL = os.environ.get("MENO_DATABASE_URL", "postgresql+asyncpg://meno_user:meno_password@db:5432/meno_db")

# --- Redis ---
REDIS_URL = os.environ.get("MENO_REDIS_URL", "redis://redis:6379/0")

# --- Sentry ---
# DSN для интеграции с Sentry (получается в панели управления Sentry)
SENTRY_DSN = os.environ.get("MENO_SENTRY_DSN", "")

# --- JWT ---
# В продакшене обязательно задать MENO_JWT_SECRET (случайная длинная строка)
JWT_SECRET = os.environ.get("MENO_JWT_SECRET", "meno-dev-secret-change-me")
JWT_ALGO = "HS256"
JWT_EXPIRE_DAYS = 30

# --- Доставка кодов ---
# "test"     — код выводится в консоль (разработка)
# "telegram" — код отправляется через Telegram-бота
# "sms_ru"   — отправка через API SMS.RU
SMS_MODE = os.environ.get("MENO_SMS_MODE", "test")
SMS_RU_API_KEY = os.environ.get("MENO_SMS_RU_API_KEY", "")
SMS_RU_SENDER = os.environ.get("MENO_SMS_RU_SENDER", "MeNo")
TELEGRAM_BOT_TOKEN = os.environ.get("MENO_TG_BOT_TOKEN", "")

# --- Владелец проекта (DevMode) ---
# Номер телефона владельца получает роль admin автоматически при регистрации
ADMIN_PHONE = os.environ.get("MENO_ADMIN_PHONE", "")

# --- Файлы ---
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
MAX_UPLOAD_MB = 50

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