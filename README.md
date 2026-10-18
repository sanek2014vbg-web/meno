# MeNo Messenger

[![CI](https://github.com/MeNo-Messenger/meno/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/MeNo-Messenger/meno/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A570%25-brightgreen)](.github/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11-blue.svg)](server/Dockerfile)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Security Policy](https://img.shields.io/badge/security-policy-red)](SECURITY.md)

**MeNo** — production-ready мессенджер сквозным шифрованием (E2EE), полностью автономный
на одном self-hosted VPS: без SMS-шлюзов, FCM, Sentry и облачных S3 ядро сохраняет
полную функциональность (локальное хранилище файлов, WebSocket-доставка, outbox-push).

## Архитектура

```
┌─────────────────────┐        ┌──────────────────────────────────────────┐
│  Client (Flet)      │  WSS   │  Server (FastAPI, async SQLAlchemy 2.0)  │
│  X25519 + AES-GCM   │◄──────►│  ├─ REST API (auth, chats, messages,     │
│  keyring / Android  │  HTTPS │  │   admin, files)                        │
│  Keystore (Этап 7.1)│        │  ├─ WS Gateway → Redis Pub/Sub           │
└─────────────────────┘        │  │   (масштабирование на N воркеров)      │
                               │  ├─ Rate limiter (Redis Lua, fallback)   │
                               │  ├─ Audit log (security_events)          │
                               │  └─ Alembic migrations                   │
                               └───────┬──────────────┬───────────────┬───┘
                                        │              │               │
                                 ┌──────▼─────┐  ┌─────▼────┐  ┌──────▼──────┐
                                 │ PostgreSQL │  │  Redis 7 │  │ MinIO / S3  │
                                 │ 16 (+FTS   │  │ cache +  │  │ (опционально;│
                                 │  russian)  │  │ pub/sub  │  │ иначе локаль-│
                                 └────────────┘  └──────────┘  │ ные файлы)   │
                                                              └───────────────┘
```

Ключевые компоненты:

| Слой | Технологии | Примечание |
|---|---|---|
| Backend | FastAPI, SQLAlchemy (async), Pydantic v2 | Единый пакетный async-стиль импортов (`server/app`) |
| Real-time | WebSocket + **Redis Pub/Sub** | Любой воркер публикует, все подписчики доставляют — горизонтальное масштабление за LB |
| Аутентификация | JWT access + **ротация refresh-сессий** | Детекция переиспользования украденного токена ⇒ отзыв всей семьи сессий |
| Хранилище | PostgreSQL 16 (прод) / SQLite (dev/тесты) | Диалект-безопасный cleanup, курсорная пагинация, идемпотентность по `client_id` |
| Поиск | PG `to_tsvector('russian')` + GIN / SQLite LIKE | Корректная кириллица (дефект A12 закрыт) |
| Файлы | S3-совместимое (MinIO) или локальный volume | Потоковая загрузка, профиль опционален |
| Наблюдаемость | Loguru, `/health`, Sentry — строго опционален | Аварийно отключается пустым `MENO_SENTRY_DSN` |
| Клиент | Flet 1.x (Flutter for Python) | E2EE-ключи в OS keyring / Android Keystore, safety-number верификация |

## Быстрый старт (Self-hosted VPS, одна команда)

Требования: Docker + docker-compose, ~2 ГБ RAM, свободные порты 8000/5432/6379/9000.

```bash
git clone https://github.com/MeNo-Messenger/meno.git && cd meno

# 1. Конфигурация: ОБЯЗАТЕЛЬНО задайте уникальный MENO_JWT_SECRET
cp .env.example .env
python -c "import secrets; print('MENO_JWT_SECRET=' + secrets.token_urlsafe(48))" >> .env
# также задайте MENO_PG_PASSWORD в .env

# 2. Поднимите весь стек (db + redis + minio + app).
#    Entrypoint контейнера сам выполнит `alembic upgrade head` перед uvicorn.
docker compose up -d --build

# 3. Проверка
curl http://localhost:8000/health    # {"status":"ok","database":"up","redis":"up"}
```

Сервер **отказывается стартовать** в prod-режиме при отсутствии/дефолтности
`MENO_JWT_SECRET` (жёсткая валидация конфига, дефект A9/P0 закрыт).

### Запуск клиента

```bash
cd client
pip install -r requirements.txt
MENO_SERVER_URL=http://localhost:8000 python main.py
```

Ключи шифрования сохраняются в защищённое системное хранилище
(`client/auth_storage.py`: Windows Credential Manager / macOS Keychain /
Secret Service / Android Keystore; для headless — шифрованный файл-фолбэк).

## Разработка: линтеры и async-тесты

```bash
cd server
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Статический анализ и форматирование (тот же ruff, что в CI)
ruff check .
ruff format --check .

# Асинхронные интеграционные тесты (SQLite из коробки; PG/Redis — через env)
pytest tests -q --cov=. --cov-fail-under=70

# То же, но против реальных сервисов (как в CI):
DATABASE_URL=postgresql+asyncpg://meno:meno@localhost:5432/meno_test \
REDIS_URL=redis://localhost:6379/0 \
MENO_JWT_SECRET=$(python -c "import secrets;print(secrets.token_urlsafe(48))") \
pytest tests -q --cov=. --cov-fail-under=70

# Миграции
alembic upgrade head
```

Pre-commit hooks (ruff + gitleaks) ставятся один раз:

```bash
pip install pre-commit && pre-commit install
```

## Структура репозитория

```
server/            FastAPI backend (routes_*.py, services/, db/, ws_manager.py)
  Dockerfile       multi-stage production-образ (python:3.11-slim, non-root)
  entrypoint.sh    alembic upgrade head → uvicorn
client/            Flet UI (auth_storage.py, chat_ui.py, screens/)
tests/             unit/ + integration/ (pytest-asyncio, PG16/SQLite матрица)
migrations/        Alembic (один head, включая FTS 'russian' и security_events)
deploy/            setup_vps.sh, meno.service
.github/workflows/ ci.yml — gitleaks, ruff, pytest(PG+Redis), coverage≥70%, docker build
SECURITY.md        политика уязвимостей + процедура ротации секретов
CONTRIBUTING.md    setup, проверки перед PR, Golden Rules («No direct changes to main»)
CODE_OF_CONDUCT.md Contributor Covenant v2.1
docker-compose.yml self-hosted стек: app + postgres + redis + minio
```

## Безопасность

- Сообщения об уязвимостях — см. [SECURITY.md](SECURITY.md).
- Fail-Fast конфигурации (`server/config.py`): в продакшене сервер **отказывается
  стартовать** без уникального `MENO_JWT_SECRET`; для локальной разработки —
  явный флаг `MENO_DEV_ENV=1`.
- Секретов в git нет: `.env` выведен из индекса и в `.gitignore`, CI-скан
  gitleaks блокирует попадание ключей в историю. Локальный pre-commit включает
  ruff/ruff-format/hygiene-хуки; gitleaks исполняется в CI (локальный хук —
  TODO-трекер в CONTRIBUTING, не утверждается как факт).
- Ветки `main` защищены: обязательный зелёный CI, no force-push.

## Оптимизации бэкенда (Этап 7.3 / v1.0.0)

- **Batch-load реакций против N+1.** История сообщений обогащается сводкой
  реакций ОДНИМ запросом `IN (:ids)` (expanding bindparam) с O(1)-агрегацией в
  Python-словарь (`load_reactions_batch`, `server/routes_reactions.py`) — вместо
  SELECT на каждое сообщение списка.
- **Денормализация `reactions_summary`.** Готовая JSON-сводка хранится в
  таблице `messages` и пересобирается атомарно в той же транзакции toggle-роута
  — чтение ленты не касается таблицы `reactions` вовсе.
- **Application-level каскады.** DELETE-роуты явно чистят зависимости
  (`reply_to_id=NULL`, `DELETE FROM reactions WHERE message_id=:id`) до удаления
  строки сообщения — защита от FK-«сирот» на SQLite, где прагма FK не всегда
  включена.
- **`schema_compat.py`.** Диалект-безопасная рантайм-ревизия схемы через
  `sa.inspect()`: самодельные SQLite-инсталляции и тестовые БД, созданные до
  Этапа 7.3, догоняют схему на лету (PG прод мигрируется Alembic).

## Roadmap клиента (Этап 7)

- [x] 7.1 Ключи в Android Keystore / OS keyring (`client/auth_storage.py`)
- [x] 7.2 Верификация E2E-отпечатков (Safety Numbers, диалог в `chat_ui.py`)
- [x] 7.3 UX: реакции, редактирование, ответы (replies), статусы sent/delivered/read

## License

MIT — см. [LICENSE](LICENSE).
