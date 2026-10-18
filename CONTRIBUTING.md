# Contributing to MeNo Messenger

Спасибо, что хотите улучшить MeNo — privacy-first self-hosted E2EE-мессенджер.
Ниже — обязательный минимум: как поднять окружение, какие проверки запускать
локально и по каким правилам принимается PR.

## Golden Rules

1. **No direct changes to `main`.** Ветку `main` принимаем только через
   squash-merge зелёного PR. Любой коммит прямо в `main` откатывается.
2. Одна ветка = одна ответственность: `feat/...`, `fix/...`, `docs/...`, `chore/...`.
3. Ни один секрет (JWT, ключи MinIO, `.env`) не попадает в коммит.
   Локальный скан gitleaks + CI блокируют историю принудительно.
4. Новая фича без теста — не фича. Каждый endpoint/service получает хотя бы
   один async-тест (`tests/unit` или `tests/integration`).
5. Утверждения в README/roadmap обязаны быть greppable в коде. Прототипы «на
   бумаге» (фича описана, кода нет) запрещены — это правило родом из аудита
   v0.x, см. раздел «Документация».

## Локальный setup

Требуется: Python 3.11 (единый стандарт: Dockerfile, CI, poetry), Docker.

```bash
git clone https://github.com/<org>/meno-messenger.git && cd meno-messenger

# 1. Инфраструктура: PostgreSQL 16 + Redis 7 (+ MinIO опционально)
docker compose up -d postgres redis

# 2. Окружение
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r server/requirements.txt -r client/requirements.txt

# 3. Конфигурация — ТОЛЬКО из примера; живой .env в git запрещено
cp .env.example .env
# сгенерируйте уникальный секрет:
python -c "import secrets; print(secrets.token_urlsafe(48))"  # -> MENO_JWT_SECRET

# 4. Pre-commit хуки (ruff + hygiene)
pre-commit install
```

Сервер для разработки: `uvicorn server.main:fastapi_app --reload --port 8000`
(при разработке вне прода можно `MENO_DEV_ENV=1`; в проде Fail-Fast config.py
отказывается стартовать с дефолтным/пустым JWT-секретом).

## Проверки перед PR

```bash
ruff check . && ruff format --check .
pytest tests/unit tests/integration          # полный зелёный прогон
mypy server                                  # строгий слой типов
```

CI повторяет то же на матрице PostgreSQL 16 + SQLite и Redis 7
(Fakeredis с реальным Lua-EVAL допускается только локально).

## PR-чеклист

- [ ] Ветка создана от актуального `main`, никаких коммитов прямо в `main`
- [ ] `ruff check` / `ruff format` — чисто
- [ ] Все тесты зелёные, добавлены тесты на новое поведение
- [ ] Миграции Alembic есть и диалект-безопасны (SQLite/Postgres); изменения
      схемы совместимы со `server/db/schema_compat.py`
- [ ] Никаких секретов в diff; `.env` не затронут
- [ ] Документация синхронизирована: README/SECURITY обновлены, если изменился
      контракт API или модель угроз
- [ ] Описание PR: что + зачем + как проверено (screenshots для UI-правок)

## Стиль кода

Python 3.11, full-async (FastAPI + SQLAlchemy 2.0 AsyncSession), единый стиль
импортов `from server import ...`. Приоритеты: читаемость > лаконичность >
макрооптимизация. Горячие пути не трогают БД (см. typing-service, WS fan-out).

Questions? Открывайте issue с меткой `question`.
