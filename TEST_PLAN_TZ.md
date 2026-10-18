# MeNo Messenger — Полный тест-отчёт и ТЗ по оптимизации, уязвимостям, улучшениям

Дата проверки: 2026-10-18. Все выводы ниже получены фактическим прогоном команд в репозитории (не догадками).

---

## ЧАСТЬ 1. РЕЗУЛЬТАТЫ ПОЛНОГО ТЕСТИРОВАНИЯ

### 1.1 Прогон pytest (`pytest -q`)
```
1 failed, 16 passed in 4.68s        # testpaths=tests (штатный прогон CI)
FAILED tests/integration/test_auth_lockout.py::test_login_lockout — assert 400 == 403
```
**Корень падения (подтверждено чтением кода):** тест логинит несуществующего пользователя `lockout_tester`. Маршрут `/api/login` для неизвестного username всегда возвращает 400 (защита от enumeration), счётчик `failed_attempts` не инкрементируется → 403 недостижим. Это **дефект теста**, а не продукта. Второй тест файла — заглушка `pass` (ничего не проверяет).

### 1.2 Скрытый набор тестов `server/tests/test_core.py` (230 строк, НЕ входит в pytest.ini testpaths)
```
pytest server/tests/test_core.py                    → ERROR при сборке: MENO_JWT_SECRET не задан
MENO_DEV_ENV=1 pytest server/tests/test_core.py     → 1 passed, 16 ERRORS
```
**Корень:** фикстуры `user_alice`, `user_bob`, `chat` определены в `tests/conftest.py`, но файл лежит вне `testpaths`, и `client_as_user` зависит от них → fixture not found. 16 реально написанных интеграционных тестов (атомарная регистрация, ротация refresh, детекция кражи семьи сессий, поиск по кириллице, пагинация курсором, WS pub/sub fan-out, идемпотентность) **фактически не исполняются нигде**. CI запускает `pytest server/tests tests`, локально так запустить нельзя без env — расхождение Env Drift.

### 1.3 Покрытие (`--cov`)
| Слой | Покрытие |
|---|---|
| TOTAL (server+client) | **18%** |
| server (с учётом неисполняемых core-тестов) | ~34% |
| client/* (crypto.py, chat_ui.py, api_client.py, auth_storage.py) | **0%** |
| server/services/janitor.py, typing.py, s3_manager.py, merge_heads.py | **0%** |
| ws_manager.py | 30% |
| routes_chats.py | 19% |
| routes_messages.py | 29% |
| sessions.py | 29% |

Критично: **E2EE-криптография клиента (client/crypto.py, 159 stmt) не имеет ни одного теста** — ошибка в XChaCha20/Poly1305 или key-derivation останется незамеченной.

### 1.4 Ruff lint (`ruff check server/ tests/ client/`) — 33 ошибки
Блокирующие CI (`ruff check server/ tests/`):
- F401 неиспользуемые импорты: `server/main.py` (asyncio, StaticFiles), `server/routes_messages.py` (auth), `server/push.py`, `server/s3_manager.py`, `tests/*` (5 шт.)
- E402 imports not at top: `server/auth.py:22-23`, `tests/conftest.py` (6 мест)

Баги в клиенте (в CI не проверяется — `ruff check` только server/tests!):
- 🔴 **F821 `client/api_client.py:303`: `await asyncio.sleep(_retry_//_retry_delay(attempt))` — синтаксический мусор `_retry_//`, NameError в рантайме при ретраях на 502/503/504.** Ретрай-цикл HTTP-клиента сломан.
- 🔴 **F821 `client/chat_ui.py:910`: `time.monotonic()` — модуль `time` не импортирован → NameError при первом же событии «печатает…».** Фича typing indicator падает.
- E741 (`l`), F841/F401 в screens/*.

### 1.5 Ruff format (`ruff format --check server/ tests/`) — ПРОВАЛ CI
```
30 files would be reformatted, 3 already formatted
```
CI-джоб «Lint» содержит шаг `ruff format --check server/ tests/` → **красный CI уже на этом шаге**, до тестов.

### 1.6 Alembic — 🔴 подтверждён дубль ревизии
```
UserWarning: Revision a1b2c3d4e5f6 is present more than once
heads: a1b2c3d4e5f6, a1f2e3d4b5c6   (два head'а!)
```
Файлы `migrations/versions/a1b2c3d4e5f6_*.py` и `b7c1d2e3f4a5_*.py` объявляют **один и тот же revision id** `a1b2c3d4e5f6` при разном содержимом (первый — идемпотентный, переносимый между PG/SQLite; второй — с PG-специфичным `regexp_replace`, упадёт на SQLite). Поведение миграции зависит от порядка обхода каталога — непредсказуемо. Плюс граф имеет два head'а (merge `f7a8b9cafed0` не покрывает новый дубль).

### 1.7 pip-audit — 🔴 63 известных CVE в зафиксированных зависимостях сервера
| Пакет | Сейчас | CVE | Минимальная фикс-версия |
|---|---|---|---|
| PyJWT | 2.10.1 | ~13 advisory (PYSEC-2026-120/-175..-179, 4140-4183) | **2.14.0–2.15.0** |
| starlette (транзитивно от fastapi) | 0.41.3 | 6 advisory (PYSEC-2026-161, -248/-249, -1941/-1942, -2280/-2281) | 0.47.2+ |
| cryptography | 44.0.0 | PYSEC-2026-35, -1284, -2141, GHSA-537c-gmf6-5ccf | **46.0.6 / 49.0.0** |
| python-multipart | 0.0.20 | 6 advisory (DoS через multipart) | **0.0.31** |
| pytest | 8.3.4 | PYSEC-2026-1845 | 9.0.3 (dev-only) |
| lupa | 2.4 | PYSEC-2026-2613 | — |
Клиентские requirements — 0 CVE, но версии **не запинены** (`>=`).

### 1.8 Гигиена git (git status)
Закоммичено и/или всё ещё в индексе: `meno.db`, `meno_smoke.db`, `migration_temp.db`, `tests/meno_test.db(-shm/-wal)` (db-shm/wal пересоздаются каждым прогоном — вечный грязный diff), все `__pycache__/*.pyc` (изменённые бинарники в staged), временные скрипты `client/_check*.py`, логи. Удаления из прошлой сессии (`git rm --cached`) **не закоммичены** — работа зависла в индексе.

### 1.9 Прочие проверки
- CI отсутствует Dependabot/Renovate (`.github/` только workflows).
- WebSocket `/ws?token=` — JWT в query-параметре (утечка в access-логи/историю). Подтверждено: `server/main.py:148 async def ws_endpoint(websocket, token="")`.
- mypy/pyright в CI нет.
- `/metrics` endpoint нет (sentry есть, Prometheus — нет).

---

## ЧАСТЬ 2. ТЗ НА ДОРАБОТКУ

### Блок A. 🔴 P0 — сделать CI зелёным и вернуть исполнение тестов (1 день)

**A1. Починить `tests/integration/test_auth_lockout.py`**
- Критерии приёмки: перед циклом тест регистрирует `lockout_tester` через `POST /api/register`; затем MAX_FAILED_ATTEMPTS×(400) → следующая попытка 403 + текст «заблокирован»; изоляция от rate-limiter (логин-лимитер срабатывает раньше lockout — использовать уникальный IP/ключ или сброс limiter, как это делает conftest `reset_state`).
- Заменить тест-заглушку `test_login_success_resets_lockout` (`pass`) на реальный: установить failed_attempts=N, залогинить верным паролем, проверить `failed_attempts==0` через БД.

**A2. Включить `server/tests/test_core.py` в рабочий прогон**
- Вариант (предпочт.): перенести в `tests/integration/test_core.py`, чтобы conftest подхватывался через `testpaths`; либо добавить `server/tests` в testpaths + переместить conftest так, чтобы он был общим.
- В CI-шаге явно задать `MENO_DEV_ENV=1` (сейчас работает только случайно — через conftest, который core-тесты не видят).
- Приёмка: `pytest server/tests tests` → 33+ passed, 0 errors.

**A3. Устранить дубль alembic-ревизии**
- Удалить/переобозначить `b7c1d2e3f4a5_auth_username_no_phone.py` (его содержимое — устаревшая PG-only версия; остаётся идемпотентный `a1b2c3d4e5f6`). Если БД пользователей уже применяли обе — release notes + проверка `alembic current`.
- Проверить линейность графа: `alembic heads` → ровно один head; `alembic upgrade head` на чистой SQLite и на PG (CI-matrix).
- Добавить в CI job шагом: `python -m alembic heads | wc -l == 1` и smoke `upgrade head` на обеих СУБД.

**A4. Исправить два рантайм-бага клиента (F821)**
- `client/api_client.py:303` → `await asyncio.sleep(_retry_delay(attempt))`.
- `client/chat_ui.py` → добавить `import time` (или перевести на `asyncio.get_event_loop().time()`).
- Расширить CI-линтер на `client/`: `ruff check server/ tests/ client/`.

**A5. Прогнать `ruff format server/ tests/` (30 файлов) одним коммитом-«форматированием», отдельно от смысловых изменений.**

### Блок B. 🔴 P0 — безопасность

**B1. Обновить зависимости по pip-audit**
- PyJWT→2.15.0, python-multipart→0.0.31, cryptography→49/50, fastapi→версия со starlette≥0.47.2, lupa→патч. Для каждого — changelog-ревью breaking changes (PyJWT 2.10→2.15: API совместим; cryptography 44→49: убрать использование deprecated AEAD-API, проверить client/crypto.py).
- Добавить CI-step `pip-audit -r server/requirements.txt --strict` (на время миграции — non-blocking warning, после обновления — blocking).
- `.github/dependabot.yml`: экосистема pip, weekly, отдельный PR на пакет.
- Запинить `client/requirements.txt` (перевести `>=` на `==`).

**B2. WebSocket-аутентификация без токена в URL**
- Передача access-токена через subprotocol (`Sec-WebSocket-Protocol: bearer.<token>`) или первый auth-фрейм с таймаутом 10 c; close 4401 при невалидном. Сервер: читать `websocket.subprotocols` / принимать `{"type":"auth","token":...}`. Клиент (`api_client.py` ws-часть) — синхронно.
- Acceptance: существующий `test_ws_endpoint_auth_rejects_bad_token` переписан под новый транспорт; токен не появляется в access-логах (проверка логов uvicorn в тесте).

**B3. Security headers — покрыть тестом**
- Текущий middleware из прошлой итерации не имеет ни одного теста. Добавить интеграционный тест: GET /api/health → присутствуют X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy; HSTS только при `MENO_HSTS_ENABLED=1`.

**B4. Rate-limit на /api/register и 2FA-эндпоинты** — сверить, что RL-ключ учитывает ip+username (уже `auth_key`), добавить лимит на `/me/totp/setup` (брутфорс секрета) — 5/мин.

**B5. Аудит bcrypt-prehash**: зафиксировать в тестах, что SHA-256+bcrypt схема верифицирует пароли >72 байт и что старые хеши (если были чистые bcrypt) мигрируют (флаг схемы хеша в строке или re-hash on login).

### Блок C. 🟠 P1 — тесты качества ядра

**C1. Тесты на `client/crypto.py` (0% → ≥85%)**: roundtrip encrypt/decrypt, tamper-детект (Poly1305 fail), пустой/битый key, формат envelope, устойчивость векторов (фиксированные nonce-векторы).
**C2. Тесты janitor.py и services/typing.py** (0%): TTL-чистка expired messages, edge cases часовых поясов (naive datetime — уже известная тема в auth),Typing stop-события.
**C3. WS-manager**: fan-out при disconnect гонки (connect/disconnect параллельно), backpressure.
**C4. Целевое покрытие**: server ≥70%, gate в CI (`--cov-fail-under=70` для server; client crypto ≥80%).
**C5. Удалить осиротевшие `test_db.py`, `test_db_mock.py` из корня и мёртвый `server/tokens.py`** (проверено grep: никто не импортирует).

### Блок D. 🟠 P1 — производительность/оптимизация

**D1. Синхронный bcrypt в async-контексте** — вынесено в `asyncio.to_thread` в login (сделано); применить так же в register/change-password/TOTP-путях (grep `verify(` / `hash(` в routes_*).
**D2. N+1 в history/messages endpoints**: routes_messages 29% покрытие — при добавлении тестов проверить join-запросы (users в списке сообщений одним `selectinload`, а не per-row).
**D3. Индекс под cursor pagination** — убедиться, что `(chat_id, id desc)` индексирован (миграция d5e6… частично; проверить EXPLAIN QUERY PLAN в тесте).
**D4. `/metrics` (prometheus-fastapi-instrumentator)** — latency по маршрутам, WS-подключения, RL-хиты; docker-compose + RUNBOOK обновить.
**D5. cache.py (33%)**: после тестов решить — living code или удалить fakeredis-only ветки.

### Блок E. 🟡 P2 — структура и DX

**E1. Разбить `client/chat_ui.py` (1114 строк)** на `ui/message_list.py`, `ui/input_bar.py`, `ui/typing.py`, `ui/attachments.py` — публичный API класса сохранить.
**E2. mypy в CI** (строгий режим для `server/auth.py`, `config.py`, `crypto*`; permissive baseline для остального).
**E3. Финализировать git-гигиену**: коммит текущих staged-удалений (pulled-back stash), `git rm --cached meno.db* *.log __pycache__ client/_check*.py`, добавить pre-commit hook (ruff-format + ruff-check + запрет commit .db/.log по扩展名).
**E4. pytest.ini**: убрать шум — добавить `norecursedirs = server/tests_old` или унифицировать layout: вся тестовая инфраструктура в `tests/` (unit/, integration/), `server/tests/` удалить после A2.
**E5. README/SECURITY.md**: раздел «Как запустить тесты локально» (MENO_DEV_ENV=1, alembic, pytest) — сейчас это знание скрыто в conftest.

### Порядок выполнения (спринт-план)
| # | Задача | Блок | Оценка | Definition of Done |
|---|---|---|---|---|
| 1 | ruff format + F401/E402 + fix двух F821 | A4,A5 | 0.5 д | CI lint зелёный |
| 2 | lockout-тест + включить core-тесты | A1,A2 | 0.5 д | 33+ passed |
| 3 | Alembic дубль + heads-guard в CI | A3 | 0.5 д | один head, matrix green |
| 4 | Upgrade зависимостей + dependabot + pip-audit gate | B1 | 1 д | 0 known vulns |
| 5 | WS auth transport | B2 | 1 д | токен не в URL |
| 6 | Тесты headers/2FA-limit/prehash | B3-B5 | 0.5 д | — |
| 7 | Crypto/janitor/typing tests + cov gate | C1-C4 | 2 д | server ≥70% |
| 8 | to_thread везде, индексы, /metrics | D | 1.5 д | benchmark before/after |
| 9 | chat_ui refactor + mypy + pre-commit | E | 2 д | — |

**Гораздо важнее новых фич:** прямо сейчас CI красится на трёх независимых фронтах (format, lockout-тест, core-тесты не собираются), а 63 CVE лежат в проде-зависимостях. Пункты 1–4 — обязательны до следующего релиза.
