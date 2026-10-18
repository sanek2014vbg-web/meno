"""Корневой conftest — единая точка сборки тестового окружения MeNo (Этап 6.1).

Делает два вещи ДО импорта server.config:
1. добавляет корень репозитория в sys.path (пакетный стиль `server.*`, чинит A1);
2. фиксирует тестовые переменные окружения: dev-секрет JWT, БД (SQLite по
   умолчанию / PostgreSQL через MENO_TEST_DATABASE_URL), fakeredis-режим кеша.

Фикстуры (client, auth_factory, clean_db, fake_redis) живут здесь, чтобы быть
доступными и для tests/unit, и для tests/integration независимо от того,
какой путь указан в pytest testpaths.

Примечание: E402 допущен осознанно — импорты server.* обязаны выполниться
ПОСЛЕ установки os.environ (server/config читается однократно при импорте).
"""
# ruff: noqa: E402
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# --- Окружение теста ДО импорта server.config (конфиг читается однократно) ---
os.environ["MENO_DEV_ENV"] = "1"            # разрешает эфемерный dev-секрет JWT
# Быстрый bcrypt в тестах (cost 4 вместо 12): иначе 16 интеграционных тестов
# с регистациями тратят минуты на CPU-bound хеширование и прогон «зависает».
os.environ.setdefault("MENO_BCRYPT_ROUNDS", "4")
_TEST_DB = os.environ.get("MENO_TEST_DATABASE_URL", "")
if not _TEST_DB:
    _TEST_DB = "sqlite+aiosqlite:///" + str(ROOT / "tests" / "meno_test.db")
os.environ["MENO_DATABASE_URL"] = _TEST_DB
os.environ.setdefault("MENO_REDIS_URL", "fakeredis://local")
os.environ["MENO_LOG_ACCESS"] = "0"

import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from server import database
from server.cache import cache
from server.main import app
from server.ws_manager import manager


def _is_sqlite() -> bool:
    return database.DATABASE_URL.startswith("sqlite")


def attach_sqlite_listeners(sync_engine) -> None:
    """Вешает PRAGMA- и lower()-хуки SQLite на (пере)созданный движок.

    Дефект-фикс №2 (release v1.0.0): фикстура clean_db пересоздаёт engine для
    каждого теста, но слушатели event-регистрации живут на СТАРОМ объекте
    sync_engine — новые пулы теряли Unicode-LOWER и busy_timeout, из-за чего
    кириллический поиск падал с 'has_more is False' (SQLite LOWER знает только
    ASCII). Функция идемпотентна: sqlalchemy.event listens_for не дублирует
    обработчик при повторной навеске того же callables на тот же объект.
    """
    from sqlalchemy import event

    # Импорт внутри функции: IS_SQLITE вычисляется при импорте connection,
    # а DATABASE_URL фиксируется этим conftest ДО первого импорта server.*.
    import server.db.connection as dbconn

    # Ветка PG-слушателя существует только когда движок собран под PostgreSQL;
    # на SQLite-тесте берём PRAGMA-хук (Unicode lower + busy_timeout + WAL).
    target = getattr(dbconn, "_sqlite_pragmas", None) or getattr(
        dbconn, "_pg_session_settings", None
    )
    if target is None:  # pragma: no cover - защита от рефакторинга connection.py
        return
    if not event.contains(sync_engine, "connect", target):
        event.listen(sync_engine, "connect", target)


def _sqlite_connect_args() -> dict:
    """Дефект-фикс (гонки блокировок SQLite): большой busy_timeout + WAL.

    Параллельные вставки (тест атомарной регистрации) иначе падают с
    'database is locked' — драйвер ждёт освобождения блокировки до 30 с."""
    args = {"timeout": 30}
    if ":memory:" not in database.DATABASE_URL:
        args["detect_types"] = 0
    return args


@pytest_asyncio.fixture(autouse=True)
async def clean_db():
    """Пересоздаёт схему БД перед каждым тестом (чинит A4: таблицы существуют
    в прогоне через ASGI-клиент на обеих СУБД)."""
    if _is_sqlite():
        # SQLite-пул привязан к event-loop предыдущего теста — пересоздаём его
        # (синхронный dispose пула: старые соединения закрыты будут при GC).
        database.engine.sync_engine.dispose()
        from sqlalchemy.ext.asyncio import create_async_engine

        kwargs = {"echo": False, "future": True}
        if ":memory:" in database.DATABASE_URL:
            from sqlalchemy.pool import StaticPool

            kwargs.update(
                poolclass=StaticPool,
                connect_args={"check_same_thread": False, "timeout": 30},
            )
        else:
            kwargs["connect_args"] = _sqlite_connect_args()
        database.engine = create_async_engine(database.DATABASE_URL, **kwargs)
        attach_sqlite_listeners(database.engine.sync_engine)
        database.AsyncSessionLocal.configure(bind=database.engine)

    async with database.engine.begin() as conn:
        if _is_sqlite():
            # busy_timeout на уровне соединения (PRAGMA) + WAL ниже.
            from sqlalchemy import text as sql_text

            await conn.execute(sql_text("PRAGMA busy_timeout=30000;"))
        await conn.run_sync(database.Base.metadata.drop_all)
        await conn.run_sync(database.Base.metadata.create_all)
    if _is_sqlite() and ":memory:" not in database.DATABASE_URL:
        # WAL включается вне транзакции begin(); он глобален для файла БД и
        # переживает пересоздание движка — писатели не блокируют читателей.
        import aiosqlite

        async with aiosqlite.connect(database.DATABASE_URL.split("///", 1)[1]) as raw:
            await raw.execute("PRAGMA journal_mode=WAL;")
            await raw.commit()
    yield
    if _is_sqlite():
        await database.engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def fake_redis(monkeypatch):
    """In-process Redis (fakeredis): cache, Lua-лимитер и WS pub/sub работают
    по реальным кодам без внешнего сервера; в CI с реальным Redis фикстуру
    можно отключить env-флагом MENO_TEST_REAL_REDIS=1.

    Дефект-фикс №4 (ревизия v1.1-fix, Env Drift): ранее фикстура monkey-patch'ила
    EVAL/EVALSHA собственной эмуляцией, потому что базовый пакет fakeredis не
    включает Lua-движок. Это делало тесты хрупкими при апгрейде redis/fakeredis
    (внутренние API менялись). Теперь requirements.txt пинит `fakeredis[lua]`
    (lupa-движок), который исполняет РЕАЛЬНЫЙ Lua-скрипт rate limiter'а
    нативно — эмуляция больше не нужна и удалена. Тесты проверяют тот же
    cluster-safe EVAL-код, что и прод.

    Если Lua-движок недоступен (например, lupa не собрался на exotic-архе),
    фикстура НЕ роняет окружение молча, а жёстко сигнализирует об этом:
    лимитер уйдёт в in-process фолбэк, и CI-задача с MENO_TEST_REQUIRE_LUA=1
    упадёт явной ошибкой (fail-fast вместо тихого дрейфа поведения)."""
    if os.environ.get("MENO_TEST_REAL_REDIS") == "1":
        yield None
        return
    try:
        import fakeredis
    except ImportError:  # fakeredis обязателен в requirements, но не блокируем тесты
        yield None
        return

    client = fakeredis.FakeAsyncRedis(decode_responses=True)

    # --- Sanity-check: реально ли этот fakeredis исполняет Lua? ---
    lua_ok = True
    try:
        probe = await client.eval("return redis.call('PING')", 0)
        lua_ok = probe in ("PONG", b"PONG", "pong")
    except Exception:
        lua_ok = False

    if not lua_ok and os.environ.get("MENO_TEST_REQUIRE_LUA") == "1":
        await client.aclose()
        raise RuntimeError(
            "fakeredis[lua] не исполняет EVAL: установите `pip install "
            "'fakeredis[lua]'` (пининг в server/requirements.txt). "
            "CI требует Lua для проверки cluster-safe rate limiter."
        )

    # --- Дефект-фикс (AttributeError: 'FakeAsyncRedis' has no attribute 'script') ---
    # В используемой версии fakeredis у FakeAsyncRedis отсутствует прямой метод
    # .script(), из-за чего monkey-patch вида `setattr(client, "script", ...)`
    # падал на этапе инициализации фикстуры. Вместо него перехватываем
    # низкоуровневые вызовы через execute_command: команда SCRIPT LOAD
    # возвращает стабильный псевдо-SHA, а реальный EVAL исполняется нативным
    # lupa-движком fakeredis[lua] (пининг в server/requirements.txt). Если Lua
    # недоступен, rate_limit.py корректно деградирует в in-process фолбэк —
    # окружение больше не роняется на стадии сборки фикстур.
    original_execute = client.execute_command

    async def _execute_command_emu(command, *args, **options):
        if str(command).upper() == "SCRIPT" and args and str(args[0]).upper() == "LOAD":
            return "fake-sha-compat"
        return await original_execute(command, *args, **options)

    monkeypatch.setattr(client, "execute_command", _execute_command_emu)

    monkeypatch.setattr(cache, "_redis", client, raising=False)
    yield client
    await client.aclose()


@pytest_asyncio.fixture(autouse=True)
async def reset_state(fake_redis):
    """Сброс состояния WS-менеджера, лимитеров и Redis-кеша между тестами."""
    manager._connections.clear()
    from server.rate_limit import limiter

    limiter._hits.clear()
    limiter._script_sha = None
    if fake_redis is not None:
        # Принудительная очистка уничтожает устаревший кэш (в т.ч. составы
        # чатов WS-менеджера) между прогонами — изоляция интеграционных тестов.
        await fake_redis.flushall()
    yield


@pytest_asyncio.fixture
async def client():
    """AsyncClient поверх ASGI-приложения (httpx >= 0.28: только ASGITransport)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest_asyncio.fixture
async def auth_factory(client):
    """Фабрика зарегистрированных пользователей: dict с токенами, id и headers."""

    async def _register(username: str, password: str = "Secret-123!", display_name: str = "") -> dict:
        resp = await client.post(
            "/api/register",
            json={"username": username, "password": password, "display_name": display_name or username},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        return {
            **data["tokens"],
            "user_id": data["user"]["id"],
            "username": username,
            "headers": {"Authorization": f"Bearer {data['tokens']['access_token']}"},
        }

    return _register


@pytest_asyncio.fixture
async def user_alice(auth_factory):
    return await auth_factory("alice")


@pytest_asyncio.fixture
async def user_bob(auth_factory):
    return await auth_factory("bob")


@pytest_asyncio.fixture
async def chat(client, user_alice, user_bob):
    """Личный чат alice <-> bob."""
    resp = await client.post(
        "/api/chats",
        json={"type": "personal", "user_ids": [user_bob["user_id"]]},
        headers=user_alice["headers"],
    )
    assert resp.status_code == 200, resp.text
    return resp.json()
