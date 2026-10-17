"""Корневой conftest — единая точка сборки тестового окружения MeNo (Этап 6.1).

Делает два вещи ДО импорта server.config:
1. добавляет корень репозитория в sys.path (пакетный стиль `server.*`, чинит A1);
2. фиксирует тестовые переменные окружения: dev-секрет JWT, БД (SQLite по
   умолчанию / PostgreSQL через MENO_TEST_DATABASE_URL), fakeredis-режим кеша.

Фикстуры (client, auth_factory, clean_db, fake_redis) живут здесь, чтобы быть
доступными и для tests/, и для server/tests/ независимо от того, какой путь
указан в pytest testpaths.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# --- Окружение теста ДО импорта server.config (конфиг читается однократно) ---
os.environ["MENO_DEV_ENV"] = "1"            # разрешает эфемерный dev-секрет JWT
_TEST_DB = os.environ.get("MENO_TEST_DATABASE_URL", "")
if not _TEST_DB:
    _TEST_DB = "sqlite+aiosqlite:///" + str(ROOT / "tests" / "meno_test.db")
os.environ["MENO_DATABASE_URL"] = _TEST_DB
os.environ.setdefault("MENO_REDIS_URL", "fakeredis://local")
os.environ["MENO_LOG_ACCESS"] = "0"

import asyncio

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from server import database
from server.cache import cache
from server.main import app
from server.ws_manager import manager


def _is_sqlite() -> bool:
    return database.DATABASE_URL.startswith("sqlite")


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

    Дефект-фикс №4: fakeredis не исполняет Lua-скрипты без lxml/lua-движка,
    поэтому на лету подменяем exec-type команды (EVAL/EVALSHA/SCRIPT) их
    эквивалентами на стандартных командах Redis — лимитер использует реальный
    cluster-safe код, а не фолбэк."""
    if os.environ.get("MENO_TEST_REAL_REDIS") == "1":
        yield None
        return
    try:
        import fakeredis
        from redis.exceptions import ResponseError
    except ImportError:  # fakeredis обязателен в requirements, но не блокируем тесты
        yield None
        return

    _FAKE_SHA = "fake-sha-compat"
    client = fakeredis.FakeAsyncRedis(decode_responses=True)

    # --- Эмуляция Lua-скрипта rate limiter'а (_LUA_ALLOW) на нативных командах
    # Redis: скользящее окно через sorted set (ZREMRANGEBYSCORE/ZCARD/ZADD/
    # PEXPIRE). Семантика идентична EVAL-скрипту, лимитер идёт по cluster-safe
    # ветке кода, а не по in-process фолбэку. ---
    async def _eval_emu(script_or_sha, numkeys, *args):
        key = str(args[0])
        now, window_ms, limit, member = (
            float(args[1]), int(float(args[2])), int(float(args[3])), str(args[4]),
        )

        # В реальном Redis EVALSHA падает с NOSCRIPT, если скрипт не закеширован;
        # эмулируем это поведение, чтобы проверять и путь script_load/EVALSHA.
        if getattr(_eval_emu, "strict_noscript", False) and script_or_sha != _FAKE_SHA:
            raise ResponseError("NOSCRIPT Lua execution disabled in fakeredis")
        entries = await client.zrange(key, 0, -1, withscores=True)
        cutoff = now - window_ms / 1000.0
        for m, s in entries:
            if float(s) <= cutoff:
                await client.zrem(key, m)
        if await client.zcard(key) >= limit:
            return 0
        await client.zadd(key, {member: now})
        await client.pexpire(key, window_ms)
        return 1

    async def _script_emu(*args):
        # SCRIPT LOAD <body> -> sha; прочие подкоманды (EXISTS/FLUSH) — ok.
        if args and str(args[0]).upper() == "LOAD":
            return _FAKE_SHA
        return True

    monkeypatch.setattr(client, "eval", _eval_emu, raising=True)
    monkeypatch.setattr(client, "evalsha", _eval_emu, raising=True)
    monkeypatch.setattr(client, "script", _script_emu, raising=True)

    monkeypatch.setattr(cache, "_redis", client, raising=False)
    yield client
    await client.aclose()


@pytest_asyncio.fixture(autouse=True)
async def reset_state():
    """Сброс состояния WS-менеджера и локальных лимитеров между тестами."""
    manager._connections.clear()
    from server.rate_limit import limiter

    limiter._hits.clear()
    limiter._script_sha = None
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
