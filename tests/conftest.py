"""MeNo — эталонный асинхронный pytest-конфиг (Этап 6.1–6.2 ТЗ).

Стратегия:
- БД: PostgreSQL через env MENO_TEST_DATABASE_URL (используется в CI с
  service-контейнером) либо временный SQLite-файл (aiosqlite) локально;
- таблицы пересоздаются перед КАЖДЫМ тестом (гарантированная изоляция);
- Redis подменяется in-process fakeredis.FakeAsyncRedis — проверяются
  реальные коды cache/rate-limit/pubsub, но без внешнего сервера;
- все импорты — пакетный стиль `server.*` (чинит A1/A4).
"""
import os
from pathlib import Path

# --- Окружение теста ДО импорта server.config (импорт конфигурации однократный) ---
os.environ["MENO_DEV_ENV"] = "1"          # разрешает эфемерный dev-секрет JWT в тестах
_TEST_DB = os.environ.get("MENO_TEST_DATABASE_URL", "")
if not _TEST_DB:
    _TEST_DB = "sqlite+aiosqlite:///" + str(Path(__file__).resolve().parent / "meno_test.db")
os.environ["MENO_DATABASE_URL"] = _TEST_DB
os.environ.setdefault("MENO_REDIS_URL", "fakeredis://local")  # флаг для monkey-patch ниже
os.environ["MENO_LOG_ACCESS"] = "0"      # не шумим access-логами в тестах

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from server import database
from server.cache import cache
from server.main import app
from server.ws_manager import manager


def _is_sqlite() -> bool:
    return database.DATABASE_URL.startswith("sqlite")


@pytest_asyncio.fixture(autouse=True)
async def clean_db():
    """Пересоздаёт схему БД перед каждым тестом (A4: таблицы существуют в TestClient-прогоне)."""
    async with database.engine.begin() as conn:
        await conn.run_sync(database.Base.metadata.drop_all)
        await conn.run_sync(database.Base.metadata.create_all)
    yield
    if _is_sqlite():
        await database.engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def fake_redis(monkeypatch):
    """Подключает fakeredis к синглтону cache: кеширование, Lua-лимитер и WS pub/sub
    работают по реальным кодам, но без внешнего Redis."""
    try:
        import fakeredis.aioredis as fiaredis
    except ImportError:
        yield None
        return
    client = fiaredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(cache, "_redis", client, raising=False)
    yield client
    await client.aclose()


@pytest_asyncio.fixture(autouse=True)
async def reset_state():
    """Сброс состояния WS-менеджера и лимитеров между тестами."""
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
    """Фабрика зарегистрированных пользователей: возвращает dict с токенами и id.

    usage: alice = await auth_factory("alice")
           headers = {"Authorization": f"Bearer {alice['access_token']}"}
    """

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
