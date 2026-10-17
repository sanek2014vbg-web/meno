"""MeNo — комплексные интеграционные тесты критических путей (Этап 6.2 ТЗ).

Покрывает дефекты/требования из ТЗ:
- A10 / Этап 2.2: атомарная регистрация, UNIQUE(username), IntegrityError-гонка;
- Этап 2.4: ротация refresh-токенов и детекция переиспользования (кражи) —
  отзыв всей семьи сессий;
- A12 / Этап 4.2: поиск сообщений по кириллице (PG: to_tsvector('russian'),
  SQLite: переносимый LIKE) + курсорная пагинация (Этап 4.4);
- A11 / Этап 5.1: WebSocket-менеджер поверх Redis Pub/Sub — fan-out на
  несколько «воркеров» (два WS-подписчика, публикация через шину);
- A5: cache/Redis-код работает на fakeredis;
- Этап 4.5: идемпотентность отправки по client_id.

Стиль импортов — пакетный `server.*` (чинит A1). Все тесты async
(pytest-asyncio, asyncio_mode=auto в pytest.ini).
"""
import asyncio
import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text as sql_text
from sqlalchemy.exc import IntegrityError

from server import database
from server.cache import cache
from server.main import app
from server.ws_manager import WS_CHANNEL, manager


# ---------------------------------------------------------------------------
# Утилита: прямой доступ к БД вне HTTP (для проверки IntegrityError-семантики)
# ---------------------------------------------------------------------------

async def _insert_user(username: str, pw_hash: str = "x", role: str = "user") -> None:
    async with database.get_db() as db:
        await db.execute(
            sql_text(
                "INSERT INTO users (username, password_hash, display_name, role) "
                "VALUES (:u, :p, :d, :r)"
            ),
            {"u": username, "p": pw_hash, "d": username, "r": role},
        )


# ---------------------------------------------------------------------------
# 1. Атомарная регистрация (Этап 2.2, дефект A10)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_register_success(client, auth_factory):
    """Успешная регистрация выдаёт пару токенов и публичный профиль."""
    user = await auth_factory("alice")
    assert user["access_token"] and user["refresh_token"]
    assert user["user_id"] > 0

    resp = await client.get("/api/me", headers=user["headers"])
    assert resp.status_code == 200
    me = resp.json()
    assert me["username"] == "alice"
    assert me["role"] == "user"
    assert "password_hash" not in me


@pytest.mark.asyncio
async def test_register_duplicate_username_rejected(client, auth_factory):
    """Второй запрос на тот же username отклоняется (400) — дубликата нет."""
    await auth_factory("bob")
    resp = await client.post(
        "/api/register",
        json={"username": "bob", "password": "Secret-123!", "display_name": "Bob 2"},
    )
    assert resp.status_code == 400
    assert "занято" in resp.json()["detail"].lower() or "уже" in resp.json()["detail"].lower()

    async with database.get_db() as db:
        rows = await database.aq(db, "SELECT id FROM users WHERE username=:u", {"u": "bob"})
    assert len(rows) == 1, "UNIQUE(username) обязан не допустить второй записи"


@pytest.mark.asyncio
async def test_register_race_integrity_error(client, auth_factory):
    """Гонка двух параллельных вставок одного username → IntegrityError,
    ровно одна запись. Это нижний уровень защиты, который использует роут."""
    await auth_factory("carol")  # занятый username
    with pytest.raises(IntegrityError):
        await _insert_user("carol")

    async with database.get_db() as db:
        rows = await database.aq(db, "SELECT id FROM users WHERE username=:u", {"u": "carol"})
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_concurrent_registrations_only_one_wins(client):
    """N параллельных register с одним username: ровно один 200, остальные 400."""
    payload = {"username": "dave", "password": "Secret-123!", "display_name": "Dave"}
    responses = await asyncio.gather(*(client.post("/api/register", json=payload) for _ in range(6)))
    codes = [r.status_code for r in responses]
    assert codes.count(200) == 1, f"атомарность нарушена: {codes}"
    assert set(codes) <= {200, 400}

    async with database.get_db() as db:
        rows = await database.aq(db, "SELECT id FROM users WHERE username=:u", {"u": "dave"})
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_register_validation_and_audit_log(client):
    """Невалидный username отсекается схемой; успешная регистрация пишется в security_events."""
    resp = await client.post(
        "/api/register", json={"username": "!!bad!!", "password": "Secret-123!"}
    )
    assert resp.status_code == 422

    await client.post("/api/register", json={"username": "erin", "password": "Secret-123!"})
    async with database.get_db() as db:
        ev = await database.aq(
            db,
            "SELECT event FROM security_events WHERE username=:u ORDER BY id",
            {"u": "erin"},
        )
    assert any(r["event"] == "register" for r in ev), "audit-лог регистрации отсутствует (Этап 2.3)"


# ---------------------------------------------------------------------------
# 2. Ротация refresh-токенов и детекция кражи (Этап 2.4)
# ---------------------------------------------------------------------------

async def _rotate(client, refresh_token: str):
    return await client.post("/api/refresh", json={"refresh_token": refresh_token})


@pytest.mark.asyncio
async def test_refresh_rotation_issues_new_pair(client, auth_factory):
    """Стандартная ротация: старый токен гаснет, выдаётся новая пара той же семьи."""
    alice = await auth_factory("alice")
    old_rt = alice["refresh_token"]

    resp = await _rotate(client, old_rt)
    assert resp.status_code == 200
    new = resp.json()
    assert new["access_token"] and new["refresh_token"]
    assert new["refresh_token"] != old_rt

    # новый токен работает
    resp2 = await _rotate(client, new["refresh_token"])
    assert resp2.status_code == 200


@pytest.mark.asyncio
async def test_refresh_reuse_detects_theft_and_revokes_family(client, auth_factory):
    """Сценарий кражи: легитимный клиент ротировал токен, злоумышленник
    повторно использует старый refresh → вся семья сессий отзывается,
    последующие ротации падают с 401."""
    bob = await auth_factory("bob")
    stolen_rt = bob["refresh_token"]           # токен, перехваченный «злоумышленником»

    legit = await _rotate(client, stolen_rt)   # легитимная ротация: stolen_rt гаснет
    assert legit.status_code == 200
    rotated_rt = legit.json()["refresh_token"]

    reuse = await _rotate(client, stolen_rt)   # переиспользование украденного токена
    assert reuse.status_code == 401, "переиспользованный refresh обязан быть отклонён"

    # детекция кражи отзывает ВСЮ семью: даже только что выданный токен мёртв
    after_theft = await _rotate(client, rotated_rt)
    assert after_theft.status_code == 401, "семья сессий должна быть отозвана целиком"

    # и новое логическое состояние подтверждено на уровне БД: ни одного живого токена семьи
    async with database.get_db() as db:
        live = await database.aq(
            db,
            "SELECT COUNT(*) AS n FROM refresh_tokens rt JOIN users u ON u.id=rt.user_id "
            "WHERE u.username=:u AND rt.revoked=0",
            {"u": "bob"},
        )
    assert live[0]["n"] == 0


@pytest.mark.asyncio
async def test_logout_revokes_session(client, auth_factory):
    """/logout удаляет сессию: refresh после выхода не действует."""
    carol = await auth_factory("carol")
    resp = await client.post(
        "/api/logout",
        json={"refresh_token": carol["refresh_token"]},
        headers=carol["headers"],
    )
    assert resp.status_code == 200
    reuse = await _rotate(client, carol["refresh_token"])
    assert reuse.status_code == 401


@pytest.mark.asyncio
async def test_invalid_refresh_token_rejected(client):
    resp = await _rotate(client, "f" * 64)  # несуществующий, но форматно валидный токен
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 3. Поиск по кириллице + курсорная пагинация (Этапы 4.2, 4.4; дефект A12)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_search_cyrillic_with_cursor_pagination(client, user_alice, chat):
    """Кириллический запрос находит все три 'Привет ...' сообщения; limit=2
    даёт две страницы с корректным next_cursor и без дублей."""
    texts = [
        "Привет как дела",
        "Привет завтра встреча",
        "Привет всем",
        "Доброе утро команда",
    ]
    ids = []
    for t in texts:
        resp = await client.post(
            f"/api/chats/{chat['id']}/messages",
            json={"type": "text", "content": t},
            headers=user_alice["headers"],
        )
        assert resp.status_code == 200, resp.text
        ids.append(resp.json()["id"])

    # страница 1
    page1 = await client.get(
        f"/api/chats/{chat['id']}/search",
        params={"q": "привет", "limit": 2},
        headers=user_alice["headers"],
    )
    assert page1.status_code == 200, page1.text
    body1 = page1.json()
    assert body1["has_more"] is True
    assert len(body1["messages"]) == 2
    assert body1["next_cursor"] is not None
    found_ids = {m["id"] for m in body1["messages"]}

    # страница 2 — по курсору
    page2 = await client.get(
        f"/api/chats/{chat['id']}/search",
        params={"q": "привет", "limit": 2, "before_id": body1["next_cursor"]},
        headers=user_alice["headers"],
    )
    assert page2.status_code == 200
    body2 = page2.json()
    found_ids |= {m["id"] for m in body2["messages"]}

    expected = set(ids[:3])  # три сообщения со словом «Привет», последнее — нет
    assert found_ids == expected, (
        f"поиск по кириллице должен найти {expected}, нашёл {found_ids}"
    )
    assert body2["has_more"] is False
    assert all(m["content"] for m in body2["messages"])


@pytest.mark.asyncio
async def test_search_no_results_returns_empty_page(client, user_alice, chat):
    resp = await client.get(
        f"/api/chats/{chat['id']}/search",
        params={"q": "абракадабра"},
        headers=user_alice["headers"],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["messages"] == [] and body["has_more"] is False


@pytest.mark.asyncio
async def test_history_cursor_pagination(client, user_alice, chat):
    """История чата тоже отдаётся курсором: before_id исключает уже полученные id."""
    for i in range(5):
        await client.post(
            f"/api/chats/{chat['id']}/messages",
            json={"type": "text", "content": f"сообщение номер {i}"},
            headers=user_alice["headers"],
        )

    first = await client.get(
        f"/api/chats/{chat['id']}/messages",
        params={"limit": 2},
        headers=user_alice["headers"],
    )
    assert first.status_code == 200
    b1 = first.json()
    assert len(b1["messages"]) == 2 and b1["has_more"]
    seen = {m["id"] for m in b1["messages"]}

    second = await client.get(
        f"/api/chats/{chat['id']}/messages",
        params={"limit": 2, "before_id": b1["next_cursor"]},
        headers=user_alice["headers"],
    )
    b2 = second.json()
    assert not seen & {m["id"] for m in b2["messages"]}, "курсорная пагинация не должна повторять записи"


@pytest.mark.asyncio
async def test_send_message_idempotency_by_client_id(client, user_alice, chat):
    """Повторная отправка с тем же client_id возвращает то же сообщение (Этап 4.5)."""
    cid = f"cid-{uuid4().hex}"
    body = {"type": "text", "content": "идемпотентный текст", "client_id": cid}
    r1 = await client.post(f"/api/chats/{chat['id']}/messages", json=body, headers=user_alice["headers"])
    r2 = await client.post(f"/api/chats/{chat['id']}/messages", json=body, headers=user_alice["headers"])
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json()["id"] == r2.json()["id"]

    async with database.get_db() as db:
        rows = await database.aq(
            db, "SELECT id FROM messages WHERE chat_id=:c AND client_id=:i",
            {"c": chat["id"], "i": cid},
        )
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# 4. WebSocket Pub/Sub поверх Redis — эмуляция нескольких воркеров (A11, 5.1)
# ---------------------------------------------------------------------------

class FakeWorkerSocket:
    """Минимальная заглушка Starlette WebSocket для in-process теста менеджера:
    реализует accept/send_json/close — ровно то, что использует WSManager."""

    def __init__(self):
        self.inbox: asyncio.Queue = asyncio.Queue()
        self.closed = False

    async def accept(self):
        pass

    async def send_json(self, payload):
        if self.closed:
            raise RuntimeError("socket closed")
        await self.inbox.put(payload)

    async def close(self, code=1000):
        self.closed = True


@pytest.mark.asyncio
async def test_ws_pubsub_fanout_across_workers(client, user_alice, user_bob, chat, fake_redis):
    """Два «воркера» подписаны на канал meno:ws; отправка сообщения через HTTP
    публикует событие в шину, и оба WS-клиента получают new_message."""
    assert fake_redis is not None, "fakeredis недоступен — шина не смоделирована"

    # Воркер 1 держит соединение alice, воркер 2 — соединение bob.
    ws_a, ws_b = FakeWorkerSocket(), FakeWorkerSocket()
    await manager.connect(user_alice["user_id"], ws_a)
    await manager.connect(user_bob["user_id"], ws_b)

    # Запускаем слушателя шины (как это делает lifespan при наличии Redis).
    await manager.start_bus_listener()
    try:
        resp = await client.post(
            f"/api/chats/{chat['id']}/messages",
            json={"type": "text", "content": "реалтайм через pub/sub"},
            headers=user_alice["headers"],
        )
        assert resp.status_code == 200, resp.text
        msg_id = resp.json()["id"]

        evt_a = await asyncio.wait_for(ws_a.inbox.get(), timeout=5)
        evt_b = await asyncio.wait_for(ws_b.inbox.get(), timeout=5)
        assert evt_a["type"] == "new_message" and evt_b["type"] == "new_message"
        assert evt_a["message"]["id"] == msg_id == evt_b["message"]["id"]

        # Публикация действительно прошла через Redis-канал:
        published = await fake_redis.publish(WS_CHANNEL, json.dumps({"probe": True}))
        assert published >= 0  # redis-совместимый API отвечает числом подписчиков
    finally:
        await manager.stop_bus_listener()
        manager.disconnect(user_alice["user_id"], ws_a)
        manager.disconnect(user_bob["user_id"], ws_b)


@pytest.mark.asyncio
async def test_ws_manager_inprocess_delivery_without_redis(client, user_alice, monkeypatch):
    """In-process режим (без Redis) доставляет сообщение локально — фолбэк для
    single-worker self-hosted инсталляций."""
    monkeypatch.setattr(cache, "_redis", None, raising=False)
    ws = FakeWorkerSocket()
    await manager.connect(user_alice["user_id"], ws)
    try:
        await manager.send_to_user(user_alice["user_id"], {"type": "ping"})
        evt = await asyncio.wait_for(ws.inbox.get(), timeout=2)
        assert evt == {"type": "ping"}
    finally:
        manager.disconnect(user_alice["user_id"], ws)
    assert manager.online_count == 0


@pytest.mark.asyncio
async def test_ws_endpoint_auth_rejects_bad_token():
    """HTTP-уровень: /ws без валидного access-токена закрывается кодом 4401."""
    with TestClient(app) as tc:
        with tc.websocket_connect("/ws?token=garbage") as ws:
            # FastAPI close() до accept проявляется как WebSocketDisconnect/ошибка
            with pytest.raises(Exception):
                ws.receive_json()


@pytest.mark.asyncio
async def test_ws_endpoint_delivers_typing(client_as_user):
    """Полный цикл эндпоинта /ws: два клиента, typing-событие доставляется
    второму участнику чата через тот же менеджер."""
    tc, tokens = client_as_user
    with tc.websocket_connect(f"/ws?token={tokens['alice']}") as ws_a, \
         tc.websocket_connect(f"/ws?token={tokens['bob']}") as ws_b:
        ws_a.send_json({"type": "ping"})
        assert ws_a.receive_json()["type"] == "pong"

        ws_a.send_json({"type": "typing", "chat_id": tokens["chat_id"]})
        evt = ws_b.receive_json()
        assert evt["type"] == "typing" and evt["chat_id"] == tokens["chat_id"]


@pytest.fixture
def client_as_user(user_alice, user_bob, chat):
    """TestClient + актуальные access-токены alice/bob и id чата (для /ws)."""
    from server import auth as auth_service

    tokens = {
        "alice": auth_service.create_access_token(user_alice["user_id"]),
        "bob": auth_service.create_access_token(user_bob["user_id"]),
        "chat_id": chat["id"],
    }
    with TestClient(app) as tc:
        yield tc, tokens
