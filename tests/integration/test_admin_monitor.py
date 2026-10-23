"""Тесты SuperAdmin-роутов и WS-тапа (MeNo Admin Center & Monitor, сервер).

Покрытие: scoped-токены (issue/verify/изоляция от user-JWT), RBAC REST-эндпоинтов,
оптимистичная блокировка kill-sessions/role-change, ring-buffer тапа и
WebSocket /api/admin/ws/tap (Starlette TestClient — транспорт не зависит от
наличия Redis; фикстура clean_db даёт чистую схему на каждый тест).

Изоляция in-process состояния: admin_tap — синглтон модуля, его ring-buffer и
счётчики переживают перезапуск схемы; фикстура tap_reset обнуляет их перед
каждым тестом, чтобы assertions были детерминированными.
"""

from __future__ import annotations

import asyncio
import threading
import uuid

import pytest
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from server import auth as auth_mod
from server import database
from server.admin_tap import admin_tap, issue_tap_token, verify_tap_token
from server.main import app

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def tap_reset():
    admin_tap._ring.clear()
    admin_tap._seq = 0
    admin_tap._events_total = 0
    yield


# --------------------------- unit: scoped tokens --------------------------- #


def test_tap_token_roundtrip_and_scope():
    token = issue_tap_token(7, "boss")
    claims = verify_tap_token(token)
    assert claims is not None and claims["user_id"] == 7
    assert claims["scope"] == "admin_tap"


def test_tap_token_rejects_garbage():
    assert verify_tap_token("not-a-jwt") is None
    assert verify_tap_token("") is None


async def test_tap_token_rejects_plain_user_jwt():
    """Обычный access-токен НЕ принимается тапом даже с корректной подписью."""
    plain = auth_mod.create_access_token(1)
    assert verify_tap_token(plain) is None


# ------------------------------ helpers ------------------------------------ #


async def _promote(client, owner_headers, user_id):
    resp = await client.put(
        f"/api/admin/users/{user_id}/role",
        json={"role": "admin"},
        headers=owner_headers,
    )
    assert resp.status_code == 200, resp.text


@pytest.fixture
async def admin_ctx(client, auth_factory):
    """Владелец (ADMIN_USERNAME при регистрации) + второй админ для запросов."""
    owner = await auth_factory("owner")
    admin = await auth_factory("tapadmin")
    await _promote(client, owner["headers"], admin["user_id"])
    return {"owner": owner, "admin": admin}


# ------------------------------ REST surface ------------------------------- #


async def test_tap_token_endpoint_requires_admin(client, user_alice):
    resp = await client.post("/api/admin/tap-token", headers=user_alice["headers"])
    assert resp.status_code == 403


async def test_tap_token_endpoint_issues_for_admin(client, admin_ctx):
    resp = await client.post(
        "/api/admin/tap-token", headers=admin_ctx["admin"]["headers"]
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token"] and body["expires_in"] == 1800
    # v2.0: контур комплаенса добавляет скоуп "compliance" — сверяем со
    # служебным множеством ALL_SCOPES, чтобы тест не устаревал при росте скоупов.
    from server.routes_admin import ALL_SCOPES

    assert set(body["scopes"]) == set(ALL_SCOPES)


async def test_admin_users_lists_with_online_flag(client, admin_ctx, user_alice):
    resp = await client.get("/api/admin/users", headers=admin_ctx["admin"]["headers"])
    assert resp.status_code == 200
    rows = resp.json()
    names = {r["username"] for r in rows}
    assert {"alice", "owner", "tapadmin"} <= names
    assert all("online" in r for r in rows)


async def test_recent_messages_cursor(client, admin_ctx, chat, user_alice):
    admin_h = admin_ctx["admin"]["headers"]
    resp = await client.post(
        f"/api/chats/{chat['id']}/messages",
        json={"type": "text", "content": "hello tap"},
        headers=user_alice["headers"],
    )
    assert resp.status_code == 200, resp.text

    resp = await client.get(
        "/api/admin/messages/recent", params={"limit": 10}, headers=admin_h
    )
    assert resp.status_code == 200
    msgs = resp.json()
    assert msgs[0]["content"] == "hello tap"
    first_id = msgs[0]["id"]

    resp = await client.get(
        "/api/admin/messages/recent",
        params={"before_id": first_id, "limit": 10},
        headers=admin_h,
    )
    assert resp.status_code == 200
    assert all(m["id"] < first_id for m in resp.json())


async def test_sessions_list_and_kill(client, admin_ctx, user_bob):
    admin_h = admin_ctx["admin"]["headers"]
    resp = await client.get(
        "/api/admin/sessions",
        params={"user_id": user_bob["user_id"]},
        headers=admin_h,
    )
    assert resp.status_code == 200
    sessions = resp.json()
    assert len(sessions) >= 1
    assert all(not s["revoked"] for s in sessions)

    resp = await client.post(
        "/api/admin/sessions/kill",
        json={"user_id": user_bob["user_id"], "reason": "test_kill"},
        headers=admin_h,
    )
    assert resp.status_code == 200
    assert resp.json()["revoked"] >= 1

    # идемпотентность оптимистичного отзыва: повторный kill ничего не берёт
    resp = await client.post(
        "/api/admin/sessions/kill",
        json={"user_id": user_bob["user_id"]},
        headers=admin_h,
    )
    assert resp.status_code == 200 and resp.json()["revoked"] == 0

    resp = await client.get(
        "/api/admin/sessions",
        params={"user_id": user_bob["user_id"]},
        headers=admin_h,
    )
    assert resp.json() == []


async def test_role_change_cas_and_self_guard(client, admin_ctx, auth_factory):
    admin_h = admin_ctx["admin"]["headers"]
    victim = await auth_factory("victim")
    resp = await client.put(
        f"/api/admin/users/{victim['user_id']}/role",
        json={"role": "admin"},
        headers=admin_h,
    )
    assert resp.status_code == 200 and resp.json()["role"] == "admin"

    me = (await client.get("/api/me", headers=admin_h)).json()
    resp = await client.put(
        f"/api/admin/users/{me['id']}/role",
        json={"role": "user"},
        headers=admin_h,
    )
    assert resp.status_code == 400

    resp = await client.put(
        f"/api/admin/users/{victim['user_id']}/role",
        json={"role": "superuser"},
        headers=admin_h,
    )
    assert resp.status_code == 422


async def test_janitor_jobs_endpoint(client, admin_ctx):
    async with database.get_db() as db:
        from server.services.ttl_registry import ensure_registered

        await ensure_registered(db)
        await db.commit()
    resp = await client.get(
        "/api/admin/janitor/jobs", headers=admin_ctx["admin"]["headers"]
    )
    assert resp.status_code == 200
    jobs = {j["job"] for j in resp.json()}
    assert {"messages_ttl", "refresh_tokens"} <= jobs


async def test_tap_stats_and_events(client, admin_ctx):
    admin_h = admin_ctx["admin"]["headers"]
    await admin_tap.emit({"scope": "messages", "kind": "unit_probe"})
    resp = await client.get("/api/admin/tap/stats", headers=admin_h)
    assert resp.status_code == 200
    assert resp.json()["events_total"] >= 1

    resp = await client.get(
        "/api/admin/tap/events", params={"limit": 50}, headers=admin_h
    )
    events = resp.json()["events"]
    assert any(e["event"]["kind"] == "unit_probe" for e in events)
    seqs = [e["seq"] for e in events]
    assert seqs == sorted(seqs)


# ------------------------------ WS /tap (ticket-flow) ----------------------- #
#
# Hardening v2: SuperAdmin-сокет принимается ТОЛЬКО по одноразовому билету.
# Контракт теста повторяет реальный клиент (admin_monitor/network.py):
#   1) POST /api/admin/ws-ticket (admin-JWT) -> {ticket, expires_in: 5};
#   2) websocket_connect(subprotocols=["meno-tap.<ticket>"]) — секрет идёт в
#      заголовке handshake, а НЕ в query (не светится в access-логах прокси);
#   3) сервер гасит билет GETDEL-ом за O(1) до accept().
# Для TestClient закрытие до accept выражается WebSocketDisconnect на __enter__.


async def _fetch_ticket(client, headers) -> str:
    """POST /api/admin/ws-ticket -> строка билета (свежий на каждый connect)."""
    resp = await client.post("/api/admin/ws-ticket", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["expires_in"] == 5 and body["ws_path"] == "/api/admin/ws/tap"
    ticket = body["ticket"]
    assert len(ticket) == 32  # uuid4().hex
    return ticket


def _tap_connect(tc, ticket: str):
    """Handshake тапа через subprotocol meno-tap.<ticket> (без токена в URL)."""
    return tc.websocket_connect(
        "/api/admin/ws/tap", subprotocols=[f"meno-tap.{ticket}"]
    )


def test_ws_tap_rejects_without_ticket():
    from starlette.websockets import WebSocketDisconnect

    with TestClient(app) as tc:
        with pytest.raises(WebSocketDisconnect):
            with _tap_connect(tc, "") as ws:
                ws.receive_json()


def test_ws_tap_rejects_random_uuid(admin_ctx):
    """Случайный UUID (не выданный эндпоинтом) -> reject 4403 без accept.

    Единый код/причина закрытия для неверного, просроченного и использованного
    билета — отсутствие oracle'а перебора (anti-enumeration).
    """
    from starlette.websockets import WebSocketDisconnect

    with TestClient(app) as tc:
        with pytest.raises(WebSocketDisconnect) as excinfo:
            with _tap_connect(tc, uuid.uuid4().hex) as ws:
                ws.receive_json()
    assert excinfo.value.code == 4403


def test_ws_tap_rejects_ticket_reuse(admin_ctx):
    """One-time семантика: второй handshake с тем же билетом -> 4403.

    Первый коннект гасит билет (GETDEL), поэтому повторное использование
    перехваченного секрета невозможно даже в пределах TTL 5 секунд.
    """
    from starlette.websockets import WebSocketDisconnect

    async def _get_ticket() -> str:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://t"
        ) as ac:
            return await _fetch_ticket(ac, admin_ctx["admin"]["headers"])

    ticket = asyncio.run(_get_ticket())

    with TestClient(app) as tc:
        with _tap_connect(tc, ticket) as ws:
            assert ws.receive_json()["type"] == "tap_hello"
        # тот же билет повторно — уже погашен первым consume
        with pytest.raises(WebSocketDisconnect) as excinfo:
            with _tap_connect(tc, ticket) as ws:
                ws.receive_json()
    assert excinfo.value.code == 4403


def test_ws_tap_rejects_plain_access_token(user_alice):
    """Legacy query-параметр ?token= более не принимается (флаг миграции
    MENO_ADMIN_TAP_LEGACY_TOKEN по умолчанию выключен)."""
    from starlette.websockets import WebSocketDisconnect

    with TestClient(app) as tc:
        with pytest.raises(WebSocketDisconnect):
            with tc.websocket_connect(
                f"/api/admin/ws/tap?token={user_alice['access_token']}"
            ) as ws:
                ws.receive_json()


def test_ws_tap_hello_backfill_live_and_commands(admin_ctx):
    """Полный цикл по БИЛЕТУ: hello -> backfill буфера -> ping/scopes.

    События бэкфилла пишутся напрямую в ring через admin_tap.record(): тот же
    буфер, из которого сервер отдаёт backfill после hello; это исключает
    зависимость от фоновых задач доставки (TestClient их не исполняет).
    """
    from server.routes_admin import ALL_SCOPES

    async def _get_ticket() -> str:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://t"
        ) as ac:
            return await _fetch_ticket(ac, admin_ctx["admin"]["headers"])

    ticket = asyncio.run(_get_ticket())

    # событие ДО подключения — обязано прийти в backfill после hello
    env_pre = admin_tap.record({"scope": "janitor", "kind": "preconnect_probe"})

    with TestClient(app) as tc:
        with _tap_connect(tc, ticket) as ws:
            hello = ws.receive_json()
            assert hello["type"] == "tap_hello"
            assert set(hello["scopes"]) == set(ALL_SCOPES)

            backfilled = ws.receive_json()
            assert backfilled["type"] == "backfill"
            # Ring-буфер глобален и переживает соединения/тесты: в него могли
            # попасть события предыдущих тестов. Проверяем контракт «догон»:
            # probe присутствует в бэкфилле, а страницы упорядочены по seq.
            seqs = [e["seq"] for e in backfilled["events"]]
            assert env_pre["seq"] in seqs
            assert seqs == sorted(seqs)

            # протокольные команды живого сокета
            ws.send_json(
                {"type": "backfill", "since_seq": 0, "limit": 5}
            )  # легальный протокольный запрос
            ans = ws.receive_json()
            assert ans["type"] == "backfill"

            ws.send_json({"type": "ping"})
            assert ws.receive_json()["type"] == "pong"

            ws.send_json({"type": "set_scopes", "scopes": ["janitor"]})
            ack = ws.receive_json()
            assert ack["type"] == "scopes_ack" and ack["scopes"] == ["janitor"]


def test_ws_tap_streams_live_message_event(admin_ctx, chat, user_alice):
    """Событие new_message долетает до тапа в реальном времени.

    Эмулируется ровно тот путь, который выполняет POST /api/chats/{id}/messages
    после коммита (message_send.deliver -> broadcast_tap -> admin_tap.subscribe
    websocket). Вызов идёт ВТОРЫМ потоком (outside portal-цикла TestClient):
    record() планируются call_soon_threadsafe на loop сервера, живой tap-поток
    их исполняет и доставляет сообщение в сокет — так обходится ограничение
    Starlette TestClient, не исполняющего фоновые задачи основного loop.
    """
    from server.routes_admin import broadcast_tap

    async def _get_ticket() -> str:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://t"
        ) as ac:
            return await _fetch_ticket(ac, admin_ctx["admin"]["headers"])

    ticket = asyncio.run(_get_ticket())

    event_payload = {
        "scope": "messages",
        "kind": "new_message",
        "chat_id": chat["id"],
        "sender_id": user_alice["user_id"],
        "message_id": 999001,
        "msg_type": "text",
        "content_preview": "live tap msg",
        "member_count": 2,
    }
    errors: list[BaseException] = []

    def _pump() -> None:
        try:
            asyncio.run(broadcast_tap(event_payload))
        except BaseException as exc:  # пробрасываем в основной поток
            errors.append(exc)

    with TestClient(app) as tc:
        with _tap_connect(tc, ticket) as ws:
            hello = ws.receive_json()
            assert hello["type"] == "tap_hello"
            if hello.get("buffered"):
                ws.receive_json()  # backfill-пакет пропускаем
            thread = threading.Thread(target=_pump, daemon=True)
            thread.start()
            env = ws.receive_json()
            thread.join(timeout=5.0)
    assert not errors, errors[0]
    assert env["type"] == "tap_event"
    assert env["event"]["kind"] == "new_message"
    assert env["event"]["chat_id"] == chat["id"]
