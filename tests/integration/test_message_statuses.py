"""MeNo — интеграционные тесты Этапа 7.3: статусы сообщений.

Покрывает PATCH /api/messages/{id}/status (sent -> delivered -> read):
- Сценарий А (прямой ход): sent -> delivered -> read, ранги CASE корректны,
  timestamps заполняются;
- Сценарий Б (запоздалый delivered из-за лагов сети): статус уже 'read',
  прилетевший 'delivered' => changed=False, отката назад нет;
- Сценарий В (идемпотентность): двойной PATCH 'read' => оба 200 OK,
  второй changed=False;
- Сценарий Г (безопасность): автор сообщения не может менять статус своего
  собственного сообщения => 403; чужой пользователь чата => 403;
- Бонус: Ghost Mode (клиентский флаг ghost=True и серверная настройка
  settings['ghost_read:{uid}']) — read тихо понижается до delivered.

Диалект-безопасно для SQLite (aiosqlite) и PostgreSQL 16: сверка идёт по
строковым значениям enum (native_enum=False => VARCHAR), без диалектных
функций. Стиль — пакетные импорты server.*, фикстуры корня conftest.py
(client, auth_factory, chat = alice <-> bob).
"""
from server import database
from server.db.models_base import MessageStatus, status_rank
from server.routes_messages import _STATUS_RANK_CASE


async def _db_status(message_id: int) -> dict:
    """Прямое чтение состояния строки из БД (вне HTTP-слоя)."""
    async with database.get_db() as db:
        row = await database.aq1(
            db,
            "SELECT status, delivered_at, read_at FROM messages WHERE id=:id",
            {"id": message_id},
        )
    assert row is not None, "сообщение исчезло из БД"
    return row


async def _send(client, sender: dict, chat: dict, content: str) -> int:
    resp = await client.post(
        f"/api/chats/{chat['id']}/messages",
        json={"type": "text", "content": content},
        headers=sender["headers"],
    )
    assert resp.status_code == 200, resp.text
    msg = resp.json()
    # Момент создания — базовый статус sent (нижняя граница шкалы).
    assert msg["status"] == MessageStatus.sent.value
    return msg["id"]


def test_status_rank_scale_is_linear():
    """Числовая шкала рангов sent(0) < delivered(1) < read(2) — источник истины
    для SQL-CASE. Регрессия лексикографического бага: словарный порядок строк
    ('delivered' < 'read' < 'sent') НЕ должен использоваться в WHERE."""
    ranks = {s: status_rank(s) for s in MessageStatus}
    assert ranks == {
        MessageStatus.sent: 0,
        MessageStatus.delivered: 1,
        MessageStatus.read: 2,
    }
    # CASE в роуте обязан маппить те же значения (константа синхронизирована).
    for status, rank in ranks.items():
        assert f"WHEN '{status.value}' THEN {rank}" in _STATUS_RANK_CASE or (
            status is MessageStatus.read and f"ELSE {rank}" in _STATUS_RANK_CASE
        ), f"CASE-маппинг рассинхронизирован со status_rank для {status.value}"


async def test_scenario_a_forward_transition(client, user_alice, user_bob, chat):
    """Сценарий А: sent -> delivered -> read. Получатель (bob) двигает статус
    вперёд по всем трём рангам; timestamps проставляются на своих переходах."""
    mid = await _send(client, user_alice, chat, "Привет, это этап 7.3")

    # sent(0) -> delivered(1)
    r1 = await client.patch(
        f"/api/messages/{mid}/status",
        json={"status": "delivered"},
        headers=user_bob["headers"],
    )
    assert r1.status_code == 200, r1.text
    body1 = r1.json()
    assert body1 == {"ok": True, "changed": True, "status": "delivered"}
    row = await _db_status(mid)
    assert row["status"] == "delivered"
    assert row["delivered_at"] is not None
    assert row["read_at"] is None, "delivered не должен проставлять read_at"

    # delivered(1) -> read(2)
    r2 = await client.patch(
        f"/api/messages/{mid}/status",
        json={"status": "read"},
        headers=user_bob["headers"],
    )
    assert r2.status_code == 200, r2.text
    assert r2.json() == {"ok": True, "changed": True, "status": "read"}
    row = await _db_status(mid)
    assert row["status"] == "read"
    assert row["delivered_at"] is not None  # COALESCE сохранил первый timestamp
    assert row["read_at"] is not None

    # Статус виден и в истории чата (MessageResponse сериализует поле).
    hist = await client.get(
        f"/api/chats/{chat['id']}/messages", headers=user_alice["headers"]
    )
    assert hist.status_code == 200
    target = [m for m in hist.json()["messages"] if m["id"] == mid]
    assert target and target[0]["status"] == "read"


async def test_scenario_b_delayed_delivered_no_regression(client, user_alice, user_bob, chat):
    """Сценарий Б: гонка лагов сети — 'read' применён, затем опоздавший
    'delivered'. Условие rank < new_rank (2 < 1 ложно) => no-op: 200 OK,
    changed=False, статус НЕ откатывается."""
    mid = await _send(client, user_alice, chat, "Опоздавший ACK")

    # Сначала read (доставленность подтянется автоматически через COALESCE).
    rr = await client.patch(
        f"/api/messages/{mid}/status",
        json={"status": "read"},
        headers=user_bob["headers"],
    )
    assert rr.status_code == 200 and rr.json()["changed"] is True
    assert rr.json()["status"] == "read"

    # Запоздалый delivered долетает позже — тихий no-op, не 500.
    rd = await client.patch(
        f"/api/messages/{mid}/status",
        json={"status": "delivered"},
        headers=user_bob["headers"],
    )
    assert rd.status_code == 200, rd.text
    body = rd.json()
    assert body["ok"] is True
    assert body["changed"] is False
    assert body["status"] == "read", "статус не может двигаться назад"

    row = await _db_status(mid)
    assert row["status"] == "read"
    assert row["read_at"] is not None, "no-op не должен затирать read_at"


async def test_scenario_c_double_read_is_idempotent(client, user_alice, user_bob, chat):
    """Сценарий В: повторная доставка одного и того же 'read' (ретраии
    клиента) — оба запроса 200 OK, но changed только у первого."""
    mid = await _send(client, user_alice, chat, "Идемпотентность")

    first = await client.patch(
        f"/api/messages/{mid}/status",
        json={"status": "read"},
        headers=user_bob["headers"],
    )
    assert first.status_code == 200 and first.json()["changed"] is True

    second = await client.patch(
        f"/api/messages/{mid}/status",
        json={"status": "read"},
        headers=user_bob["headers"],
    )
    assert second.status_code == 200, second.text
    body = second.json()
    assert body["ok"] is True
    assert body["changed"] is False
    assert body["status"] == "read"

    # Третий повтор delivered/read подряд — стабильно no-op, БД не меняется.
    third = await client.patch(
        f"/api/messages/{mid}/status",
        json={"status": "delivered"},
        headers=user_bob["headers"],
    )
    assert third.status_code == 200 and third.json()["changed"] is False
    row = await _db_status(mid)
    assert row["status"] == "read"


async def test_scenario_d_sender_forbidden_on_own_message(client, user_alice, chat):
    """Сценарий Г (безопасность): автор не может сам выставить себе
    delivered/read (иначе накручивал бы синие галочки) => 403."""
    mid = await _send(client, user_alice, chat, "Моё сообщение")

    for target in ("delivered", "read"):
        resp = await client.patch(
            f"/api/messages/{mid}/status",
            json={"status": target},
            headers=user_alice["headers"],
        )
        assert resp.status_code == 403, f"{target}: ожидали 403, получили {resp.status_code}"

    row = await _db_status(mid)
    assert row["status"] == "sent", "403 обязан предшествовать любой записи"


async def test_non_member_and_bad_payload_rejected(client, auth_factory, chat, user_alice):
    """Границы безопасности/валидации: посторонний => 403; неизвестное
    сообщение => 404; недопустимый статус/попытка сбросить в 'sent' => 422
    (валидный вход отсекается схемой, а не падением роута)."""
    eve = await auth_factory("eve")
    mid = await _send(client, user_alice, chat, "Только для чата")

    resp = await client.patch(
        f"/api/messages/{mid}/status",
        json={"status": "read"},
        headers=eve["headers"],
    )
    assert resp.status_code == 403

    resp = await client.patch(
        "/api/messages/999999/status",
        json={"status": "read"},
        headers=eve["headers"],
    )
    assert resp.status_code == 404

    # 'sent' запрещён как целевой (назад не ходим), мусор — 422.
    mallory = await auth_factory("mallory")
    for bad in ("sent", "deleted", "READ"):
        resp = await client.patch(
            f"/api/messages/{mid}/status",
            json={"status": bad},
            headers=mallory["headers"],
        )
        assert resp.status_code == 422, f"'{bad}' обязан отсесть на валидации схемы"


async def _enable_ghost_setting(user: dict) -> None:
    """Включает серверную настройку Ghost Mode напрямую в таблице settings
    (UI-эндпоинт настроек — задача следующего коммита).

    ON CONFLICT — стандартный SQL upsert, одинаково исполняется SQLite
    (>= 3.24, аiosqlite в тестах) и PostgreSQL 16.
    """
    from sqlalchemy import text as sql_text

    async with database.get_db() as db:
        await db.execute(
            sql_text(
                "INSERT INTO settings (key, value) VALUES (:k, :v) "
                "ON CONFLICT(key) DO UPDATE SET value=:v"
            ),
            {"k": f"ghost_read:{user['user_id']}", "v": "1"},
        )


async def test_ghost_mode_client_flag_stays_delivered(client, user_alice, user_bob, chat):
    """Ghost Mode (клиентский флаг): read => тихий 200 OK, changed отражает
    фактический переход в delivered, физический статус в БД — 'delivered',
    read_at не появляется. Собеседник никогда не увидит синих галочек."""
    mid = await _send(client, user_alice, chat, "Прочитано инкогнито")

    resp = await client.patch(
        f"/api/messages/{mid}/status",
        json={"status": "read", "ghost": True},
        headers=user_bob["headers"],
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["status"] == "delivered"
    assert body["changed"] is True  # sent -> delivered всё же состоялся

    row = await _db_status(mid)
    assert row["status"] == "delivered"
    assert row["read_at"] is None

    # Повторный ghost-read ничего не меняет: идемпотентный no-op.
    again = await client.patch(
        f"/api/messages/{mid}/status",
        json={"status": "read", "ghost": True},
        headers=user_bob["headers"],
    )
    assert again.status_code == 200 and again.json()["changed"] is False


async def test_ghost_mode_server_setting_applies_without_flag(client, user_alice, user_bob, chat):
    """Ghost Mode (серверная настройка settings['ghost_read:{uid}']): обычный
    PATCH read без флага тоже останавливается на delivered."""
    await _enable_ghost_setting(user_bob)
    mid = await _send(client, user_alice, chat, "Настроенный призрак")

    resp = await client.patch(
        f"/api/messages/{mid}/status",
        json={"status": "read"},
        headers=user_bob["headers"],
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "delivered"

    row = await _db_status(mid)
    assert row["status"] == "delivered"
    assert row["read_at"] is None
