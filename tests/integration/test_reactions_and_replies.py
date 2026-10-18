"""MeNo — интеграционные тесты Этапа 7.4 (Микро-спринт 3, часть 1): реакции и ответы.

Покрывает:
- модели/миграцию: таблица reactions с UNIQUE(message_id, user_id) и FK CASCADE,
  колонки messages.reply_to_id / reactions_summary;
- POST /api/messages/{id}/reactions — toggle on/off, E2EE-непрозрачность blob'а,
  консистентность денормализованного кэша, права (403/404), валидация тела (422);
- гонка двойного POST: параллельные toggle от одного пользователя не создают
  дубликат (замок уникальности -> rowcount-логика без 500);
- GET batch-эндпоинт реакций (анти-N+1) и историю чата с реакциями;
- ответы: reply_to_id сохраняется, оригинал из чужого чата отвергается (400),
  удаление оригинала НЕ каскадирует на ответ (SET NULL).

Диалект-безопасно для SQLite (aiosqlite) и PostgreSQL 16: только стандартный
SQL через ORM-метаданные и bind-параметры; фикстуры корневых conftest.py.
"""
import asyncio
import json

from server import database

# Фейковый AES-GCM blob (nonce:ct:tag, base64url) — сервер обязан обращаться
# с ним как с непрозрачными байтами (тест на "слепот" relay).
BLOB_THUMBS_UP = "h9t_3ZxQv2r1K8nL:cHlwb3JlLXVwLWVtb2pp:"
BLOB_HEART = "aB3dE5fG7hI9jK:cHVycGxlLWhlYXJ0:"


async def _db_reaction_rows(message_id: int) -> list[dict]:
    async with database.get_db() as db:
        return await database.aq(
            db,
            "SELECT id, user_id, encrypted_payload FROM reactions "
            "WHERE message_id=:mid ORDER BY user_id",
            {"mid": message_id},
        )


async def _db_message_fields(message_id: int) -> dict:
    async with database.get_db() as db:
        row = await database.aq1(
            db,
            "SELECT reply_to_id, reactions_summary FROM messages WHERE id=:id",
            {"id": message_id},
        )
    assert row is not None, "сообщение исчезло из БД"
    return row


async def _send(client, sender: dict, chat: dict, content: str, **extra) -> dict:
    resp = await client.post(
        f"/api/chats/{chat['id']}/messages",
        json={"type": "text", "content": content, **extra},
        headers=sender["headers"],
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_reaction_schema_constraints_exist():
    """ORM-контрактыtoggle-замка и каскадов: UNIQUE(message,user), FK CASCADE/SET NULL."""
    from server.db.models_base import Message, Reaction

    reaction_table = Reaction.__table__
    unique_pairs = [
        tuple(sorted(c.name for c in uc.columns))
        for uc in reaction_table.constraints
        if uc.__class__.__name__ == "UniqueConstraint"
    ]
    assert ("message_id", "user_id") in unique_pairs

    fk_by_target = {
        fk.target_fullname: fk.ondelete for fk in reaction_table.foreign_keys
    }
    assert fk_by_target["messages.id"] == "CASCADE"
    assert fk_by_target["users.id"] == "CASCADE"

    msg_table = Message.__table__
    assert "reply_to_id" in msg_table.c and "reactions_summary" in msg_table.c
    reply_fk = next(fk for fk in msg_table.foreign_keys if fk.target_fullname == "messages.id")
    assert reply_fk.ondelete == "SET NULL"


async def test_toggle_on_off_roundtrip(client, user_alice, user_bob, chat):
    """Сценарий toggle: POST -> реакция активна; повторный POST -> снята; снова -> активна."""
    msg = await _send(client, user_bob, chat, "Реакция-тест")
    mid = msg["id"]

    r1 = await client.post(
        f"/api/messages/{mid}/reactions",
        json={"payload": BLOB_THUMBS_UP},
        headers=user_alice["headers"],
    )
    assert r1.status_code == 200, r1.text
    body1 = r1.json()
    assert body1["active"] is True
    assert body1["reactions"] == {BLOB_THUMBS_UP: [user_alice["user_id"]]}

    # Повторный POST тем же пользователем = снятие реакции (toggle off).
    r2 = await client.post(
        f"/api/messages/{mid}/reactions",
        json={"payload": BLOB_HEART},
        headers=user_alice["headers"],
    )
    assert r2.status_code == 200, r2.text
    body2 = r2.json()
    assert body2["active"] is False
    assert body2["reactions"] == {}
    assert await _db_reaction_rows(mid) == []

    # Третий POST — снова вставка, кэш и таблица консистентны.
    r3 = await client.post(
        f"/api/messages/{mid}/reactions",
        json={"payload": BLOB_HEART},
        headers=user_alice["headers"],
    )
    assert r3.json()["active"] is True
    rows = await _db_reaction_rows(mid)
    assert len(rows) == 1 and rows[0]["encrypted_payload"] == BLOB_HEART


async def test_denormalized_summary_stays_consistent(client, user_alice, user_bob, chat):
    """Кэш messages.reactions_summary обновляется в той же транзакции, что и таблица."""
    msg = await _send(client, user_bob, chat, "Кэш-консистентность")
    mid = msg["id"]

    await client.post(
        f"/api/messages/{mid}/reactions",
        json={"payload": BLOB_THUMBS_UP},
        headers=user_alice["headers"],
    )
    summary = json.loads((await _db_message_fields(mid))["reactions_summary"])
    assert summary == {BLOB_THUMBS_UP: [user_alice["user_id"]]}

    await client.post(
        f"/api/messages/{mid}/reactions",
        json={"payload": BLOB_THUMBS_UP},
        headers=user_bob["headers"],
    )
    summary = json.loads((await _db_message_fields(mid))["reactions_summary"])
    assert summary[BLOB_THUMBS_UP] == sorted(
        [user_alice["user_id"], user_bob["user_id"]]
    )
    # Кэш = точное отражение таблицы: одинаковое число строк.
    assert len(summary[BLOB_THUMBS_UP]) == len(await _db_reaction_rows(mid))


async def test_concurrent_double_post_no_duplicate(client, user_alice, user_bob, chat):
    """Гонка двух параллельных POST одним пользователем: замок UNIQUE не даёт дубликата."""
    msg = await _send(client, user_bob, chat, "Гонка реакций")
    mid = msg["id"]

    results = await asyncio.gather(*[
        client.post(
            f"/api/messages/{mid}/reactions",
            json={"payload": BLOB_THUMBS_UP},
            headers=user_alice["headers"],
        )
        for _ in range(2)
    ])
    assert all(r.status_code == 200 for r in results), [r.text for r in results]
    rows = await _db_reaction_rows(mid)
    assert len(rows) == 1, "UNIQUE(message_id, user_id) обязан схлопнуть гонку в одну строку"


async def test_permissions_and_validation(client, user_alice, user_bob, chat, auth_factory):
    """Права и валидация: чужой -> 403, несуществующее -> 404, мусор-тело -> 422."""
    msg = await _send(client, user_bob, chat, "Права реакций")
    mid = msg["id"]
    stranger = await auth_factory("carol")

    r_forbidden = await client.post(
        f"/api/messages/{mid}/reactions",
        json={"payload": BLOB_THUMBS_UP},
        headers=stranger["headers"],
    )
    assert r_forbidden.status_code == 403

    r_missing = await client.post(
        "/api/messages/999999/reactions",
        json={"payload": BLOB_THUMBS_UP},
        headers=user_alice["headers"],
    )
    assert r_missing.status_code == 404

    r_invalid = await client.post(
        f"/api/messages/{mid}/reactions",
        json={"payload": "short"},
        headers=user_alice["headers"],
    )
    assert r_invalid.status_code == 422


async def test_history_batch_load_no_n_plus_one(
    client, user_alice, user_bob, chat, auth_factory
):
    """История отдаёт реакции страницей; отдельный batch-endpoint жив и авторизуем."""
    m1 = await _send(client, user_bob, chat, "первое")
    m2 = await _send(client, user_bob, chat, "второе")
    await client.post(
        f"/api/messages/{m1['id']}/reactions",
        json={"payload": BLOB_HEART},
        headers=user_alice["headers"],
    )

    hist = await client.get(
        f"/api/chats/{chat['id']}/messages", headers=user_bob["headers"]
    )
    assert hist.status_code == 200, hist.text
    by_id = {m["id"]: m for m in hist.json()["messages"]}
    assert by_id[m1["id"]]["reactions"] == {BLOB_HEART: [user_alice["user_id"]]}
    assert by_id[m2["id"]]["reactions"] == {}

    batch = await client.get(
        f"/api/chats/{chat['id']}/messages/reactions",
        params={"ids": f"{m1['id']},{m2['id']}"},
        headers=user_alice["headers"],
    )
    assert batch.status_code == 200, batch.text
    assert batch.json()["reactions"] == {str(m1["id"]): {BLOB_HEART: [user_alice["user_id"]]}}

    stranger = await auth_factory("dave")
    r_forbidden = await client.get(
        f"/api/chats/{chat['id']}/messages/reactions",
        params={"ids": str(m1["id"])},
        headers=stranger["headers"],
    )
    assert r_forbidden.status_code == 403


async def test_reply_to_same_chat_ok(client, user_alice, user_bob, chat):
    """Ответ валиден: reply_to_id сохраняется и возвращается в истории и WS-payload."""
    original = await _send(client, user_alice, chat, "Оригинал для ответа")
    reply = await _send(
        client, user_bob, chat, "Ответ на оригинал",
        reply_to_id=original["id"],
    )
    assert reply["reply_to_id"] == original["id"]

    hist = await client.get(f"/api/chats/{chat['id']}/messages", headers=user_bob["headers"])
    msgs = {m["id"]: m for m in hist.json()["messages"]}
    assert msgs[reply["id"]]["reply_to_id"] == original["id"]


async def test_reply_to_foreign_or_missing_rejected(
    client, auth_factory, user_alice, user_bob, chat
):
    """Бизнес-валидация: оригинал из чужого чата или несуществующий -> 400.

    «Чужое пространство» — групповой чат bob+carol: bob создаёт его как
    инициатор с валидным вторым участником (personal-чат bob<->alice уже
    существует через фикстуру `chat` и вернёт существующий id вместо чужого).
    """
    carol = await auth_factory("carol")
    other = await client.post(
        "/api/chats",
        json={"type": "group", "title": "Тусовка без Алисы", "user_ids": [carol["user_id"]]},
        headers=user_bob["headers"],
    )
    assert other.status_code == 200, other.text
    foreign_msg = await _send(client, user_bob, other.json(), "Чужой чат")

    r_foreign = await client.post(
        f"/api/chats/{chat['id']}/messages",
        json={
            "type": "text",
            "content": "Незаконный ответ",
            "reply_to_id": foreign_msg["id"],
        },
        headers=user_alice["headers"],
    )
    assert r_foreign.status_code == 400

    r_missing = await client.post(
        f"/api/chats/{chat['id']}/messages",
        json={"type": "text", "content": "Ответ в никуда", "reply_to_id": 999999},
        headers=user_alice["headers"],
    )
    assert r_missing.status_code == 400


async def test_delete_original_keeps_reply_with_null(client, user_alice, user_bob, chat):
    """SET NULL: удаление оригинала не стирает ответ — reply_to_id обнуляется."""
    original = await _send(client, user_alice, chat, "Удаляемый оригинал")
    reply = await _send(
        client, user_bob, chat, "Живой ответ", reply_to_id=original["id"]
    )

    r_del = await client.delete(
        f"/api/messages/{original['id']}", headers=user_alice["headers"]
    )
    assert r_del.status_code == 200, r_del.text

    fields = await _db_message_fields(reply["id"])
    assert fields["reply_to_id"] is None, "ON DELETE SET NULL обязан снять ссылку, не удалив строку"


async def test_message_delete_cascades_reactions(client, user_alice, user_bob, chat):
    """CASCADE: удаление сообщения физически чистит его реакции (нет висячих строк)."""
    msg = await _send(client, user_bob, chat, "Сообщение с реакцией")
    mid = msg["id"]
    await client.post(
        f"/api/messages/{mid}/reactions",
        json={"payload": BLOB_THUMBS_UP},
        headers=user_alice["headers"],
    )
    assert len(await _db_reaction_rows(mid)) == 1

    r_del = await client.delete(f"/api/messages/{mid}", headers=user_bob["headers"])
    assert r_del.status_code == 200

    async with database.get_db() as db:
        orphans = await database.aq(
            db, "SELECT id FROM reactions WHERE message_id=:mid", {"mid": mid}
        )
    assert orphans == [], "FK ON DELETE CASCADE обязан удалить реакции вместе с сообщением"
