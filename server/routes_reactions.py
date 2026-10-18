"""MeNo — реакции на сообщения (Этап 7.4, Микро-спринт 3).

Privacy-модель (E2EE):
- эмодзи НЕ покидает устройство в открытом виде: клиент шифрует его
  AES-GCM симметричным ключом чата и присылает непрозрачный blob в
  поле `payload`. Сервер хранит и пересылает blob как есть — он не
  знает ни эмодзи, ни его автора для посторонних;
- открытые метаданные (`user_id`, `message_id`) необходимы для
  toggle-инварианта UNIQUE(message_id, user_id) и авторизации.

Anti-N+1: загрузка истории получает реакции ОДНИМ batch-запросом
`IN (:ids)` (fetch_summaries_batch), а не по запросу на сообщение.

Транзакционность: изменение строки `reactions` и денормализованного
кэша `messages.reactions_summary` выполняются в одной сессии/транзакции
(get_db делает commit на выходе) — кэш никогда не расходится с таблицей.
WS-событие рассылается ПОСЛЕ коммита (паттерн send_message/update_status).
"""
import json

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text as sql_text
from sqlalchemy.exc import IntegrityError

from server import database
from server.deps import get_current_user, is_chat_member
from server.utils import as_utc, utc_now
from server.ws_manager import manager

router = APIRouter(prefix="/api", tags=["reactions"])


class ReactionToggleRequest(BaseModel):
    """Тело POST /messages/{id}/reactions."""

    payload: str = Field(
        min_length=8,
        max_length=512,
        description="AES-GCM blob зашифрованного эмодзи {nonce}:{ct}:{tag} "
                    "(base64url) — сервер не имеет ключа чата и не видит эмодзи",
    )


def _parse_summary(raw: object) -> dict:
    """Безопасная десериализация денормализованного кэша реакций.

    Легаси-строки до миграции c8d9e0f1a2b3 имеют NULL или битый JSON —
    наружу отдаём пустой словарь, никаких исключений на выдаче (без 500).
    """
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


async def _live_message_or_404(db, message_id: int) -> dict:
    """Загрузка сообщения с проверкой «живости» (TTL-окно = 0, как в статус-роуте)."""
    m = await database.aq1(
        db,
        "SELECT chat_id, sender_id, expires_at FROM messages WHERE id=:id",
        {"id": message_id},
    )
    if not m:
        raise HTTPException(404, "Сообщение не найдено")
    # Сгорающее сообщение физически мертво, хотя janitor ещё не стёр строку:
    # реакция на него невозможна (иначе кэш пережил бы собственный контент).
    if m.get("expires_at") is not None and as_utc(m["expires_at"]) <= utc_now():
        raise HTTPException(404, "Сообщение не найдено")
    return m


def _rebuild_summary(rows: list[dict]) -> dict:
    """Пересборка кэша из актуальных строк реакций: {payload: [user_id, ...]}.

    Ключ — сам зашифрованный blob: одинаковые эмодзи от разных пользователей
    дают одинаковый детерминированный blob только при одном ключе чата, что
    корректно группирует реакции без раскрытия содержимого на сервере.
    """
    summary: dict[str, list[int]] = {}
    for r in rows:
        summary.setdefault(r["encrypted_payload"], []).append(r["user_id"])
    return summary


@router.post("/messages/{message_id}/reactions")
async def toggle_reaction(
    message_id: int,
    body: ReactionToggleRequest,
    user: dict = Depends(get_current_user),
):
    """Toggle-реакция: есть связь (message, user) -> удалить, нет -> вставить.

    Защита от гонки двойного POST — не check-then-act, а «замок» уникальности:
    оба конкурента проходят SELECT-проверку, но INSERT проигравшего ловит
    IntegrityError на UNIQUE(message_id, user_id) -> откат -> повторная
    проверка -> идемпотентный ответ без дубликата и без 500.
    """
    async with database.get_db() as db:
        m = await _live_message_or_404(db, message_id)
        if not await is_chat_member(m["chat_id"], user["id"]):
            raise HTTPException(403, "Нет доступа")

        existing = await database.aq1(
            db,
            "SELECT id FROM reactions WHERE message_id=:mid AND user_id=:uid",
            {"mid": message_id, "uid": user["id"]},
        )

        if existing:
            await db.execute(
                sql_text("DELETE FROM reactions WHERE id=:id"),
                {"id": existing["id"]},
            )
            active = False
        else:
            try:
                await db.execute(
                    sql_text(
                        "INSERT INTO reactions (message_id, user_id, encrypted_payload) "
                        "VALUES (:mid, :uid, :payload)"
                    ),
                    {"mid": message_id, "uid": user["id"], "payload": body.payload},
                )
            except IntegrityError:
                # Проиграли гонку параллельному POST того же пользователя:
                # победитель уже вставил реакцию — это эквивалентно toggle-off.
                await db.rollback()
                won = await database.aq1(
                    db,
                    "SELECT id FROM reactions WHERE message_id=:mid AND user_id=:uid",
                    {"mid": message_id, "uid": user["id"]},
                )
                if won:
                    return {
                        "ok": True,
                        "active": True,
                        "message_id": message_id,
                        "reactions": await _current_summary(db, message_id),
                    }
                raise HTTPException(409, "Реакция не сохранена, повторите попытку")
            active = True

        # Денормализованный кэш обновляется в ЭТОЙ ЖЕ транзакции —
        # список чатов и поиск всегда видят консистентное состояние.
        summary = _rebuild_summary(await _reaction_rows(db, message_id))
        await db.execute(
            sql_text("UPDATE messages SET reactions_summary=:s WHERE id=:id"),
            {"s": json.dumps(summary, ensure_ascii=False), "id": message_id},
        )
        members = [r["user_id"] for r in await database.aq(
            db, "SELECT user_id FROM chat_members WHERE chat_id=:cid",
            {"cid": m["chat_id"]},
        )]

    # WS вне транзакции (после commit): подписчики получают только
    # записанное состояние; blob остаётся непрозрачным для relay.
    await manager.send_to_users(members, {
        "type": "reaction_update",
        "chat_id": m["chat_id"],
        "message_id": message_id,
        "user_id": user["id"],
        "payload": body.payload,
        "active": active,
        "reactions": summary,
    })
    return {"ok": True, "active": active, "message_id": message_id, "reactions": summary}


async def _reaction_rows(db, message_id: int) -> list[dict]:
    """Все реакции одного сообщения (порядок детерминирован для кэша)."""
    return await database.aq(
        db,
        "SELECT encrypted_payload, user_id FROM reactions "
        "WHERE message_id=:mid ORDER BY user_id",
        {"mid": message_id},
    )


async def _current_summary(db, message_id: int) -> dict:
    return _rebuild_summary(await _reaction_rows(db, message_id))


@router.get("/chats/{chat_id}/messages/reactions")
async def batch_reactions_for_messages(
    chat_id: int,
    ids: str = Query(default="", description="Список id через запятую: '1,2,3'"),
    user: dict = Depends(get_current_user),
):
    """Batch-load реакций по списку id сообщений — ОДИН запрос вместо N.

    Используется историей чата: после выборки страницы сообщений клиенты
    получают все треки одним round-trip `WHERE message_id IN (...)`.
    Диалект-безопасно: bind-params генерируются динамически (:m0, :m1...),
    поэтому список любого размера работает и на SQLite, и на PG 16.
    """
    if not await is_chat_member(chat_id, user["id"]):
        raise HTTPException(403, "Вы не участник этого чата")

    message_ids = _parse_ids(ids)
    if not message_ids:
        return {"reactions": {}}

    placeholders = ", ".join(f":m{i}" for i in range(len(message_ids)))
    params = {f"m{i}": mid for i, mid in enumerate(message_ids)}
    params["cid"] = chat_id
    async with database.get_db() as db:
        rows = await database.aq(
            db,
            f"SELECT r.message_id AS mid, r.user_id AS uid, r.encrypted_payload AS payload "
            f"FROM reactions r JOIN messages m ON m.id = r.message_id "
            f"WHERE m.chat_id = :cid AND r.message_id IN ({placeholders}) "
            f"ORDER BY r.message_id, r.user_id",
            params,
        )

    grouped: dict[int, dict[str, list[int]]] = {}
    for r in rows:
        per_msg = grouped.setdefault(r["mid"], {})
        per_msg.setdefault(r["payload"], []).append(r["uid"])
    return {"reactions": {str(mid): grp for mid, grp in grouped.items()}}


def _parse_ids(raw: object) -> list[int]:
    """Разбор query-параметра `ids=1,2,3` с защитой от мусора (только положительные int)."""
    if not isinstance(raw, str):
        return []
    parsed: list[int] = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if chunk.isdigit():
            value = int(chunk)
            if value > 0:
                parsed.append(value)
    return parsed[:200]  # жёсткий потолок страницы — защита от abuse-запросов
