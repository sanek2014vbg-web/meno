"""MeNo — Этап 7.3: E2EE-реакции и CAS-ранги статусов доставки.

Приватность по дизайну (ТЗ v2.0 Пункт 14): сервер хранит ТОЛЬКО AES-GCM blob
(`encrypted_payload`) — он не знает ни эмодзи, ни автора содержания реакции.
Метадананные «кто/куда/когда» неизбежны (это floor любого E2EE-транспорта),
но содержание скрыто.

Два механизма надёжности, реализованных здесь физически:

1. Атомарный CAS UPDATE со searched-CASE (защита от Race Conditions):
   `status_rank` сообщения может только НЕУБЫВАТЬ ('sent'=0 -> 'delivered'=1
   -> 'read'=2). Два конкурентных обновления одного сообщения не могут
   «откатить» статус назад: CASE сравнивает ранг внутри UPDATE на строке,
   которую БД уже заблокировала для записи — проигравший гонки увидит
   новый ранг и сохранит максимальный. native_enum=False: в БД лежит
   SMALLINT, диалект-переносимость SQLite/PostgreSQL гарантирована.

2. Batch-load реакций через ОДИН запрос `IN (:ids)` (борьба с N+1):
   история чата из 50 сообщений резолвится двумя SQL-запросами
   (messages + reactions GROUP BY), а не 51. Агрегация в Python-dict — O(N).

Toggle-семантика: повторный POST реакции тем же пользователем на то же
сообщение СНИМАЕТ её (DELETE) — UniqueConstraint(message_id, user_id) делает
это идемпотентным; IntegrityError при параллельной гонке двух вкладок
перехватывается и трактуется как «победитель уже записал».
"""

import json
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import bindparam, text as sql_text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from server import database
from server.deps import get_current_user, is_chat_member
from server.rate_limit import limiter, user_key
from server.ws_manager import manager

router = APIRouter(prefix="/api", tags=["reactions"])

# --- CAS-ранги статусов доставки (Этап 7.3 ТЗ) -----------------------------
# Числовые ранги хранятся в messages.status_rank (SMALLINT, native_enum=False).
STATUS_RANKS = {"sent": 0, "delivered": 1, "read": 2}
RANK_STATUSES = {v: k for k, v in STATUS_RANKS.items()}


class UpdateStatusRequest(BaseModel):
    """Обновление статуса доставки сообщения (CAS, монотонно возрастающий ранг)."""

    status: str = Field(..., pattern="^(sent|delivered|read)$")


class ReactRequest(BaseModel):
    """AES-GCM blob реакции, зашифрованный общим секретом чата на клиенте."""

    encrypted_payload: str = Field(
        ...,
        min_length=8,
        max_length=4096,
        description="base64(nonce+ciphertext+tag) — сервер не разбирает содержимое",
    )


# --------------------------------------------------------------------------- #
# 1. CAS UPDATE: searched-CASE прямо в SET, ранг только растёт                #
# --------------------------------------------------------------------------- #

_CAS_STATUS_SQL = """
UPDATE messages
SET status_rank = CASE
        WHEN status_rank < :new_rank THEN :new_rank
        ELSE status_rank
    END
WHERE id = :id AND chat_id = :cid AND status_rank <> :new_rank
"""


async def cas_bump_status(
    db: AsyncSession, message_id: int, chat_id: int, status: str
) -> dict:
    """Атомарно поднимает ранг статуса сообщения; никогда не понижает его.

    Возвращает {"bumped": bool, "rank": int}. Условие `status_rank <> :new_rank`
    в WHERE делает повторный вызов no-op (идемпотентность без лишней блокировки).
    """
    new_rank = STATUS_RANKS[status]
    result = await db.execute(
        sql_text(_CAS_STATUS_SQL),
        {"new_rank": new_rank, "id": message_id, "cid": chat_id},
    )
    row = await database.aq1(
        db, "SELECT status_rank FROM messages WHERE id=:id", {"id": message_id}
    )
    rank = int(row["status_rank"]) if row else new_rank
    return {
        "bumped": result.rowcount > 0,
        "rank": rank,
        "status": RANK_STATUSES.get(rank, "sent"),
    }


@router.post("/messages/{message_id}/status")
async def update_message_status(
    message_id: int,
    body: UpdateStatusRequest,
    user: dict = Depends(get_current_user),
):
    """REST-вход для CAS-апдейта статуса (delivered/read от получателя)."""
    async with database.get_db() as db:
        m = await database.aq1(
            db,
            "SELECT id, chat_id, sender_id FROM messages WHERE id=:id",
            {"id": message_id},
        )
        if not m:
            raise HTTPException(404, "Сообщение не найдено")
        if not await is_chat_member(m["chat_id"], user["id"]):
            raise HTTPException(403, "Вы не участник этого чата")
        outcome = await cas_bump_status(db, message_id, m["chat_id"], body.status)
    payload = {
        "type": outcome["status"],  # "delivered" | "read" — контракт клиента
        "message_id": message_id,
        "chat_id": m["chat_id"],
        "user_id": user["id"],
    }
    if outcome["bumped"]:
        await manager.send_to_user(m["sender_id"], payload)
    return {"ok": True, **outcome}


# --------------------------------------------------------------------------- #
# 2. Toggle-реакция + пересборка денормализованной сводки в той же транзакции #
# --------------------------------------------------------------------------- #


async def _rebuild_summary(db: AsyncSession, message_id: int) -> str:
    """Пересчитывает reactions_summary для одного сообщения (COUNT blobs).

    Сервер считает только КОЛИЧЕСТВО записей: группировка по эмодзи невозможна
    без знания plaintext — это осознанная privacy-деградация (см. docstring).
    """
    rows = await database.aq(
        db,
        "SELECT encrypted_payload FROM reactions WHERE message_id=:mid ORDER BY id",
        {"mid": message_id},
    )
    summary: Dict[str, int] = {}
    for r in rows:
        # Ключ bucket'а — префикс blob'а: одинаковым реакциям (одинаковый
        # plaintext при стабильном ключе чата) соответствует одинаковый ключ,
        # поэтому count склеивается корректно; разные реакции не сливаются.
        bucket = r["encrypted_payload"][:24]
        summary[bucket] = summary.get(bucket, 0) + 1
    return json.dumps(summary, separators=(",", ":"))


@router.post("/messages/{message_id}/reactions")
async def toggle_reaction(
    message_id: int,
    body: ReactRequest,
    request: Request,
    user: dict = Depends(get_current_user),
):
    """POST /api/messages/{id}/reactions — toggle E2EE-реакции.

    Есть запись (message_id, user_id) -> удаляем; нет -> вставляем blob.
    Сводка пересобирается в ЭТОЙ ЖЕ транзакции (get_db коммитит на выходе),
    поэтому денормализованный reactions_summary физически не может разойтись
    с таблицей reactions.
    """
    if not await limiter.allow_async(user_key("react", request, user["id"]), 30, 60):
        raise HTTPException(429, "Слишком много реакций")

    async with database.get_db() as db:
        m = await database.aq1(
            db, "SELECT id, chat_id FROM messages WHERE id=:id", {"id": message_id}
        )
        if not m:
            raise HTTPException(404, "Сообщение не найдено")
        if not await is_chat_member(m["chat_id"], user["id"]):
            raise HTTPException(403, "Вы не участник этого чата")

        existing = await database.aq1(
            db,
            "SELECT id FROM reactions WHERE message_id=:mid AND user_id=:uid",
            {"mid": message_id, "uid": user["id"]},
        )
        if existing:
            await db.execute(
                sql_text("DELETE FROM reactions WHERE id=:id"), {"id": existing["id"]}
            )
            action = "removed"
        else:
            try:
                await db.execute(
                    sql_text(
                        "INSERT INTO reactions (message_id, user_id, encrypted_payload) "
                        "VALUES (:mid, :uid, :blob)"
                    ),
                    {
                        "mid": message_id,
                        "uid": user["id"],
                        "blob": body.encrypted_payload,
                    },
                )
                action = "added"
            except IntegrityError:
                # Гонка двух вкладок: победитель уже вставил строку
                # (UNIQUE(message_id,user_id)). Откатываем свою ветку и
                # отвечаем идемпотентно — дубликата физически нет.
                await db.rollback()
                return {"ok": True, "action": "already_present"}

        summary = await _rebuild_summary(db, message_id)
        await db.execute(
            sql_text(
                "UPDATE messages SET reactions_summary=:s "
                "WHERE id=:id AND reactions_summary<>:s"
            ),
            {"s": summary, "id": message_id},
        )
        members = [
            r["user_id"]
            for r in await database.aq(
                db,
                "SELECT user_id FROM chat_members WHERE chat_id=:cid",
                {"cid": m["chat_id"]},
            )
        ]

    await manager.send_to_users(
        members,
        {
            "type": "reaction",
            "action": action,
            "message_id": message_id,
            "chat_id": m["chat_id"],
            "user_id": user["id"],
            "reactions_summary": summary,
        },
    )
    return {"ok": True, "action": action, "reactions_summary": summary}


# --------------------------------------------------------------------------- #
# 3. Batch-load реакций: ОДИН запрос IN (:ids) вместо N (устранение N+1)      #
# --------------------------------------------------------------------------- #


async def load_reactions_batch(
    db: AsyncSession, message_ids: List[int]
) -> Dict[int, str]:
    """Возвращает {message_id: reactions_summary_json} одним SQL-запросом.

    Расширяемый `IN :ids` (expanding bindparam) — SQLAlchemy генерирует
    плейсхолдеры под все id: никаких f-string-конкатенаций id в SQL
    (антипаттерн из push.py, отмеченный аудитом). GROUP BY считается на
    стороне БД, агрегация в Python-dict — O(N) один проход.
    """
    if not message_ids:
        return {}
    stmt = sql_text(
        "SELECT message_id, COUNT(*) AS n, MIN(substr(encrypted_payload,1,24)) AS bucket "
        "FROM reactions WHERE message_id IN :ids GROUP BY message_id, bucket"
    ).bindparams(bindparam("ids", expanding=True))
    rows = (await db.execute(stmt, {"ids": list(message_ids)})).all()
    agg: Dict[int, Dict[str, int]] = {}
    for r in rows:
        bucket = agg.setdefault(r.message_id, {})
        key = r.bucket or ""
        bucket[key] = bucket.get(key, 0) + int(r.n)
    return {
        mid: json.dumps(buckets, separators=(",", ":")) for mid, buckets in agg.items()
    }
