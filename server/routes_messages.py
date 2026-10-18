"""MeNo — маршруты сообщений: отправка, история, поиск, исчезающие сообщения.

Ключевые свойства (ТЗ):
- курсорная пагинация истории и поиска (Этап 4.4);
- идемпотентность отправки по client_id + дедупликация (Этап 4.5);
- статусы сообщений sent -> delivered -> read с защитой от гонок (Этап 7.3);
- транзакционная запись: INSERT сообщения и commit в одной сессии, WS/push
  — только после успешного коммита;
- полнотекстовый поиск с поддержкой кириллицы: на PG используется
  to_tsvector('russian'), на SQLite — переносимый LIKE (Этап 4.2);
- антиспам-лимит по окну времени (tz-aware UTC).
"""
from datetime import timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import text as sql_text
from sqlalchemy.exc import IntegrityError

from server import config, database, push as push_service
from server.db.connection import engine
from server.db.models_base import MessageStatus, status_rank
from server.deps import get_current_user, is_chat_member
from server.rate_limit import user_key, limiter
from server.utils import as_utc, utc_now
from server.ws_manager import manager

router = APIRouter(prefix="/api", tags=["messages"])


def _schema_has_expires_at() -> bool:
    """Есть ли в реальной схеме БД колонка messages.expires_at.

    Совместимость (Этап 4.1/A7): легаси-БД могут быть созданы до миграции
    a1f2e3d4b5c6 — запросы с явным упоминанием expires_at на них падают с
    'no such column'. Результат кэшируется на процесс: схема меняется только
    вместе с деплоем/миграцией. Проверка синхронная и одноразовая, поэтому
    не добавляет round-trip в горячий путь после первого вызова.
    """
    global _EXPIRES_AT_OK
    if _EXPIRES_AT_OK is None:
        try:
            from sqlalchemy import inspect as sa_inspect

            with engine.sync_engine.connect() as conn:
                cols = {c["name"] for c in sa_inspect(conn).get_columns("messages")}
            _EXPIRES_AT_OK = "expires_at" in cols
        except Exception:  # инспектор недоступен — считаем схему полной
            _EXPIRES_AT_OK = True
    return _EXPIRES_AT_OK


_EXPIRES_AT_OK: bool | None = None


def _schema_has_reply_to() -> bool:
    """Есть ли в реальной схеме БД колонка messages.reply_to_id (Этап 7.4).

    Тот же легаси-паттерн, что и _schema_has_expires_at: БД, созданные до
    миграции c8d9e0f1a2b3, не имеют колонок ответов/реакций — INSERT с явным
    reply_to_id на них упал бы с 'no such column' (500). Кэш на процесс.
    """
    global _REPLY_TO_OK
    if _REPLY_TO_OK is None:
        try:
            from sqlalchemy import inspect as sa_inspect

            with engine.sync_engine.connect() as conn:
                cols = {c["name"] for c in sa_inspect(conn).get_columns("messages")}
            _REPLY_TO_OK = "reply_to_id" in cols
        except Exception:  # инспектор недоступен — считаем схему полной
            _REPLY_TO_OK = True
    return _REPLY_TO_OK


_REPLY_TO_OK: bool | None = None

_REACTIONS_TABLE_OK: bool | None = None


def _reactions_table_exists() -> bool:
    """Есть ли в реальной схеме БД таблица reactions (Этап 7.4).

    Тот же легаси-паттерн, что и _schema_has_reply_to: на БД, созданных до
    миграции c8d9e0f1a2b3, DELETE FROM reactions упал бы с 'no such table'.
    Результат кэшируется на процесс.
    """
    global _REACTIONS_TABLE_OK
    if _REACTIONS_TABLE_OK is None:
        try:
            from sqlalchemy import inspect as sa_inspect

            with engine.sync_engine.connect() as conn:
                tables = set(sa_inspect(conn).get_table_names())
            _REACTIONS_TABLE_OK = "reactions" in tables
        except Exception:  # инспектор недоступен — считаем схему полной
            _REACTIONS_TABLE_OK = True
    return _REACTIONS_TABLE_OK


def _live_clause() -> str:
    """SQL-предикат «сообщение ещё живо» или заглушка для легаси-схемы."""
    return _LIVE_CLAUSE if _schema_has_expires_at() else "1=1"


class SendMessageRequest(BaseModel):
    type: str = Field(default="text", pattern="^(text|image|file|voice|emoji)$")
    content: str = Field(default="", max_length=4000)
    media_path: str = Field(default="")
    duration: Optional[int] = Field(default=0, description="Длительность аудио в секундах")
    ttl_seconds: Optional[int] = Field(default=None, ge=5, le=86400 * 7)
    view_once: bool = False
    e2e: bool = False
    client_id: Optional[str] = Field(
        default=None, min_length=8, max_length=64,
        description="Идемпотентный ключ клиента: повторная отправка не создаст дубликат",
    )
    # --- Этап 7.4: Ответы (Replies/Quotes) ---
    reply_to_id: Optional[int] = Field(
        default=None, ge=1,
        description="id сообщения-оригинала в ЭТОМ ЖЕ чате; "
                    "валидируется на сервере (существование + принадлежность чату)",
    )


class MessageResponse(BaseModel):
    id: int
    chat_id: int
    sender_id: int
    sender_name: str
    type: str
    content: str
    media_path: Optional[str]
    duration: Optional[int] = 0
    ttl_seconds: Optional[int]
    view_once: bool
    viewed: bool
    e2e: bool
    client_id: Optional[str] = None
    # --- Этап 7.3: Статусы сообщений (sent -> delivered -> read) ---
    status: str = "sent"
    delivered_at: Optional[object] = None
    read_at: Optional[object] = None
    # --- Этап 7.4: Ответы и Реакции ---
    reply_to_id: Optional[int] = None
    reactions: dict = Field(default_factory=dict)
    # v2.0 Пункт 2: абсолютный момент физической смерти сообщения (tz-aware UTC).
    # Клиент использует его для локального таймера автоудаления карточки —
    # даже если WS-событие message_delete потерялось (обход прокси и т.п.).
    expires_at: Optional[object] = None
    created_at: object


class MessagesListResponse(BaseModel):
    messages: List[MessageResponse]
    next_cursor: Optional[int] = None
    has_more: bool


# v2.0 Пункт 2: SQL-предикат «сообщение ещё живо». Исключает из любых
# выдач строки, чей срок истёк, но которые ещё не успел стереть janitor
# (окно между expires_at и следующим тиком <= 10 c). Диалект-безопасно:
# сравнение tz-aware параметра с колонкой одинаково работает на asyncpg
# и aiosqlite; legacy-строки без expires_at фильтруются по created_at+ttl.
_LIVE_CLAUSE = (
    "("
    "(m.expires_at IS NOT NULL AND m.expires_at > :now) "
    "OR (m.expires_at IS NULL AND ("
    "m.ttl_seconds IS NULL "
    "OR datetime(m.created_at, '+' || CAST(m.ttl_seconds AS TEXT) || ' seconds') > :now_text"
    "))"
    ")"
)


def _live_params(now, now_text: str) -> dict:
    return {"now": now, "now_text": now_text}


def _serialize_msg(m: dict, reactions: Optional[dict] = None) -> MessageResponse:
    return MessageResponse(
        id=m["id"],
        chat_id=m["chat_id"],
        sender_id=m["sender_id"],
        sender_name=m.get("sender_name", ""),
        type=m["type"],
        content=m["content"],
        media_path=m["media_path"],
        duration=m.get("duration") or 0,
        ttl_seconds=m["ttl_seconds"],
        view_once=bool(m["view_once"]),
        viewed=bool(m["viewed"]),
        e2e=bool(m.get("e2e")),
        client_id=m.get("client_id"),
        # Этап 7.3: легаси-строки до миграции b7c3d9e1f2a4 имеют status=NULL —
        # наружу отдаём консервативное «sent» (нижняя граница шкалы).
        status=(m.get("status") or MessageStatus.sent.value)
        if isinstance(m.get("status"), (str, type(None)))
        else str(m["status"]),
        delivered_at=m.get("delivered_at"),
        read_at=m.get("read_at"),
        # Этап 7.4: ответы и реакции (легаси-схемы без колонок -> дефолты).
        reply_to_id=m.get("reply_to_id"),
        reactions=reactions if reactions is not None else {},
        expires_at=m.get("expires_at"),
        created_at=m["created_at"],
    )


async def fetch_reactions_batch(message_ids: List[int]) -> dict:
    """Batch-load реакций страницы истории — ОДИН запрос вместо N (анти-N+1).

    Возвращает {message_id: summary-dict}; сообщения без реакций просто
    отсутствуют в словаре (_serialize_msg подставит пустой {}).
    Диалект-безопасно: динамические bind-плейсхолдеры (:m0, :m1...) работают
    одинаково на SQLite и PostgreSQL 16; пустой вход не делает round-trip.
    """
    if not message_ids:
        return {}
    placeholders = ", ".join(f":m{i}" for i in range(len(message_ids)))
    params = {f"m{i}": mid for i, mid in enumerate(message_ids)}
    async with database.get_db() as db:
        rows = await database.aq(
            db,
            f"SELECT message_id AS mid, user_id AS uid, encrypted_payload AS payload "
            f"FROM reactions WHERE message_id IN ({placeholders}) "
            f"ORDER BY message_id, user_id",
            params,
        )
    grouped: dict = {}
    for r in rows:
        per_msg = grouped.setdefault(r["mid"], {})
        per_msg.setdefault(r["payload"], []).append(r["uid"])
    return grouped


@router.get("/chats/{chat_id}/messages", response_model=MessagesListResponse)
async def list_messages(
    chat_id: int,
    limit: int = Query(default=50, ge=1, le=200),
    before_id: Optional[int] = None,
    user: dict = Depends(get_current_user),
):
    """История чата: курсорная пагинация «назад» (before_id = id самого старого
    сообщения предыдущей страницы)."""
    if not await is_chat_member(chat_id, user["id"]):
        raise HTTPException(403, "Вы не участник этого чата")
    now = utc_now()
    async with database.get_db() as db:
        sql = (
            "SELECT m.*, u.display_name AS sender_name "
            "FROM messages m "
            "JOIN users u ON u.id = m.sender_id "
            f"WHERE m.chat_id = :chat_id AND {_live_clause()} "
        )
        params = {"chat_id": chat_id, "fetch_n": limit + 1}
        params.update(_live_params(now, now.strftime("%Y-%m-%d %H:%M:%S")))
        if before_id:
            sql += " AND m.id < :before_id"
            params["before_id"] = before_id
        sql += " ORDER BY m.id DESC LIMIT :fetch_n"

        rows = await database.aq(db, sql, params)

    has_more = len(rows) > limit
    page = rows[:limit]
    if not page:
        return MessagesListResponse(messages=[], next_cursor=None, has_more=False)
    # Анти-N+1 (Этап 7.4): реакции всей страницы — ОДНИМ batch-запросом IN (:ids).
    reactions_map = await fetch_reactions_batch([m["id"] for m in page])
    messages = [
        _serialize_msg(m, reactions=reactions_map.get(m["id"], {}))
        for m in reversed(page)
    ]
    return MessagesListResponse(
        messages=messages,
        next_cursor=page[-1]["id"] if has_more else None,
        has_more=has_more,
    )


@router.get("/chats/{chat_id}/search", response_model=MessagesListResponse)
async def search_messages(
    chat_id: int,
    q: str = Query(..., min_length=2, max_length=100),
    limit: int = Query(default=50, ge=1, le=200),
    before_id: Optional[int] = None,
    user: dict = Depends(get_current_user),
):
    """Полнотекстовый поиск сообщений в чате.

    PostgreSQL: `to_tsvector('russian', ...)` — корректная работа с кириллицей
    (индекс из миграции 5c8d9e0f1a2b). SQLite (self-hosted без PG):
    регистронезависимый LIKE — тоже поддерживает кириллицу.
    """
    if not await is_chat_member(chat_id, user["id"]):
        raise HTTPException(403, "Вы не участник этого чата")

    q_clean = q.strip()
    if not q_clean:
        return MessagesListResponse(messages=[], next_cursor=None, has_more=False)

    async with database.get_db() as db:
        if config.IS_SQLITE:
            where = "LOWER(m.content) LIKE LOWER(:q)"
            params = {"chat_id": chat_id, "q": f"%{q_clean}%"}
        else:
            where = ("to_tsvector('russian', m.content) "
                     "@@ plainto_tsquery('russian', :q)")
            params = {"chat_id": chat_id, "q": q_clean}

        now = utc_now()
        sql = (
            "SELECT m.*, u.display_name AS sender_name "
            "FROM messages m "
            "JOIN users u ON u.id = m.sender_id "
            f"WHERE m.chat_id = :chat_id AND {where} AND {_live_clause()} "
        )
        params["fetch_n"] = limit + 1
        params.update(_live_params(now, now.strftime("%Y-%m-%d %H:%M:%S")))
        if before_id:
            sql += " AND m.id < :before_id"
            params["before_id"] = before_id
        sql += " ORDER BY m.id DESC LIMIT :fetch_n"

        rows = await database.aq(db, sql, params)

    has_more = len(rows) > limit
    page = rows[:limit]
    if not page:
        return MessagesListResponse(messages=[], next_cursor=None, has_more=False)
    messages = [_serialize_msg(m) for m in reversed(page)]
    return MessagesListResponse(
        messages=messages,
        next_cursor=page[-1]["id"] if has_more else None,
        has_more=has_more,
    )


@router.post("/chats/{chat_id}/messages")
async def send_message(
    chat_id: int,
    body: SendMessageRequest,
    request: Request,
    user: dict = Depends(get_current_user),
):
    if not await is_chat_member(chat_id, user["id"]):
        raise HTTPException(403, "Вы не участник этого чата")

    # Антиспам: скользящее окно (Redis-лимитер cluster-safe + счётчик в БД)
    if not await limiter.allow_async(
        user_key("msg", request, user["id"]), config.SPAM_MSG_PER_MINUTE, 60
    ):
        raise HTTPException(429, "Слишком часто отправляете сообщения")

    if not body.content and not body.media_path:
        raise HTTPException(400, "Пустое сообщение")

    # --- Этап 7.4: валидация ответа (Replies/Quotes) ---
    # Бизнес-правило: оригинал обязан существовать и лежать в ЭТОМ ЖЕ чате.
    # Без проверки chat_id клиент мог бы «прицепить» reply к сообщению из
    # чужого чата — утечка метаданных между приватными пространствами.
    if body.reply_to_id is not None:
        async with database.get_db() as db:
            original = await database.aq1(
                db, "SELECT id FROM messages WHERE id=:id AND chat_id=:cid",
                {"id": body.reply_to_id, "cid": chat_id},
            )
        if not original:
            raise HTTPException(400, "Сообщение для ответа не найдено в этом чате")

    now = utc_now()
    # v2.0 Пункт 2: точный абсолютный дедлайн физической смерти сообщения.
    expires_at = now + timedelta(seconds=body.ttl_seconds) if body.ttl_seconds else None
    async with database.get_db() as db:
        # Идемпотентность (Этап 4.5): если client_id уже есть в чате —
        # возвращаем существующее сообщение, дубликат не создаётся.
        if body.client_id:
            dup = await database.aq1(
                db,
                "SELECT m.*, u.display_name AS sender_name FROM messages m "
                "JOIN users u ON u.id=m.sender_id "
                "WHERE m.chat_id=:cid AND m.client_id=:clid",
                {"cid": chat_id, "clid": body.client_id},
            )
            if dup:
                return _serialize_msg(dup)

        # Скобка после "INSERT INTO messages (" закрыта ниже, когда список
        # колонок собран целиком — раньше хвост шаблона сливался с первым
        # именем из columns и получался мусорный колонка-идентификатор.
        insert_sql = "INSERT INTO messages ("
        # Дефект-фикс (Этап 7.4): список колонок и порядок VALUES собираются из
        # ОДНОГО упорядоченного dict — раньше "created_at" попадал в колонки
        # раньше reply_to_id/expires_at, а плейсхолдеры строились по другому
        # порядку, и SQLite связывал параметры позиционно: datetime из
        # created_at уходил в колонку reply_to_id -> FOREIGN KEY constraint
        # failed / ValidationError 'unable to parse string as an integer'.
        insert_params = {
            "chat_id": chat_id,
            "sender_id": user["id"],
            "type": body.type,
            "content": body.content.strip(),
            "media_path": body.media_path,
            "duration": body.duration or 0,
            "ttl_seconds": body.ttl_seconds,
            "view_once": 1 if body.view_once else 0,
            "e2e": 1 if body.e2e else 0,
            "client_id": body.client_id,
            "created_at": now,
        }
        # Колонку reply_to_id добавляет миграция c8d9e0f1a2b3 — на легаси-схемах
        # её нет, поэтому включаем в INSERT только при наличии колонки.
        if _schema_has_reply_to():
            insert_params["reply_to_id"] = body.reply_to_id
        if expires_at is not None and _schema_has_expires_at():
            # v2.0 Пункт 2: абсолютный дедлайн физической смерти сообщения.
            insert_params["expires_at"] = expires_at
        columns = list(insert_params)
        insert_sql += ", ".join(columns) + ") VALUES (" + ", ".join(
            f":{k}" for k in columns
        ) + ")"
        try:
            await db.execute(sql_text(insert_sql), insert_params)
        except IntegrityError:
            # Гонка двух параллельных отправок с одним client_id —
            # победитель уже записал; достаем его сообщение.
            if body.client_id:
                await db.rollback()
                dup = await database.aq1(
                    db,
                    "SELECT m.*, u.display_name AS sender_name FROM messages m "
                    "JOIN users u ON u.id=m.sender_id "
                    "WHERE m.chat_id=:cid AND m.client_id=:clid",
                    {"cid": chat_id, "clid": body.client_id},
                )
                if dup:
                    return _serialize_msg(dup)
            raise

        msg_id_row = await db.execute(
            sql_text("SELECT MAX(id) AS mid FROM messages WHERE chat_id=:cid"), {"cid": chat_id}
        )
        mid = msg_id_row.scalar()
        if mid is None:
            row = await database.aq1(
                db,
                "SELECT id FROM messages WHERE chat_id=:cid AND sender_id=:sid ORDER BY id DESC LIMIT 1",
                {"cid": chat_id, "sid": user["id"]},
            )
            mid = row["id"] if row else None
        msg = await database.aq1(
            db,
            "SELECT m.*, u.display_name AS sender_name FROM messages m "
            "JOIN users u ON u.id = m.sender_id WHERE m.id=:id",
            {"id": mid},
        )
        members = [r["user_id"] for r in await database.aq(
            db, "SELECT user_id FROM chat_members WHERE chat_id=:cid", {"cid": chat_id}
        )]
        sender_label = msg["sender_name"]

    # Реакции не запрашиваем batch'ом: у свежего сообщения их быть не может
    # (FK на messages.id + только что созданный id) — пустой словарь экономит
    # один round-trip к БД в горячем пути отправки.
    payload = {"type": "new_message", "message": _serialize_msg(msg, reactions={})}

    # Доставка ПОСЛЕ коммита транзакции (get_db делает commit на выходе):
    await manager.send_to_users(members, payload)

    # Фоновые push / outbox-fallback
    try:
        for uid in members:
            if uid == user["id"]:
                continue
            if not manager.is_online(uid):
                if body.e2e:
                    push_body = "🔒 Зашифрованное сообщение"
                elif body.type == "image":
                    push_body = "📷 Фотография"
                elif body.type == "file":
                    push_body = "📎 Файл"
                elif body.type == "voice":
                    push_body = "🎙️ Голосовое сообщение"
                else:
                    push_body = (body.content or "")[:120]
                await push_service.send_to_user(
                    uid, sender_label, push_body,
                    {"chat_id": str(chat_id), "message_id": str(msg["id"])},
                )
    except Exception as exc:  # noqa: BLE001 — push не должен ронять отправку
        from loguru import logger
        logger.warning("Push delivery failed: {}", exc.__class__.__name__)

    return payload["message"]


@router.get("/push/poll")
async def push_poll(user: dict = Depends(get_current_user)):
    """Long-polling fallback доставки уведомлений без облачных сервисов (Этап 3.3)."""
    items = await push_service.poll_outbox(user["id"])
    return {"items": items}


@router.post("/messages/{message_id}/view")
async def mark_viewed(message_id: int, user: dict = Depends(get_current_user)):
    async with database.get_db() as db:
        m = await database.aq1(db, "SELECT * FROM messages WHERE id=:id", {"id": message_id})
        if not m:
            raise HTTPException(404, "Сообщение не найдено")
        # v2.0 Пункт 2: истёкшее по TTL сообщение уже физически мертво —
        # не отдаём его контент и не шлём статус прочтения, не дожидаясь
        # следующего тика janitor'а (окно видимости = 0).
        if _schema_has_expires_at() and m.get("expires_at") is not None \
                and as_utc(m["expires_at"]) <= utc_now():
            raise HTTPException(404, "Сообщение не найдено")
        if not await is_chat_member(m["chat_id"], user["id"]):
            raise HTTPException(403, "Нет доступа")
        was_unseen_view_once = bool(m["view_once"]) and not m["viewed"]
        if was_unseen_view_once:
            await db.execute(sql_text("UPDATE messages SET viewed=1 WHERE id=:id"), {"id": message_id})

    payload = {"type": "message_viewed", "message_id": message_id, "chat_id": m["chat_id"]}
    await manager.send_to_user(m["sender_id"], payload)

    if was_unseen_view_once:
        async with database.get_db() as db:
            members = [r["user_id"] for r in await database.aq(
                db, "SELECT user_id FROM chat_members WHERE chat_id=:cid", {"cid": m["chat_id"]}
            )]
        await manager.send_to_users(
            members,
            {"type": "message_delete", "chat_id": m["chat_id"], "message_ids": [message_id]},
        )
    return {"ok": True}


class UpdateStatusRequest(BaseModel):
    """Тело PATCH /messages/{id}/status (Этап 7.3).

    ghost=True — клиентский флаг «призрачного чтения»: сервер применит
    статус не выше delivered (см. _ghost_read_enabled). Флаг является
    дополнением к серверной настройке пользователя: любой из источников
    включает privacy-режим.
    """

    status: str = Field(pattern="^(delivered|read)$")
    ghost: bool = Field(
        default=False,
        description="Не показывать собеседнику синие галочки (read -> delivered)",
    )


# SQL-выражение числового ранга статуса (Этап 7.3). Диалект-безопасно:
# стандартный searched CASE исполняется и SQLite, и PostgreSQL 16.
# Ранги задаются ЯВНО (_STATUS_ORDER/status_rank в models_base.py), потому
# что лексикографический порядок строк НЕ совпадает с жизненным циклом:
# 'delivered' < 'read' < 'sent' — наивное сравнение статусов как строк
# сделало бы базовый 'sent' «больше» всех и сломало переход sent->delivered.
_STATUS_RANK_CASE = "(CASE COALESCE(status, 'sent') " \
                    "WHEN 'sent' THEN 0 WHEN 'delivered' THEN 1 ELSE 2 END)"


async def _ghost_read_enabled(db, user_id: int) -> bool:
    """Серверная настройка Ghost Mode пользователя (privacy-first).

    Хранится в KV-таблице settings под ключом `ghost_read:{user_id}`
    (anyio-совместимое чтение без кеша: редкий путь, только для read).
    Значения '1'/'true' — включено; отсутствие записи — выключено.
    """
    row = await database.aq1(
        db, "SELECT value FROM settings WHERE key=:k", {"k": f"ghost_read:{user_id}"}
    )
    return bool(row) and (row["value"] or "").strip().lower() in ("1", "true", "on", "yes")


@router.patch("/messages/{message_id}/status")
async def update_message_status(
    message_id: int,
    body: UpdateStatusRequest,
    user: dict = Depends(get_current_user),
):
    """Перевод сообщения в статус delivered/read — идемпотентно и атомарно.

    Защита от состояния гонки (read раньше delivered из-за лагов сети)
    строится на одном условном UPDATE «compare-and-set» по ЧИСЛОВОМУ
    рангу статуса, который БД вычисляет на лету через CASE:

        UPDATE messages SET ... WHERE id=:id
          AND (CASE status ... END) < :new_rank   -- ранги: sent=0, deliv=1, read=2

    - Переход возможен ТОЛЬКО вперёд по шкале рангов: запоздалый
      «delivered» (rank 1), прилетевший когда в базе уже «read» (rank 2),
      не удовлетворяет условию 2 < 1 => rowcount=0 => тихий no-op (200 OK,
      changed=False), никакого 500 и никакого отката статуса назад.
    - Идемпотентность повторов: второй «read» при «read» => rowcount=0.
    - Окна между проверкой и записью нет: сравнение и запись выполняются
      одним оператором под row-level lock (PG) / write-lock (SQLite WAL).
    - Ghost Mode: если у читателя включена настройка `ghost_read:{uid}`
      (или клиент прислал ghost=True), целевой статус понижается до
      delivered — «read» в базу не попадает, ответ остаётся 200 OK.
    - WS-событие отправляется только при changed=True и ПОСЛЕ commit
      (паттерн send_message): подписчик не увидит событие о строке,
      которую параллельно удалил janitor.
    """
    async with database.get_db() as db:
        m = await database.aq1(
            db,
            "SELECT chat_id, sender_id, expires_at FROM messages WHERE id=:id",
            {"id": message_id},
        )
        if not m:
            raise HTTPException(404, "Сообщение не найдено")
        # Сгорающее сообщение физически мертво — статусы не принимаем
        # (то же окно видимости = 0, что и в mark_viewed).
        if _schema_has_expires_at() and m.get("expires_at") is not None \
                and as_utc(m["expires_at"]) <= utc_now():
            raise HTTPException(404, "Сообщение не найдено")
        if not await is_chat_member(m["chat_id"], user["id"]):
            raise HTTPException(403, "Нет доступа")
        # Отправляющему нельзя «читать» собственные сообщения — иначе он
        # сам себе выставил бы синие галочки.
        if m["sender_id"] == user["id"]:
            raise HTTPException(403, "Нельзя менять статус своего сообщения")

        now = utc_now()
        target = MessageStatus(body.status)
        # --- Ghost Mode: read превращаем в delivered (тихий 200 OK) ---
        if target is MessageStatus.read and (
            body.ghost or await _ghost_read_enabled(db, user["id"])
        ):
            target = MessageStatus.delivered

        if target is MessageStatus.delivered:
            set_clause = "status = :new_status, delivered_at = :now"
        else:  # read: доставляем и прочитанность, и доставленность разом
            set_clause = (
                "status = :new_status, delivered_at = COALESCE(delivered_at, :now), "
                "read_at = :now"
            )
        result = await db.execute(
            sql_text(
                f"UPDATE messages SET {set_clause} "  # noqa: B907 — константа модуля
                f"WHERE id = :id AND {_STATUS_RANK_CASE} < :new_rank"
            ),
            {
                "id": message_id,
                "new_status": target.value,
                "new_rank": status_rank(target),
                "now": now,
            },
        )
        changed = result.rowcount > 0
        current = await database.aq1(
            db, "SELECT status FROM messages WHERE id=:id", {"id": message_id}
        )

    final_status = (current or {}).get("status") or MessageStatus.sent.value
    if changed:
        # WS — вне транзакции (после commit): событие видит только записанное.
        await manager.send_to_user(
            m["sender_id"],
            {
                "type": "message_status",
                "message_id": message_id,
                "chat_id": m["chat_id"],
                "status": final_status,
                "reader_id": user["id"],
            },
        )
    return {"ok": True, "changed": changed, "status": final_status}


@router.delete("/messages/{message_id}")
async def delete_message(message_id: int, user: dict = Depends(get_current_user)):
    async with database.get_db() as db:
        m = await database.aq1(db, "SELECT * FROM messages WHERE id=:id", {"id": message_id})
        if not m:
            raise HTTPException(404, "Сообщение не найдено")
        if m["sender_id"] != user["id"]:
            raise HTTPException(403, "Удалять можно только свои сообщения")
        # Диалект-безопасный каскад: явную очистку зависимостей выполняем ДО удаления
        # строки, потому что SQLite по умолчанию работает с выключенным
        # PRAGMA foreign_keys и FK-правила SET NULL / CASCADE молча не сработают.
        # На PostgreSQL эти же запросы идемпотентны и лишь дублируют каскад БД.
        if _schema_has_reply_to():
            await db.execute(
                sql_text("UPDATE messages SET reply_to_id=NULL WHERE reply_to_id=:id"),
                {"id": message_id},
            )
        if _reactions_table_exists():
            await db.execute(
                sql_text("DELETE FROM reactions WHERE message_id=:id"), {"id": message_id}
            )
        await db.execute(sql_text("DELETE FROM messages WHERE id=:id"), {"id": message_id})
        members = [r["user_id"] for r in await database.aq(
            db, "SELECT user_id FROM chat_members WHERE chat_id=:cid", {"cid": m["chat_id"]}
        )]

    await manager.send_to_users(
        members, {"type": "message_deleted", "message_id": message_id, "chat_id": m["chat_id"]}
    )
    return {"ok": True}


class ReportRequest(BaseModel):
    message_id: int
    reason: str = Field(default="", max_length=500)


@router.post("/reports")
async def report_message(body: ReportRequest, user: dict = Depends(get_current_user)):
    async with database.get_db() as db:
        m = await database.aq1(db, "SELECT * FROM messages WHERE id=:id", {"id": body.message_id})
        if not m:
            raise HTTPException(404, "Сообщение не найдено")
        if not await is_chat_member(m["chat_id"], user["id"]):
            raise HTTPException(403, "Вы не участник этого чата")
        if m["sender_id"] == user["id"]:
            raise HTTPException(400, "Нельзя пожаловаться на своё сообщение")
        already = await database.aq1(
            db,
            "SELECT id FROM reports WHERE message_id=:mid AND reporter_id=:uid AND status='open'",
            {"mid": body.message_id, "uid": user["id"]},
        )
        if already:
            raise HTTPException(400, "Вы уже пожаловались на это сообщение")
        await db.execute(
            sql_text("INSERT INTO reports (chat_id, message_id, reporter_id, reason) "
                     "VALUES (:cid, :mid, :uid, :reason)"),
            {"cid": m["chat_id"], "mid": m["id"], "uid": user["id"], "reason": body.reason.strip()},
        )
    return {"ok": True, "message": "Жалоба отправлена модератору"}
