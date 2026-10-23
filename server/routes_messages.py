"""MeNo — маршруты сообщений: тонкий HTTP-слой поверх сервисов (аудит, Пункт 1).

Доменная логика декомпозирована в server/services/:
- message_history  — курсорная страница истории и диалект-адаптивный поиск;
- message_send     — идемпотентная отправка + post-commit WS/push доставка;
- message_view     — атомарный CAS «прочитано» для view-once;
- message_moderation — условное удаление по владельцу и жалобы.

На слое маршрута остаются ТОЛЬКО HTTP-зависимости: схема запроса/ответа,
аутентификация (get_current_user), проверка членства (is_chat_member),
антиспам-лимитер, маппинг доменных исходов в коды ответов и i18n-тексты
сообщений об ошибках (server.messages_errors).

Инварианты, унаследованные от god-route версии (сохранены намеренно):
- response_model и имена полей не менялись ни на символ — контракт API
  стабилен для Flet-клиента;
- события WS/push публикуются строго ПОСЛЕ коммита транзакции (post-commit
  invariant проекта); get_db делает commit на выходе контекста;
- все SQL параметризован; динамических фрагментов из пользовательского
  ввода нет (поиск передаётся только как bind-параметр :q).

Big O (для всей поверхности маршрута): история/поиск — index seek
(chat_id,id) DESC LIMIT n+1 → O(log N + limit); отправка — O(log N) предпроверка
идемпотентности + INSERT; просмотр/удаление/жалоба — O(log N) PK-seek'ы.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from server import config, messages_errors as texts
from server import push as push_service
from server.db.session_manager import get_db
from server.deps import get_current_user, is_chat_member
from server.rate_limit import limiter, user_key
from server.services import (
    message_history,
    message_moderation,
    message_send,
    message_view,
)
from server.utils import as_utc

log = logging.getLogger("meno.routes.messages")

router = APIRouter(prefix="/api", tags=["messages"])


class SendMessageRequest(BaseModel):
    type: str = Field(default="text", pattern="^(text|image|file|voice|emoji)$")
    content: str = Field(default="", max_length=4000)
    media_path: str = Field(default="")
    duration: Optional[int] = Field(
        default=0, description="Длительность аудио в секундах"
    )
    ttl_seconds: Optional[int] = Field(default=None, ge=5, le=86400 * 7)
    view_once: bool = False
    e2e: bool = False
    client_id: Optional[str] = Field(
        default=None,
        min_length=8,
        max_length=64,
        description="Идемпотентный ключ клиента: повторная отправка не создаст дубликат",
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
    # v2.0 Пункт 2: абсолютный момент физической смерти сообщения (tz-aware UTC).
    # Клиент использует его для локального таймера автоудаления карточки —
    # даже если WS-событие message_delete потерялось (обход прокси и т.п.).
    expires_at: Optional[object] = None
    created_at: object
    # Корпоративный DLP-комплаенс: ЯВНОЕ (не скрытое!) поле факта журналирования.
    # Для исчезающих сообщений deliver() выставляет его в True перед WS fan-out,
    # и оно попадает в real-time payload — клиент обязан показать пользователю
    # уведомление о фиксации в журнале аудита (требование прозрачности; см.
    # Privacy Policy). В HTTP-ответах (история/отправка) всегда False: запись
    # в журнал создаётся атомарно с INSERT, но подтверждение доставляется
    # только через управляемый WS-канал, чтобы не менять публичный REST-контракт.
    compliance_logged: bool = False


class MessagesListResponse(BaseModel):
    messages: List[MessageResponse]
    next_cursor: Optional[int] = None
    has_more: bool


class ReportRequest(BaseModel):
    message_id: int
    reason: str = Field(default="", max_length=500)


def _iso_utc(dt) -> Optional[str]:
    """datetime/ISO-строка из БД → канонический ISO-8601 UTC (или None).

    Дефект-фикс v1.0.0 (WS fan-out тест): колонки created_at/expires_at на
    SQLite возвращаются драйвером как datetime или TEXT в зависимости от пути
    записи. Нормализация ДО публикации гарантирует одинаковый wire-формат
    payload для PostgreSQL и SQLite — потребители WS видят только строку.
    """
    parsed = as_utc(dt)
    return parsed.isoformat() if parsed is not None else None


def _serialize_msg(m: dict) -> MessageResponse:
    """ORM-dict → публичная схема ответа (поля и формат — контракт API).

    Поле compliance_logged заполняется из runtime-словаря сообщения: в HTTP-
    ответах всегда False (колонки в messages нет), а deliver() перед WS
    fan-out выставляет True для исчезающих сообщений — явное уведомление о
    фиксации в журнале корпоративного аудита (прозрачность DLP).
    """
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
        expires_at=_iso_utc(m.get("expires_at")),
        created_at=_iso_utc(m["created_at"]) or "",
        compliance_logged=bool(m.get("compliance_logged")),
    )


def _page_response(rows: List[dict], limit: int) -> MessagesListResponse:
    """Курсорная нарезка over-fetch страницы: has_more = len(rows) > limit."""
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
        raise HTTPException(403, texts.t(texts.NOT_CHAT_MEMBER))
    async with get_db() as db:
        rows = await message_history.fetch_page(db, chat_id, limit=limit, before_id=before_id)
    return _page_response(rows, limit)


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
    (GIN-индекс миграции e6f7a8b9cafe). SQLite (self-hosted без PG):
    регистронезависимый LIKE — тоже поддерживает кириллицу.
    """
    if not await is_chat_member(chat_id, user["id"]):
        raise HTTPException(403, texts.t(texts.NOT_CHAT_MEMBER))

    q_clean = q.strip()
    if not q_clean:
        return MessagesListResponse(messages=[], next_cursor=None, has_more=False)

    where, extra_params = message_history.search_predicate(q_clean)
    async with get_db() as db:
        rows = await message_history.fetch_page(
            db,
            chat_id,
            limit=limit,
            before_id=before_id,
            extra_where=where,
            extra_params=extra_params,
        )
    return _page_response(rows, limit)


@router.post("/chats/{chat_id}/messages")
async def send_message(
    chat_id: int,
    body: SendMessageRequest,
    request: Request,
    user: dict = Depends(get_current_user),
):
    """Идемпотентная отправка: запись в транзакции, WS/push — после коммита."""
    if not await is_chat_member(chat_id, user["id"]):
        raise HTTPException(403, texts.t(texts.NOT_CHAT_MEMBER))

    # Антиспам: скользящее окно (Redis-лимитер cluster-safe + счётчик в БД)
    if not await limiter.allow_async(
        user_key("msg", request, user["id"]), config.SPAM_MSG_PER_MINUTE, 60
    ):
        raise HTTPException(429, texts.t(texts.SPAM_LIMIT))

    if not body.content and not body.media_path:
        raise HTTPException(400, texts.t(texts.EMPTY_MESSAGE))

    new_msg = message_send.NewMessage(
        chat_id=chat_id,
        sender_id=user["id"],
        type=body.type,
        content=body.content,
        media_path=body.media_path,
        duration=body.duration or 0,
        ttl_seconds=body.ttl_seconds,
        view_once=body.view_once,
        e2e=body.e2e,
        client_id=body.client_id,
    )

    async with get_db() as db:
        msg = await message_send.insert_message(
            db, new_msg, has_expires_at=message_history.schema_has_expires_at()
        )
        # Корпоративный DLP: исчезающее сообщение копируется в
        # compliance_audit_logs ЭТОЙ ЖЕ транзакцией (атомарно с INSERT выше) —
        # дворник сотрёт строку messages по expires_at, доказательная копия
        # останется в журнале комплаенса. Для не-ephemeral сообщений no-op за O(1).
        await message_send.capture_compliance_log(db, msg)
        members = await message_send.member_ids_of(db, chat_id)

    payload = {"type": "new_message", "message": _serialize_msg(msg)}

    # Доставка СТРОГО после коммита (get_db сделал commit на выходе контекста):
    # подписчики никогда не увидят событие о незакоммиченном сообщении.
    await message_send.deliver(
        message=msg,
        payload=payload,
        members=members,
        sender_id=user["id"],
        sender_label=msg["sender_name"],
        push_body=message_send.push_body_for(new_msg),
    )
    return payload["message"]


@router.get("/push/poll")
async def push_poll(user: dict = Depends(get_current_user)):
    """Long-polling fallback доставки уведомлений без облачных сервисов (Этап 3.3)."""
    items = await push_service.poll_outbox(user["id"])
    return {"items": items}


@router.post("/messages/{message_id}/view")
async def mark_viewed(message_id: int, user: dict = Depends(get_current_user)):
    """Отметка прочтения; первый просмотр view-once запускает самоудаление.

    Гонка двух параллельных «прочитал» закрыта условным UPDATE внутри
    message_view.mark_viewed_atomically (Пункт 3 аудита): событие
    message_delete публикует ровно один победитель.
    """
    async with get_db() as db:
        m = await message_view.load_live_message(
            db, message_id, has_expires_at=message_history.schema_has_expires_at()
        )
        if m is None:
            raise HTTPException(404, texts.t(texts.MSG_NOT_FOUND))
        if not await is_chat_member(m["chat_id"], user["id"]):
            raise HTTPException(403, texts.t(texts.NO_ACCESS))
        first_view = False
        if m["view_once"] and not m["viewed"]:
            first_view = await message_view.mark_viewed_atomically(db, message_id)
        members = await message_view.chat_members(db, m["chat_id"]) if first_view else []

    # Post-commit: статус прочтения автору — всегда; самоудаление — только
    # победителю гонки unseen->seen.
    await message_view.publish_view_events(m, members if first_view else [])
    return {"ok": True}


@router.delete("/messages/{message_id}")
async def delete_message(message_id: int, user: dict = Depends(get_current_user)):
    """Удаление собственного сообщения (условный DELETE по владельцу в WHERE)."""
    async with get_db() as db:
        m = await message_moderation.load_message(db, message_id)
        if m is None:
            raise HTTPException(404, texts.t(texts.MSG_NOT_FOUND))
        deleted = await message_moderation.delete_own_message_atomically(
            db, message_id, user["id"]
        )
        if not deleted:
            # Строка исчезла между SELECT и DELETE (параллельное удаление /
            # janitor) либо принадлежит другому автору — проверяем причину.
            current = await message_moderation.load_message(db, message_id)
            if current is not None and current["sender_id"] != user["id"]:
                raise HTTPException(403, texts.t(texts.DELETE_FOREIGN))
            raise HTTPException(404, texts.t(texts.MSG_NOT_FOUND))
        members = await message_moderation.chat_members(db, m["chat_id"])

    await message_moderation.publish_delete_event(m, members)
    return {"ok": True}


@router.post("/reports")
async def report_message(body: ReportRequest, user: dict = Depends(get_current_user)):
    """Жалоба на сообщение модератору (только чужие сообщения, без дублей)."""
    async with get_db() as db:
        m = await message_moderation.load_message(db, body.message_id)
        if m is None:
            raise HTTPException(404, texts.t(texts.MSG_NOT_FOUND))
        if not await is_chat_member(m["chat_id"], user["id"]):
            raise HTTPException(403, texts.t(texts.NOT_CHAT_MEMBER))
        if m["sender_id"] == user["id"]:
            raise HTTPException(400, texts.t(texts.REPORT_SELF))
        if await message_moderation.has_open_report(db, body.message_id, user["id"]):
            raise HTTPException(400, texts.t(texts.REPORT_DUPLICATE))
        await message_moderation.insert_report(
            db,
            chat_id=m["chat_id"],
            message_id=m["id"],
            reporter_id=user["id"],
            reason=body.reason,
        )
    return {"ok": True, "message": texts.t(texts.REPORT_SENT)}
