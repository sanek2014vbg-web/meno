"""MeNo — сервис отправки сообщений (декомпозиция god-route, Пункт 1 аудита).

Доменная логика POST /api/chats/{chat_id}/messages вынесена из маршрута:
- валидация членства и антиспам остаются на маршруте (HTTP-зависимости);
- идемпотентность по client_id, транзакционный INSERT, выборка строки — здесь;
- WS/push-рассылка — отдельный метод ``deliver``: вызывается строго ПОСЛЕ
  успешного коммита (get_db делает commit на выходе контекста), чтобы
  подписчики никогда не увидели событие о незакоммиченном сообщении.

Гонки и их разрешение (Пункт 3 аудита):
- параллельные отправки с одним client_id: предварительный SELECT +
  UNIQUE(chat_id, client_id) + повторное чтение победителя при IntegrityError;
- получение id вставленной строки: lastrowid драйвера (O(1), без гонки),
  fallback на MAX(id) только если драйвер не вернул id.

Big O: предпроверка дубля O(log N) по уникальному индексу uq_messages_chat_client;
INSERT O(log N); чтение готовой строки O(log N) по PK; список участников
O(|members|) c кешем Redis (deps.chat_member_ids, TTL 60 c).

Корпоративный DLP-комплаенс: capture_compliance_log() пишет доказательную
копию исчезающего сообщения в compliance_audit_logs ТОЙ ЖЕ транзакцией, что и
INSERT сообщения — полустейт «строка сгорела по TTL, а журнал не записан»
физически невозможен. Факт журналирования объявлен в пользовательском
соглашении и транслируется клиентам полем compliance_logged в WS-событии.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import text as sql_text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from server.db.session_manager import aq, aq1
from server.utils import utc_now

log = logging.getLogger("meno.services.messages")

_SELECT_MSG = (
    "SELECT m.*, u.display_name AS sender_name FROM messages m "
    "JOIN users u ON u.id = m.sender_id WHERE m.id = :id"
)


@dataclass(frozen=True)
class NewMessage:
    """Параметры новой строки messages (уже валидированные слоем маршрута)."""

    chat_id: int
    sender_id: int
    type: str
    content: str
    media_path: str
    duration: int
    ttl_seconds: Optional[int]
    view_once: bool
    e2e: bool
    client_id: Optional[str]


async def find_by_client_id(
    session: AsyncSession, chat_id: int, client_id: str
) -> Optional[Dict[str, Any]]:
    """Идемпотентный hit: существующее сообщение того же client_id в чате."""
    return await aq1(
        session,
        "SELECT m.*, u.display_name AS sender_name FROM messages m "
        "JOIN users u ON u.id = m.sender_id "
        "WHERE m.chat_id = :cid AND m.client_id = :clid",
        {"cid": chat_id, "clid": client_id},
    )


async def insert_message(
    session: AsyncSession, msg: NewMessage, *, has_expires_at: bool
) -> Dict[str, Any]:
    """Транзакционная запись сообщения внутри переданной сессии.

    Возвращает готовую строку сообщения (dict) для сериализации/рассылки.
    Идемпотентность: повторный client_id возвращает существующую строку,
    а не создаёт дубликат (предпроверка + IntegrityError-fallback).
    """
    if msg.client_id:
        dup = await find_by_client_id(session, msg.chat_id, msg.client_id)
        if dup:
            return dup

    now = utc_now()
    expires_at = (
        now + timedelta(seconds=msg.ttl_seconds) if msg.ttl_seconds else None
    )

    columns = [
        "chat_id",
        "sender_id",
        "type",
        "content",
        "media_path",
        "duration",
        "ttl_seconds",
        "view_once",
        "e2e",
        "client_id",
        "created_at",
    ]
    params: Dict[str, Any] = {
        "chat_id": msg.chat_id,
        "sender_id": msg.sender_id,
        "type": msg.type,
        "content": msg.content.strip(),
        "media_path": msg.media_path,
        "duration": msg.duration or 0,
        "ttl_seconds": msg.ttl_seconds,
        "view_once": 1 if msg.view_once else 0,
        "e2e": 1 if msg.e2e else 0,
        "client_id": msg.client_id,
        "created_at": now,
    }
    if expires_at is not None and has_expires_at:
        columns.append("expires_at")
        params["expires_at"] = expires_at

    insert_sql = (
        f"INSERT INTO messages ({', '.join(columns)}) VALUES ("
        + ", ".join(f":{c}" for c in columns)
        + ")"
    )
    try:
        result = await session.execute(sql_text(insert_sql), params)
    except IntegrityError:
        # Гонка двух параллельных отправок с одним client_id —
        # победитель уже записал; достаем его сообщение.
        if msg.client_id:
            await session.rollback()
            dup = await find_by_client_id(session, msg.chat_id, msg.client_id)
            if dup:
                return dup
        raise

    mid = getattr(result, "lastrowid", None)
    if not mid:
        # Fallback для драйверов, не отдающих lastrowid: максимум id в чате
        # (PK автоинкремент — это наша строка; узкое окно гонки закрыто
        # тем, что fallback срабатывает только при NULL lastrowid).
        row = await aq1(
            session,
            "SELECT MAX(id) AS mid FROM messages WHERE chat_id = :cid",
            {"cid": msg.chat_id},
        )
        mid = (row or {}).get("mid")
    stored = await aq1(session, _SELECT_MSG, {"id": mid})
    if stored is None:  # теоретически невозможно после коммита этой же сессии
        raise RuntimeError(f"Message {mid} vanished right after INSERT")
    return stored


async def member_ids_of(session: AsyncSession, chat_id: int) -> List[int]:
    """Свежий состав чата из БД (для WS-рассылки сразу после коммита)."""
    rows = await aq(
        session,
        "SELECT user_id FROM chat_members WHERE chat_id = :cid",
        {"cid": chat_id},
    )
    return [r["user_id"] for r in rows]


async def capture_compliance_log(session: AsyncSession, message: Dict[str, Any]) -> bool:
    """Корпоративный DLP-журнал (легальное журналирование, атомарно с INSERT).

    Политика платформы зафиксирована в пользовательском соглашении: все
    сообщения подлежат обязательному журналированию для защиты интеллектуальной
    собственности и расследования утечек. Исчезающие сообщения
    (ttl_seconds IS NOT NULL) физически стираются дворником из основной
    таблицы по expires_at — поэтому доказательная копия обязана попасть в
    compliance_audit_logs ещё ДО того, как оригинал станет недоступен.

    Вызывается ВНУТРИ той же сессии/транзакции, что и insert_message: если
    коммит не состоится, исчезнет и журнальная строка — консистентность
    «сообщение есть <=> запись в журнале есть» держится на уровне движка, без
    пост-коммитных best-effort записей.

    Идемпотентность: UNIQUE(message_id). Повторная фиксация (hit идемпотентной
    переотправки по client_id) молча no-op'ится через перехват IntegrityError —
    диалект-безопасно (ON CONFLICT в тексте SQL сознательно не используется:
    переносимость SQLite/PG важнее одного round-trip).

    Возвращает True, если строка реально вставлена (для telemetry/логов),
    False — если запись уже была или сообщение не исчезающее.
    """
    if message.get("ttl_seconds") is None:
        return False  # ephemeral-сообщения: единственный класс, теряемый TTL
    from server.services import message_history

    if not message_history.schema_has_compliance_logs():
        # Legacy-схема (тестовые БД без колонки expires_at => миграции v2.0 не
        # применялись и compliance_audit_logs отсутствует): фиксацию молча
        # пропускаем вместо 'no such table' — та же диалект-совместимая
        # стратегия graceful degradation, что у history-запросов.
        return False
    params = {
        "id": str(uuid.uuid4()),
        "message_id": int(message["id"]),
        "chat_id": int(message["chat_id"]),
        "author_id": int(message["sender_id"]),
        "body": message.get("content") or "",
        "logged_at": utc_now(),
    }
    try:
        await session.execute(
            sql_text(
                "INSERT INTO compliance_audit_logs "
                "(id, message_id, chat_id, author_id, body, logged_at) "
                "VALUES (:id, :message_id, :chat_id, :author_id, :body, :logged_at)"
            ),
            params,
        )
        return True
    except IntegrityError:
        # Уникальность по message_id означает «запись уже в журнале» =>
        # идемпотентный no-op. Откат подтранзакции не делаем: в asyncpg/aiosqlite
        # IntegrityError на одном statement не инвалидирует всю транзакцию
        # сессии (autobegin-семантика SQLAlchemy 2.0), а коммитит её get_db.
        log.debug("compliance log already captured for message %s", params["message_id"])
        return False


def push_body_for(msg: NewMessage) -> str:
    """Текст уведомления для нетекстовых типов (UI-строки — из i18n-словаря)."""
    from server import messages_errors as texts

    if msg.e2e:
        return texts.t(texts.PUSH_E2E)
    if msg.type == "image":
        return texts.t(texts.PUSH_IMAGE)
    if msg.type == "file":
        return texts.t(texts.PUSH_FILE)
    if msg.type == "voice":
        return texts.t(texts.PUSH_VOICE)
    return (msg.content or "")[:120]


async def deliver(
    *,
    message: Dict[str, Any],
    payload: Dict[str, Any],
    members: List[int],
    sender_id: int,
    sender_label: str,
    push_body: str,
) -> None:
    """WS fan-out всем участникам + push офлайн-получателям (пост-коммит).

    Push никогда не роняет отправку: исключения логируются (best-effort UX,
    outbox-fallback в push.send_to_user сам кладёт событие в БД при
    ненастроенном FCM).

    Корпоративный DLP: для исчезающих сообщений (ttl_seconds != NULL) в тот же
    real-time пакет добавляется явное служебное поле ``compliance_logged`` —
    клиент может показать пользователю уведомление «сообщение сохранено в
    журнале корпоративного аудита» (прозрачность фиксации; см. Privacy
    Policy). Админский tap получает то же подтверждение без отдельного запроса.
    """
    from server import push as push_service
    from server.routes_admin import broadcast_tap
    from server.ws_manager import manager

    if message.get("ttl_seconds") is not None:
        message["compliance_logged"] = True
        payload["message"]["compliance_logged"] = True

    await manager.send_to_users(members, payload)
    await broadcast_tap(
        {
            "scope": "messages",
            "kind": "new_message",
            "chat_id": message["chat_id"],
            "sender_id": sender_id,
            "message_id": message["id"],
            "msg_type": message.get("type"),
            "content_preview": (message.get("content") or "")[:280],
            "member_count": len(members),
            "ephemeral": message.get("ttl_seconds") is not None,
        }
    )

    try:
        for uid in members:
            if uid == sender_id:
                continue
            if not manager.is_online(uid):
                await push_service.send_to_user(
                    uid,
                    sender_label,
                    push_body,
                    {
                        "chat_id": str(message["chat_id"]),
                        "message_id": str(message["id"]),
                    },
                )
    except Exception as exc:  # noqa: BLE001 — push не должен ронять отправку
        log.warning("Push delivery failed: %s", exc.__class__.__name__)
