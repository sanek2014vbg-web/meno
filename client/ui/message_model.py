"""MeNo — внутренняя модель сообщения и status-хелперы (ui.message_model).

Вынесено из chat_ui.py в рамках Фазы 5 (рефакторинг UI):
- MessageStatus — жизненный цикл сообщения (sending/sent/delivered/read/failed);
- Message       — единая внутренняя модель сообщения клиента.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import flet as ft

# ---------------------------------------------------------------------------
# Константы
# ---------------------------------------------------------------------------

QUICK_REACTIONS = ["👍", "❤️", "😂", "😮", "😢", "🙏"]
MAX_EDIT_WINDOW_SECONDS = 24 * 3600  # окно редактирования — сутки
SAFETY_NUMBER_GROUPS = 12  # 12 групп по 5 цифр = 60 цифр


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value: Optional[str]) -> datetime:
    """Парсит ISO/«Y-m-d H:M:S» строки сервера в tz-aware UTC."""
    if not value:
        return _now_utc()
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return _now_utc()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _fmt_time(dt: datetime) -> str:
    return dt.astimezone().strftime("%H:%M")


# ---------------------------------------------------------------------------
# E2EE-реакции (Этап 7.4): клиент шифрует эмодзи ключом чата (AES-GCM),
# сервер хранит и ретранслирует только непрозрачный blob.
# ---------------------------------------------------------------------------

#: Короткий префикс — отличает наш формат blob'а от мусора/легаси-строк.
REACTION_BLOB_PREFIX = "rx1:"


def encrypt_reaction_payload(chat_key: bytes, emoji: str) -> str:
    """Эмодзи -> AES-GCM blob (base64url) для POST /messages/{id}/reactions."""
    import base64

    import crypto

    sealed = crypto.encrypt_text(chat_key, emoji)
    b64url = base64.urlsafe_b64encode(sealed.encode()).decode().rstrip("=")
    return f"{REACTION_BLOB_PREFIX}{b64url}"


def decrypt_reaction_blob(chat_key: Optional[bytes], blob: str) -> Optional[str]:
    """Blob -> эмодзи; None при отсутствии ключа или битом содержимом.

    Дешифровка локальна и best-effort: чужой/повреждённый blob никогда не
    должен уронить UI (сообщение отрисуется без этой реакции).
    """
    if chat_key is None or not blob or not blob.startswith(REACTION_BLOB_PREFIX):
        return None
    try:
        import base64

        import crypto

        body = blob[len(REACTION_BLOB_PREFIX):]
        padded = body + "=" * (-len(body) % 4)
        sealed = base64.urlsafe_b64decode(padded.encode()).decode()
        return crypto.decrypt_text(chat_key, sealed)
    except Exception:
        return None


def apply_reaction_summary(
    message: "Message",
    summary: dict,
    chat_key: Optional[bytes],
) -> bool:
    """Серверный summary {blob: [user_id,...]} -> локальные реакции сообщения.

    Возвращает True, если набор реакций реально изменился (нужна
    перерисовка ряда). Это единственная точка, где зашифрованные реакции
    превращаются в человекочитаемые эмодзи на клиенте.
    """
    rebuilt: dict[str, set[int]] = {}
    for blob, users in (summary or {}).items():
        emoji = decrypt_reaction_blob(chat_key, str(blob))
        if emoji is None:
            continue  # нет ключа / мусор — молча деградируем
        rebuilt.setdefault(emoji, set()).update(int(u) for u in users)
    changed = rebuilt != message.reactions
    message.reactions = rebuilt
    return changed


# ---------------------------------------------------------------------------
# Модель данных
# ---------------------------------------------------------------------------


class MessageStatus(str, Enum):
    SENDING = "sending"
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"
    FAILED = "failed"


STATUS_GLYPH: dict[MessageStatus, str] = {
    MessageStatus.SENDING: "🕓",
    MessageStatus.SENT: "✓",
    MessageStatus.DELIVERED: "✓✓",
    MessageStatus.READ: "✓✓",
    MessageStatus.FAILED: "⚠",
}

# ---------------------------------------------------------------------------
# «Живая галочка» (Этап 7.3, Спринт 3): маппинг статуса -> Material-иконка
# ---------------------------------------------------------------------------

#: Линейный жизненный цикл статусов сервера (отправленное в прошлое поле).
_STATUS_FLOW: tuple[MessageStatus, ...] = (
    MessageStatus.SENT,
    MessageStatus.DELIVERED,
    MessageStatus.READ,
)


def status_icon(status: MessageStatus) -> str:
    """Чистая изолированная функция: MessageStatus -> имя иконки ft.Icons.

    sent -> CHECK (одна серая галочка);
    delivered/read -> DONE_ALL (две галочки; цвет задаёт status_icon_color).
    Локальные pre/post-состояния клиента (sending/failed) сохраняют свою
    семантику: 🕓/⚠ рисуются через STATUS_GLYPH, для иконок — часы и ошибка.
    """
    return {
        # SCHEDULE_OUTLINED (часы) — в installed Flet нет CLOCK_OUTLINED;
        # семантика «в очереди на отправку» сохраняется.
        MessageStatus.SENDING: ft.Icons.SCHEDULE_OUTLINED,
        MessageStatus.SENT: ft.Icons.CHECK,
        MessageStatus.DELIVERED: ft.Icons.DONE_ALL,
        MessageStatus.READ: ft.Icons.DONE_ALL,
        MessageStatus.FAILED: ft.Icons.ERROR_OUTLINE,
    }[status]


def status_icon_color(status: MessageStatus, sub_color: str, read_color: str) -> str:
    """Цвет галочки: read — акцентный синий, всё остальное — приглушённый."""
    return read_color if status is MessageStatus.READ else sub_color


def next_status(current: MessageStatus, incoming: MessageStatus) -> MessageStatus:
    """Монотонный merge двух статусов: побеждает более поздний по циклу.

    События WS могут прилетать в произвольном порядке (лаги сети), поэтому
    клиентский статус никогда не откатывается назад: sent(0)->delivered(1)->
    read(2). Локальные состояния SENDING/FAILED вне цикла — возвращаем их
    как есть, если ни один из статусов не принадлежит потоку.
    """
    cur_rank = _STATUS_FLOW.index(current) if current in _STATUS_FLOW else -1
    inc_rank = _STATUS_FLOW.index(incoming) if incoming in _STATUS_FLOW else -1
    return incoming if inc_rank > cur_rank else current


@dataclass
class Message:
    """Единая внутренняя модель сообщения клиента."""

    id: Optional[int]
    chat_id: int
    sender_id: int
    text: str
    created_at: datetime = field(default_factory=_now_utc)
    edited_at: Optional[datetime] = None
    # v2.0 Пункт 2: абсолютный момент физической смерти сообщения (tz-aware UTC).
    # NULL => сообщение не сгорает. Используется локальным таймером-страховкой:
    # даже если WS-событие message_delete потерялось, карточка исчезнет сама.
    expires_at: Optional[datetime] = None
    status: MessageStatus = MessageStatus.SENDING
    reactions: dict[str, set[int]] = field(default_factory=dict)  # emoji -> user_ids
    reply_to_id: Optional[int] = None
    reply_preview: Optional[str] = None
    read_by: set[int] = field(default_factory=set)
    failed: bool = False
    # Этап 7.3 «Живая галочка»: back-link на отрисованный MessageRow
    # (исключительно для O(1)-замены строки черновика при подтверждении;
    # repr/eq по умолчанию не трогаем — поле compare=False).
    _row: object = field(default=None, repr=False, compare=False)

    @classmethod
    def from_server(cls, raw: dict, my_id: int) -> "Message":
        """Конвертирует ответ API (/messages, WS event) во внутреннюю модель."""
        reactions: dict[str, set[int]] = {}
        for r in raw.get("reactions") or []:
            reactions.setdefault(r["emoji"], set()).add(int(r["user_id"]))
        read_by = {int(u) for u in (raw.get("read_by") or [])}
        status = cls._status_from_raw(raw, my_id, read_by)
        return cls(
            id=raw.get("id"),
            chat_id=int(raw.get("chat_id", 0)),
            sender_id=int(raw.get("sender_id", 0)),
            text=raw.get("text", ""),
            created_at=_parse_ts(raw.get("created_at")),
            edited_at=_parse_ts(raw["edited_at"]) if raw.get("edited_at") else None,
            expires_at=_parse_ts(raw["expires_at"]) if raw.get("expires_at") else None,
            status=status,
            reactions=reactions,
            reply_to_id=raw.get("reply_to_id"),
            reply_preview=(raw.get("reply") or {}).get("preview"),
            read_by=read_by,
        )

    @staticmethod
    def _status_from_raw(raw: dict, my_id: int, read_by: set[int]) -> MessageStatus:
        if raw.get("failed"):
            return MessageStatus.FAILED
        if int(raw.get("sender_id", -1)) == my_id:
            if read_by - {my_id}:
                return MessageStatus.READ
            if raw.get("delivered"):
                return MessageStatus.DELIVERED
            return MessageStatus.SENT
        return MessageStatus.READ if my_id in read_by else MessageStatus.DELIVERED

    @property
    def can_edit(self) -> bool:
        return (
            self.status is not MessageStatus.SENDING
            and not self.failed
            and (_now_utc() - self.created_at).total_seconds()
            <= MAX_EDIT_WINDOW_SECONDS
        )
