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
