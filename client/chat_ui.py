"""MeNo — фасад модульного UI чата (Этап 7.3, рефакторинг Фазы 5).

Исторически этот файл был монолитом на 1100+ строк. Теперь он выполняет
только три задачи:
1. инициализацию/сборку макета экрана чата через компоненты пакета ``ui``;
2. роутинг входящих WS-событий в активный экран (ChatScreen.handle_event);
3. сохранение плоского публичного API (re-export), чтобы существующие
   импорты ``from chat_ui import ...`` продолжали работать без изменений.

Компоненты:
- ui/auth_view.py    — экран входа/регистрации + TOTP/2FA;
- ui/chat_list.py    — боковая панель списка чатов с поиском;
- ui/message_area.py — область сообщений, typing indicator, вложения, диалоги;
- ui/message_model.py— внутренняя модель Message/MessageStatus.
"""

from __future__ import annotations

from typing import Optional

import flet as ft

from ui.message_model import (
    MAX_EDIT_WINDOW_SECONDS,
    QUICK_REACTIONS,
    SAFETY_NUMBER_GROUPS,
    STATUS_GLYPH,
    Message,
    MessageStatus,
)
from ui.message_area import (
    ChatScreen,
    EditDialog,
    ReactionPicker,
    ReplyPreview,
    SafetyNumberDialog,
    TypingIndicator,
    compute_safety_number,
    fingerprint_from_public_key,
)

__all__ = [
    "ChatAppShell",
    "ChatScreen",
    "Message",
    "MessageStatus",
    "EditDialog",
    "ReactionPicker",
    "ReplyPreview",
    "SafetyNumberDialog",
    "TypingIndicator",
    "compute_safety_number",
    "fingerprint_from_public_key",
    "QUICK_REACTIONS",
    "STATUS_GLYPH",
    "MAX_EDIT_WINDOW_SECONDS",
    "SAFETY_NUMBER_GROUPS",
]


class ChatAppShell:
    """Сборка макета и маршрутизация: связывает api/crypto-слой приложения
    с модульными компонентами интерфейса.

    Ожидается объект ``app`` с атрибутами:
    - .page  — ft.Page;
    - .api   — ApiClient;
    - .me    — dict c id/username текущего пользователя.
    """

    def __init__(self, app) -> None:
        self.app = app
        self.active_screen: Optional[ChatScreen] = None

    async def open_chat(self, chat: dict) -> ft.Control:
        """Открывает экран чата и делает его активным адресатом WS-событий."""
        screen = ChatScreen(self.app, chat)
        control = await screen.build()
        self.active_screen = screen
        return control

    def close_chat(self) -> None:
        self.active_screen = None

    def route_event(self, ev: dict) -> None:
        """Маршрутизирует входящее WebSocket-событие в активный экран чата."""
        if self.active_screen is not None:
            self.active_screen.handle_event(ev)
