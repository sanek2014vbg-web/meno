"""MeNo — область отображения сообщений (ui.message_area).

Вынесено из chat_ui.py в рамках Фазы 5 (рефакторинг UI):
- переиспользуемые виджеты: EditDialog / ReactionPicker / ReplyPreview /
  SafetyNumberDialog / TypingIndicator;
- E2E-верификация: fingerprint_from_public_key / compute_safety_number;
- контроллер экрана ChatScreen (логика скролла, отправка, WS-события).

Зависимости от приложения минимальны и документированы через протоколы:
app.page — ft.Page, app.api — ApiClient, app.crypto — локальное E2E-хранилище ключей.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import time
import uuid
from typing import Awaitable, Callable, Optional

import flet as ft

import crypto
import themes
from ui.message_model import (
    QUICK_REACTIONS,
    SAFETY_NUMBER_GROUPS,
    STATUS_GLYPH,
    Message,
    MessageStatus,
    _fmt_time,
    _now_utc,
    _parse_ts,
)


# ---------------------------------------------------------------------------
# E2E-верификация: Safety Numbers
# ---------------------------------------------------------------------------


def fingerprint_from_public_key(pub_b64: str) -> bytes:
    """SHA-256 от сырых 32 байт X25519 публичного ключа."""
    raw = base64.b64decode(pub_b64)
    return hashlib.sha256(raw).digest()


def compute_safety_number(my_pub_b64: str, peer_pub_b64: str) -> str:
    """Детерминированный 60-значный Safety Number пары участников.

    Байты отсортированных отпечатков конкатенируются, чтобы оба собеседника
    вычисляли идентичное число независимо от порядка аргументов.
    """
    fp_a = fingerprint_from_public_key(my_pub_b64)
    fp_b = fingerprint_from_public_key(peer_pub_b64)
    combined = b"".join(sorted([fp_a, fp_b]))
    digest = hashlib.sha256(combined).digest()
    digits = "".join(f"{b:03d}" for b in digest[:20])  # 20 байт -> 60 цифр
    return " ".join(digits[i : i + 5] for i in range(0, SAFETY_NUMBER_GROUPS * 5, 5))


# Диалоги и виджеты
# ---------------------------------------------------------------------------


class _DismissableDialog:
    """Общая логика закрытия модальных диалогов в Flet 1.x."""

    def _dismiss(self) -> None:
        self.dialog.open = False
        self.dialog.update()


class EditDialog(_DismissableDialog):
    """Диалог редактирования текста сообщения с валидацией окна."""

    def __init__(
        self, message: Message, on_save: Callable[[str], Awaitable[None]], colors: dict
    ):
        self.message = message
        self.on_save = on_save
        self.c = colors
        self.field = ft.TextField(
            value=message.text,
            multiline=True,
            min_lines=2,
            max_lines=8,
            autofocus=True,
            border=ft.InputBorder.OUTLINE,
            content_padding=10,
        )
        hint = ""
        if message.edited_at:
            hint = f"Отредактировано {_fmt_time(message.edited_at)}"
        # Flet 1.x: у AlertDialog нет параметра subtitle — подсказка вынесена
        # в content (актуальный паттерн Material 3).
        content_controls: list[ft.Control] = []
        if hint:
            content_controls.append(ft.Text(hint, size=12, color=self.c["sub"]))
        content_controls.append(self.field)
        self.dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Редактировать сообщение"),
            content=ft.Container(
                width=420,
                content=ft.Column(content_controls, spacing=8, tight=True),
            ),
            actions=[
                ft.TextButton("Отмена", on_click=self._cancel),
                ft.FilledButton("Сохранить", icon=ft.Icons.SEND, on_click=self._save),
            ],
        )

    def _cancel(self, e) -> None:
        self._dismiss()

    async def _save(self, e) -> None:
        new_text = (self.field.value or "").strip()
        if not new_text or new_text == self.message.text:
            self.field.error_text = "Пустой или неизменённый текст"
            self.field.update()
            return
        self._dismiss()
        await self.on_save(new_text)

    def show(self, page: ft.Page) -> None:
        self._page = page
        page.show_dialog(self.dialog)


class ReactionPicker(_DismissableDialog):
    """Поп-овер выбора быстрой реакции на сообщение."""

    def __init__(
        self, message: Message, on_pick: Callable[[str], Awaitable[None]], colors: dict
    ):
        self.message = message
        self.on_pick = on_pick
        self.c = colors
        self._page: Optional[ft.Page] = None
        buttons = [
            ft.IconButton(
                icon=emoji,
                tooltip=emoji,
                icon_size=26,
                on_click=lambda e, em=emoji: self._choose(em),
            )
            for emoji in QUICK_REACTIONS
        ]
        self.dialog = ft.AlertDialog(
            title=ft.Text("Реакция", size=14),
            content=ft.Row(buttons, wrap=True, alignment=ft.MainAxisAlignment.CENTER),
            actions=[ft.TextButton("Убрать все", on_click=self._clear)],
        )

    async def _choose(self, emoji: str) -> None:
        self._dismiss()
        await self.on_pick(emoji)

    async def _clear(self, e) -> None:
        self._dismiss()
        await self.on_pick("")

    def show(self, page: ft.Page) -> None:
        self._page = page
        page.show_dialog(self.dialog)


class ReplyPreview(ft.Container):
    """Слайс-бар над полем ввода: цитата отвечаемого сообщения."""

    def __init__(self, colors: dict, on_cancel: Callable[[], None]):
        super().__init__(
            visible=False,
            padding=ft.Padding(12, 8, 12, 8),
            bgcolor=colors.get("chip", "#eef1f5"),
            border_radius=8,
            content=ft.Row(
                [
                    ft.VerticalDivider(width=3, color=colors.get("accent", "#2563eb")),
                    ft.Column(
                        [
                            ft.Text("", size=12, weight=ft.FontWeight.BOLD),
                            ft.Text(
                                "",
                                size=12,
                                color=colors["sub"],
                                max_lines=1,
                                overflow=ft.TextOverflow.ELLIPSIS,
                            ),
                        ],
                        spacing=2,
                        expand=True,
                    ),
                    ft.IconButton(
                        ft.Icons.CLOSE, icon_size=18, on_click=lambda e: on_cancel()
                    ),
                ],
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=8,
            ),
        )
        self._author_lbl: ft.Text = self.content.controls[1].controls[0]
        self._text_lbl: ft.Text = self.content.controls[1].controls[1]

    def set_target(self, author: str, text: str) -> None:
        self._author_lbl.value = author
        self._text_lbl.value = text
        self.visible = True
        self.update()

    def clear(self) -> None:
        self._author_lbl.value = ""
        self._text_lbl.value = ""
        self.visible = False
        self.update()


class SafetyNumberDialog(_DismissableDialog):
    """AlertDialog верификации E2E-отпечатков (Этап 7.2).

    Показывает 60-значный Safety Number личного чата, который участники должны
    сверить при личной встрече (или по доверенному каналу). Совпадение чисел
    подтверждает отсутствие MITM.
    """

    def __init__(
        self, safety_number: Optional[str], error: Optional[str], colors: dict
    ):
        self.c = colors
        self._page: Optional[ft.Page] = None
        if error:
            content: ft.Control = ft.Text(
                f"Не удалось получить ключ собеседника: {error}\n"
                "Убедитесь, что оба участника включили E2E.",
                color="#dc2626",
                selectable=True,
            )
        else:
            content = ft.Column(
                [
                    ft.Text(
                        "Сверьте это число с собеседником лично или по защищённому каналу. "
                        "Если числа совпадают — переписка не перехватывается.",
                        size=13,
                        color=self.c["sub"],
                    ),
                    ft.Container(
                        content=ft.Text(
                            safety_number or "",
                            size=16,
                            weight=ft.FontWeight.BOLD,
                            selectable=True,
                        ),
                        padding=14,
                        bgcolor=self.c.get("chip", "#f1f5f9"),
                        border_radius=10,
                        width=440,
                        alignment=ft.Alignment(0, 0),
                    ),
                    ft.Text(
                        "Отпечаток: SHA-256(pub_A || pub_B), отсортированные ключи",
                        size=11,
                        color=self.c["sub"],
                    ),
                ],
                spacing=12,
                width=440,
            )
        self.dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Верификация E2E (Safety Number)"),
            content=content,
            actions=[ft.FilledButton("Закрыть", on_click=lambda e: self._close())],
        )

    def _close(self) -> None:
        self._dismiss()

    def show(self, page: ft.Page) -> None:
        self._page = page
        page.show_dialog(self.dialog)


# ---------------------------------------------------------------------------
# Контроллер экрана
# ---------------------------------------------------------------------------


class TypingIndicator(ft.Container):
    """Анимированный индикатор «[Имя] печатает...» (Material 3, v2.0 Пункт 9).

    Лёгкий виджет под списком сообщений: три пульсирующие точки + подпись.
    Автоскрытие: если за TYPING_AUTOHIDE_SECONDS (6 c, TTL серверного ключа)
    не пришло ни одного обновляющего события по пользователю, виджет
    бесшумно исчезает.
    """

    TYPING_AUTOHIDE_SECONDS = 6.0
    _DOT_FRAMES = ("●○○", "○●○", "○○●")

    def __init__(self, colors: dict):
        super().__init__()
        self._colors = colors
        self._dots_lbl = ft.Text(self._DOT_FRAMES[0], size=13, color=colors["sub"])
        self._caption = ft.Text(
            "", size=13, style=ft.FontStyle(italic=True), color=colors["sub"]
        )
        self.visible = False
        self.padding = ft.Padding(16, 2, 16, 2)
        self.bgcolor = colors["surface"]
        self.content = ft.Row([self._dots_lbl, self._caption], spacing=6)
        # deadline по каждому печатающему пользователю: {user_id: loop_time+6}
        self._deadlines: dict[int, float] = {}
        self._names: dict[int, str] = {}
        self._anim_task = None
        self._hide_task = None

    # --- API для ChatScreen -------------------------------------------------
    def mark_typing(self, user_id: int, name: str) -> None:
        """Отметить, что пользователь `name` печатает сейчас (сброс таймера)."""
        self._deadlines[int(user_id)] = time.monotonic() + self.TYPING_AUTOHIDE_SECONDS
        self._names[int(user_id)] = name or f"user#{user_id}"
        self._render_caption()
        if not self.visible:
            self.visible = True
        self._start_anim()
        self._schedule_hide()
        self._safe_update()

    def mark_stopped(self, user_id: int) -> None:
        """Пользователь перестал печатать — скрыть немедленно, если он последний."""
        self._deadlines.pop(int(user_id), None)
        self._names.pop(int(user_id), None)
        if not self._deadlines:
            self._hide_now()
        else:
            self._render_caption()
            self._safe_update()

    def hide_all(self) -> None:
        """Полный сброс (при отправке собственного сообщения / выходе из чата)."""
        self._deadlines.clear()
        self._names.clear()
        self._hide_now()

    # --- Внутренняя логика --------------------------------------------------
    def _caption_text(self) -> str:
        names = list(self._names.values())
        if not names:
            return ""
        if len(names) == 1:
            return f"{names[0]} печатает…"
        if len(names) == 2:
            return f"{names[0]} и {names[1]} печатают…"
        return f"Ещё {len(names)} печатают…"

    def _render_caption(self) -> None:
        self._caption.value = self._caption_text()

    def _hide_now(self) -> None:
        self.visible = False
        self._cancel_tasks()
        self._safe_update()

    def _safe_update(self) -> None:
        try:
            self.update()
        except Exception:
            pass  # контрол ещё не примонтирован к странице или страница закрыта

    def _start_anim(self) -> None:
        if self._anim_task is not None and not self._anim_task.done():
            return
        try:
            self._anim_task = asyncio.ensure_future(self._animate())
        except RuntimeError:
            self._anim_task = None

    async def _animate(self) -> None:
        i = 0
        try:
            while self.visible and self._deadlines:
                self._dots_lbl.value = self._DOT_FRAMES[i % 3]
                i += 1
                self._safe_update()
                await asyncio.sleep(0.45)
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

    def _schedule_hide(self) -> None:
        if self._hide_task is not None and not self._hide_task.done():
            self._hide_task.cancel()
        try:
            self._hide_task = asyncio.ensure_future(self._autohide_loop())
        except RuntimeError:
            self._hide_task = None

    async def _autohide_loop(self) -> None:
        """Каждые 0.5 с проверяем дедлайны; истёкшие молча убираем."""
        try:
            while True:
                await asyncio.sleep(0.5)
                if not self._deadlines:
                    if self.visible:
                        self._hide_now()
                    return
                now = time.monotonic()
                expired = [uid for uid, dl in self._deadlines.items() if dl <= now]
                if expired:
                    for uid in expired:
                        self._deadlines.pop(uid, None)
                        self._names.pop(uid, None)
                    if not self._deadlines:
                        self._hide_now()
                        return
                    self._render_caption()
                    self._safe_update()
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

    def _cancel_tasks(self) -> None:
        for task in (self._anim_task, self._hide_task):
            if task is not None and not task.done():
                task.cancel()
        self._anim_task = None
        self._hide_task = None


class ChatScreen:
    """Экран чата с полным набором UX-фич Этапа 7.3.

    Параметры ``app``: .page (ft.Page), .api (ApiClient), .me (dict c id/username),
    .chat (dict c id/title/type/members). Колбэки API инкапсулированы в
    _api_* методах — для подмены в тестах/другом бэкенде достаточно переопределить их.
    """

    def __init__(self, app, chat: dict):
        self.app = app
        self.chat = chat
        self.chat_id = int(chat["id"])
        self.messages: list[Message] = []
        self.index_by_id: dict[int, Message] = {}
        self.reply_target: Optional[Message] = None
        self._draft_tx: str = ""
        self._ws_task: Optional[asyncio.Task] = None
        self._menu: Optional[ft.Control] = None
        # v2.0 Пункт 9: debounce-контроллер отправки client_typing
        self._last_typing_emit: float = 0.0
        self._typing_stop_task: Optional[asyncio.Task] = None
        self.typing_indicator: Optional["TypingIndicator"] = None
        # v2.0 Пункт 2: локальные таймеры-страховки по expires_at
        # (если WS-событие message_delete потерялось — карточка сгорит сама).
        self._burn_tasks: dict[int, asyncio.TimerHandle] = {}

    @property
    def page(self) -> ft.Page:
        return self.app.page

    @property
    def my_id(self) -> int:
        return int(self.app.me["id"])

    @property
    def c(self) -> dict:
        base = themes.colors(self.page)
        return {
            **base,
            "accent": base.get("bubble_me", "#2563eb"),
            "appbar": base["card"],
            "surface": base["card"],
            "chip": base["field"],
        }

    # ==================== Сборка UI ====================

    async def build(self) -> ft.Control:
        c = self.c
        self.title_lbl = ft.Text(
            self.chat.get("title", "Чат"), size=18, weight=ft.FontWeight.W_600
        )
        self.e2e_badge = ft.Icon(
            ft.Icons.LOCK, size=16, color=c["sub"], tooltip="E2E включён"
        )
        self.verify_btn = ft.IconButton(
            ft.Icons.VERIFIED_USER_OUTLINED,
            icon_size=20,
            tooltip="Проверить Safety Number",
            on_click=lambda e: asyncio.ensure_future(self.show_safety_numbers()),
            visible=self.chat.get("type") == "private",
        )

        self.list_view = ft.ListView(
            expand=True, spacing=6, reverse=False, auto_scroll=True
        )

        # v2.0 Пункт 9: анимированный индикатор «печатает…» под списком сообщений
        self.typing_indicator = TypingIndicator(c)

        self.input = ft.TextField(
            hint_text="Сообщение…",
            expand=True,
            multiline=True,
            min_lines=1,
            max_lines=5,
            shift_enter=True,
            on_submit=lambda e: asyncio.ensure_future(self.send_current_message()),
            on_change=self.on_input_change,
        )
        self.reply_preview = ReplyPreview(c, on_cancel=self.cancel_reply)

        send_btn = ft.FilledIconButton(
            icon=ft.Icons.SEND,
            on_click=lambda e: asyncio.ensure_future(self.send_current_message()),
        )

        header = ft.AppBar(
            title=ft.Row([self.title_lbl, self.e2e_badge, self.verify_btn], spacing=8),
            bgcolor=c["appbar"],
            leading=ft.IconButton(
                ft.Icons.ARROW_BACK, on_click=lambda e: self.app.open_chats_list()
            ),
        )
        composer = ft.Container(
            padding=ft.Padding(10, 6, 10, 10),
            bgcolor=c["surface"],
            content=ft.Column(
                [self.reply_preview, ft.Row([self.input, send_btn], spacing=8)],
                spacing=4,
            ),
        )
        self.root = ft.Column(
            [header, self.list_view, self.typing_indicator, composer],
            expand=True,
            spacing=0,
        )
        await self.load_history()
        return self.root

    # ==================== Данные ====================

    async def load_history(self) -> None:
        raw = await self._api_messages()
        now = _now_utc()
        # v2.0 Пункт 2: страховка на случай потерянного message_delete —
        # истёкшие сообщения не рендерим и снимаем с них локальные таймеры.
        self.messages = [
            Message.from_server(m, self.my_id)
            for m in raw
            if not (m.get("expires_at") and _parse_ts(m["expires_at"]) <= now)
        ]
        self.index_by_id = {m.id: m for m in self.messages if m.id is not None}
        self._render_all()
        for msg in self.messages:
            self._schedule_burn(msg)

    async def _api_messages(self) -> list[dict]:
        return await self.app.api.messages(self.chat_id, limit=100)

    async def _api_send(self, text: str, tx: str, reply_to: Optional[int]) -> dict:
        return await self.app.api.send_message(
            self.chat_id, text, client_tx=tx, reply_to=reply_to
        )

    async def _api_edit(self, message_id: int, text: str) -> dict:
        return await self.app.api.edit_message(message_id, text)

    async def _api_react(self, message_id: int, emoji: str) -> dict:
        return await self.app.api.react_message(message_id, emoji)

    async def _api_read(self, message_id: int) -> dict:
        return await self.app.api.mark_viewed(message_id)

    async def _api_peer_pubkey(self) -> tuple[Optional[str], Optional[str]]:
        """Возвращает (pubkey, error) публичный ключ собеседника для приватного чата."""
        try:
            members = self.chat.get("members") or []
            peer = next((m for m in members if int(m["id"]) != self.my_id), None)
            if peer is None:
                return None, "собеседник не найден"
            pub = await self.app.api.e2e_get_key(int(peer["id"]))
            return (pub or None), (None if pub else "ключ не установлен")
        except Exception as exc:  # сетевые/HTTP ошибки показываем в диалоге
            return None, str(exc)

    # ==================== Рендеринг ====================

    def _render_all(self) -> None:
        self.list_view.controls.clear()
        for msg in self.messages:
            self.list_view.controls.append(self._bubble(msg))
        self.list_view.update()

    def _bubble(self, m: Message) -> ft.Control:
        c = self.c
        mine = m.sender_id == self.my_id

        author = "" if mine else self._author_name(m.sender_id)
        parts: list[ft.Control] = []
        if author:
            parts.append(
                ft.Text(author, size=11, weight=ft.FontWeight.BOLD, color=c["accent"])
            )
        if m.reply_preview and m.reply_to_id:
            parts.append(
                ft.Container(
                    padding=ft.Padding(8, 4, 8, 4),
                    border=ft.border.only(left=ft.BorderSide(3, c["accent"])),
                    bgcolor="#00000010",
                    border_radius=4,
                    content=ft.Text(
                        m.reply_preview,
                        size=11,
                        color=c["sub"],
                        max_lines=1,
                        overflow=ft.TextOverflow.ELLIPSIS,
                    ),
                )
            )
        body = ft.Text(m.text, size=14, selectable=True)
        if m.edited_at:
            body = ft.Row(
                [body, ft.Text("(ред.)", size=10, italic=True, color=c["sub"])],
                spacing=4,
                tight=True,
            )
        parts.append(body)

        if m.reactions:
            chips = [
                ft.Container(
                    padding=ft.Padding(6, 2, 6, 2),
                    bgcolor="#00000012",
                    border_radius=10,
                    content=ft.Text(f"{emoji} {len(users)}", size=11),
                )
                for emoji, users in sorted(m.reactions.items())
            ]
            parts.append(ft.Row(chips, spacing=4, wrap=True))

        meta: list[ft.Control] = [
            ft.Text(_fmt_time(m.created_at), size=10, color=c["sub"])
        ]
        if mine:
            glyph = STATUS_GLYPH[m.status]
            meta.append(
                ft.Text(
                    glyph,
                    size=10,
                    color="#16a34a"
                    if m.status in (MessageStatus.READ, MessageStatus.DELIVERED)
                    else c["sub"],
                )
            )
        parts.append(ft.Row(meta, spacing=4, alignment=ft.MainAxisAlignment.END))

        bubble = ft.Container(
            content=ft.Column(parts, spacing=4, tight=True),
            padding=ft.Padding(12, 8, 12, 8),
            bgcolor=c["bubble_me"] if mine else c["bubble_other"],
            border_radius=14,
        )
        wrapper = ft.GestureDetector(
            on_tap_down=lambda e, msg=m: self._on_bubble_tap(e, msg),
            on_long_press=lambda e, msg=m: self._open_context(msg),
            content=bubble,
        )
        return ft.Row(
            [wrapper],
            alignment=ft.MainAxisAlignment.END if mine else ft.MainAxisAlignment.START,
        )

    def _context_menu(self, m: Message) -> list[ft.Control]:
        items: list[ft.Control] = [
            ft.ListTile(
                leading=ft.Icon(ft.Icons.REPLY),
                title=ft.Text("Ответить"),
                on_click=lambda e, msg=m: self._ctx_action(self.begin_reply, msg),
            ),
            ft.ListTile(
                leading=ft.Icon(ft.Icons.MOOD),
                title=ft.Text("Реакция…"),
                on_click=lambda e, msg=m: self._ctx_action(
                    lambda mm: ReactionPicker(mm, self.toggle_reaction, self.c).show(
                        self.page
                    ),
                    msg,
                ),
            ),
        ]
        if m.sender_id == self.my_id:
            items.append(
                ft.ListTile(
                    leading=ft.Icon(ft.Icons.EDIT),
                    title=ft.Text(
                        "Редактировать" if m.can_edit else "Редактирование недоступно"
                    ),
                    enabled=m.can_edit,
                    on_click=lambda e, msg=m: self._ctx_action(
                        lambda mm: EditDialog(mm, self._save_edit(mm), self.c).show(
                            self.page
                        ),
                        msg,
                    ),
                )
            )
        return items

    def _ctx_action(self, fn, msg: Message) -> None:
        if self._menu is not None:
            self._menu.open = False
            self._menu.update()
            self._menu = None
        fn(msg)

    def _on_bubble_tap(self, e, m: Message) -> None:
        """Тап по failed/непрочитанному сообщению — повторная отправка/отметка прочтения."""
        if m.failed and m.id is None:
            asyncio.ensure_future(self.resend_failed(m))
            return
        if (
            m.sender_id != self.my_id
            and self.my_id not in m.read_by
            and m.id is not None
        ):
            asyncio.ensure_future(self._mark_read(m))

    def _open_context(self, m: Message) -> None:
        self._menu = ft.BottomSheet(
            show_drag_handle=True,
            content=ft.Column(self._context_menu(m), tight=True, width=420),
        )
        self.page.show_dialog(self._menu)

    # ==================== Действия пользователя ====================

    def begin_reply(self, m: Message) -> None:
        self.reply_target = m
        preview = m.text if len(m.text) <= 90 else m.text[:90] + "…"
        author = "Вы" if m.sender_id == self.my_id else self._author_name(m.sender_id)
        self.reply_preview.set_target(author, preview)
        self.input.focus()

    def cancel_reply(self) -> None:
        self.reply_target = None
        self.reply_preview.clear()

    async def toggle_reaction(self, emoji: str) -> None:
        target = self.reply_target
        if target is None or target.id is None:
            return
        try:
            res = await self._api_react(target.id, emoji)
            target.reactions = {
                k: set(int(u) for u in v)
                for k, v in (res.get("reactions") or {}).items()
            }
            self._refresh_bubble(target)
        except Exception as exc:
            self._snack(f"Реакция не отправлена: {exc}")

    async def _save_edit(self, m: Message) -> Callable[[str], Awaitable[None]]:
        async def handler(new_text: str) -> None:
            if m.id is None:
                return
            try:
                res = await self._api_edit(m.id, new_text)
                m.text = res.get("text", new_text)
                m.edited_at = _parse_ts(res.get("edited_at") or m.edited_at.isoformat())
                self._refresh_bubble(m)
                self._snack("Сообщение отредактировано")
            except Exception as exc:
                self._snack(f"Ошибка редактирования: {exc}")

        return handler

    async def send_current_message(self) -> None:
        text = (self.input.value or "").strip()
        if not text:
            return
        self.input.value = ""
        self.input.update()
        reply_to = self.reply_target.id if self.reply_target else None
        self.cancel_reply()

        tx = self._new_tx()
        draft = Message(
            id=None,
            chat_id=self.chat_id,
            sender_id=self.my_id,
            text=text,
            status=MessageStatus.SENDING,
            reply_to_id=reply_to,
            reply_preview=self.reply_target.text if self.reply_target else None,
        )
        self.messages.append(draft)
        self.list_view.controls.append(self._bubble(draft))
        self.list_view.update()

        try:
            res = await self._api_send(text, tx, reply_to)
            confirmed = Message.from_server(res, self.my_id)
            self._replace_message(draft, confirmed)
        except Exception as exc:
            draft.status = MessageStatus.FAILED
            draft.failed = True
            self._refresh_bubble(draft)
            self._snack(
                f"Не отправлено ({exc}). Нажмите на сообщение для повторной попытки."
            )

    async def resend_failed(self, m: Message) -> None:
        if m.id is not None or not m.failed:
            return
        m.failed = False
        m.status = MessageStatus.SENDING
        self._refresh_bubble(m)
        try:
            res = await self._api_send(m.text, self._new_tx(), m.reply_to_id)
            self._replace_message(m, Message.from_server(res, self.my_id))
        except Exception as exc:
            m.status = MessageStatus.FAILED
            m.failed = True
            self._refresh_bubble(m)
            self._snack(f"Повтор не удался: {exc}")

    async def _mark_read(self, m: Message) -> None:
        if m.id is None:
            return
        try:
            await self._api_read(m.id)
            m.read_by.add(self.my_id)
            if m.sender_id != self.my_id:
                m.status = MessageStatus.READ
        except Exception:
            pass  # статус прочтения — best-effort, не критично для UX

    # ==================== Статусы (WS) ====================

    # ---------- v2.0 Пункт 9: Debounce-контроллер «печатает» ----------
    TYPING_DEBOUNCE_SECONDS = 2.0  # не чаще одного client_typing в 2 секунды
    TYPING_STOP_DELAY_SECONDS = 5.0  # «перестал печатать» после паузы ввода

    def on_input_change(self, e) -> None:
        """on_change TextField: троттлинг отправки client_typing по WebSocket.

        Событие уходит не чаще раза в TYPING_DEBOUNCE_SECONDS; каждое
        изменение текста перезапускает таймер stop-события. Полностью
        асинхронно и без исключений наружу — UX-фича best-effort.
        """
        text = self.input.value or ""
        now = time.monotonic()
        if not text.strip():
            # Черновик пуст — немедленно шлём stop (он не лимитится сервером).
            self._last_typing_emit = 0.0
            self._cancel_stop_timer()
            asyncio.ensure_future(self._send_typing_event(""))
            return
        if now - self._last_typing_emit >= self.TYPING_DEBOUNCE_SECONDS:
            self._last_typing_emit = now
            asyncio.ensure_future(self._send_typing_event(text))
        self._restart_stop_timer()

    async def _send_typing_event(self, text: str) -> None:
        try:
            await self.app.api.ws_send(
                {
                    "type": "client_typing",
                    "chat_id": self.chat_id,
                    "text": text,
                }
            )
        except Exception:
            pass  # WS ещё не поднят / сеть упала — молча деградируем

    def _restart_stop_timer(self) -> None:
        self._cancel_stop_timer()
        self._typing_stop_task = asyncio.ensure_future(self._typing_stop_later())

    def _handle_typing_event(self, ev: dict) -> None:
        """WS-событие user_typing от бэкенда (v2.0 Пункт 9)."""
        if int(ev.get("chat_id", -1)) != self.chat_id:
            return
        uid = int(ev.get("user_id", 0))
        if not uid or uid == self.my_id:
            return
        indicator = getattr(self, "typing_indicator", None)
        if indicator is None:
            return
        if ev.get("typing"):
            indicator.mark_typing(uid, self._author_name(uid))
        else:
            indicator.mark_stopped(uid)

    # ---------- Таймер «перестал печатать» (v2.0 Пункт 9) ----------
    async def _typing_stop_later(self) -> None:
        """Через TYPING_STOP_DELAY_SECONDS бездействия шлём stop-событие.

        Задача отменяется через _cancel_stop_timer при каждом новом вводе,
        поэтому событие уходит ровно один раз на паузу печати.
        """
        try:
            await asyncio.sleep(self.TYPING_STOP_DELAY_SECONDS)
            await self._send_typing_event("")
        except asyncio.CancelledError:
            return
        except Exception:
            pass

    def _cancel_stop_timer(self) -> None:
        task = getattr(self, "_typing_stop_task", None)
        if task is not None and not task.done():
            task.cancel()
        self._typing_stop_task = None

    # ==================== Диспетчер WS-событий ====================

    def handle_event(self, ev: dict) -> None:
        """Роутер входящих WebSocket-событий для активного экрана чата."""
        etype = ev.get("type")
        if etype == "ping":
            return
        if etype == "user_typing":
            self._handle_typing_event(ev)
            return
        if etype != "message_status" and etype != "message":
            # Фолбэк: часть событий приходит плоским payload'ом из ws_manager.
            if "status" not in ev and etype not in ("react", "edited", "reaction"):
                return
        kind = ev.get("kind") or etype
        msg_id = ev.get("message_id") or ev.get("id")
        if kind in ("delivered", "read"):
            m = self.index_by_id.get(int(msg_id)) if msg_id else None
            if m is None:
                return
            who = int(ev.get("user_id", 0))
            if kind == "read":
                m.read_by.add(who)
            if m.sender_id == self.my_id:
                m.status = (
                    MessageStatus.READ if kind == "read" else MessageStatus.DELIVERED
                )
                self._refresh_bubble(m)
        elif kind == "react":
            m = self.index_by_id.get(int(msg_id)) if msg_id else None
            if m is not None:
                emoji = ev.get("emoji", "")
                user = int(ev.get("user_id", 0))
                bucket = m.reactions.setdefault(emoji, set())
                (bucket.discard if ev.get("removed") else bucket.add)(user)
                if not bucket:
                    m.reactions.pop(emoji, None)
                self._refresh_bubble(m)
        elif kind == "edited":
            m = self.index_by_id.get(int(msg_id)) if msg_id else None
            if m is not None:
                m.text = ev.get("text", m.text)
                m.edited_at = _parse_ts(ev.get("edited_at"))
                self._refresh_bubble(m)
        elif kind == "message":
            incoming = Message.from_server(ev.get("payload") or {}, self.my_id)
            if incoming.id is not None and incoming.id in self.index_by_id:
                return  # дедупликация по id
            self.messages.append(incoming)
            if incoming.id is not None:
                self.index_by_id[incoming.id] = incoming
            self.list_view.controls.append(self._bubble(incoming))
            self.list_view.update()
            if incoming.sender_id != self.my_id:
                asyncio.ensure_future(self._mark_read(incoming))

    # ==================== E2E-верификация ====================

    async def show_safety_numbers(self) -> None:
        my_pub = (
            crypto.get_public_key()
        )  # base64 публичный X25519-ключ из локального хранилища
        peer_pub, error = (None, None)
        if my_pub:
            peer_pub, error = await self._api_peer_pubkey()
        number = None
        if my_pub and peer_pub:
            number = compute_safety_number(my_pub, peer_pub)
        SafetyNumberDialog(number, error, self.c).show(self.page)

    # ==================== Утилиты ====================

    def _new_tx(self) -> str:
        return uuid.uuid4().hex

    def _author_name(self, user_id: int) -> str:
        for mbr in self.chat.get("members") or []:
            if int(mbr["id"]) == user_id:
                return (
                    mbr.get("display_name") or mbr.get("username") or f"user#{user_id}"
                )
        return f"user#{user_id}"

    def _replace_message(self, old: Message, new: Message) -> None:
        for i, m in enumerate(self.messages):
            if m is old:
                self.messages[i] = new
                break
        if new.id is not None:
            self.index_by_id[new.id] = new
        idx = (
            self.list_view.controls.index(self._find_row_for(old))
            if self._find_row_for(old)
            else -1
        )
        if idx >= 0:
            self.list_view.controls[idx] = self._bubble(new)
        else:
            self.list_view.controls.append(self._bubble(new))
        self.list_view.update()

    def _find_row_for(self, m: Message) -> Optional[ft.Control]:
        # Пул строк сопоставляется по тексту+времени черновика (id ещё нет).
        for row in self.list_view.controls:
            container = getattr(row, "controls", [None])[0]
            gesture = getattr(container, "content", None)
            inner = getattr(gesture, "content", None)
            col = getattr(inner, "content", None)
            texts = getattr(col, "controls", []) if col else []
            first_body = next(
                (t for t in texts if isinstance(t, ft.Text) and t.size == 14), None
            )
            if first_body is not None and first_body.value == m.text and m.id is None:
                return row
        return None

    def _refresh_bubble(self, m: Message) -> None:
        for i, row in enumerate(self.list_view.controls):
            if self._row_matches(row, m):
                self.list_view.controls[i] = self._bubble(m)
                self.list_view.update()
                return
        # Черновик без id уже заменён в _replace_message; сюда не попадаем.

    def _row_matches(self, row: ft.Control, m: Message) -> bool:
        container = getattr(row, "controls", [None])[0]
        gesture = getattr(container, "content", None)
        inner = getattr(gesture, "content", None)
        col = getattr(inner, "content", None)
        texts = getattr(col, "controls", []) if col else []
        body = next((t for t in texts if isinstance(t, ft.Text) and t.size == 14), None)
        return body is not None and body.value == m.text

    def _snack(self, text: str) -> None:
        sb = getattr(self.app, "snack", None)
        if sb is not None:
            sb.content = ft.Text(text)
            sb.open = True
            self.page.update()
        else:
            self.page.show_dialog(ft.SnackBar(content=ft.Text(text)))


__all__ = [
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
]
