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
import math
import time
import uuid
from typing import Awaitable, Callable, Optional

import flet as ft

import crypto
import themes
from ui.message_model import (
    QUICK_REACTIONS,
    SAFETY_NUMBER_GROUPS,
    Message,
    MessageStatus,
    _fmt_time,
    _now_utc,
    _parse_ts,
    apply_reaction_summary,
    encrypt_reaction_payload,
    next_status,
    status_icon,
    status_icon_color,
)


# ---------------------------------------------------------------------------
# «Живая галочка» (Этап 7.3): статус -> Material-иконка ft.Icon
# ---------------------------------------------------------------------------

#: Имя иконки статуса — делег в чистую изолированную функцию message_model.
_STATUS_ICON = status_icon
#: Цвет прочитанной галочки (ft.colors.BLUE по ТЗ спринта 3).
_READ_COLOR = ft.Colors.BLUE


def status_icon_control(status: MessageStatus, sub_color: str) -> ft.Icon:
    """Собирает ft.Icon для статуса: sent — одна серая ✓, delivered — две
    серые ✓✓, read — две синие ✓✓ (BLUE). Чистая функция без побочных
    эффектов — используется и при первичной отрисовке пузыря, и в
    MessageRow.update_status_ui (O(1) точечное обновление)."""
    return ft.Icon(
        status_icon(status),
        size=15,
        color=status_icon_color(status, sub_color, _READ_COLOR),
        tooltip=status.value,
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
    """Веер-радар быстрых реакций (Спринт 3 «Reaxions»).

    Короткий тап по пузырю — мгновенный 👍 (в ChatScreen._end_swipe),
    длинный тап открывает этот радар: 6 эмодзи раскрываются дугой вокруг
    сообщения; выбор шлёт optimistic-toggle с E2EE blob'ом.
    """

    #: Углы раскрытия «веера» — от -75° до +75° относительно горизонтали.
    FAN_ANGLES = (-75, -45, -15, 15, 45, 75)
    FAN_RADIUS = 96.0

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
        # Веер: каждый эмодзи смещён вдоль своей дуги (sin/cos — чистая
        # математика без аллокаций, O(len(QUICK_REACTIONS)) один раз при открытии).
        fan: list[ft.Control] = []
        for i, btn in enumerate(buttons):
            angle_deg = self.FAN_ANGLES[i % len(self.FAN_ANGLES)]
            rad = math.radians(angle_deg)
            dx = self.FAN_RADIUS * math.cos(rad)
            dy = -self.FAN_RADIUS * math.sin(rad)  # экранные Y инвертированы
            fan.append(
                ft.Container(
                    content=btn,
                    translate=ft.Transform.translate(dx, dy),
                    animate_transform=ft.Animation(
                        250, ft.AnimationCurve.EASE_OUT_BACK
                    ),
                )
            )
        self.dialog = ft.AlertDialog(
            title=ft.Text("Реакция", size=14),
            content=ft.Stack(fan, width=260, height=180),
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
# MessageRow — пузырёк сообщения с «живой галочкой» (Этап 7.3, Спринт 3)
# ---------------------------------------------------------------------------


class MessageRow(ft.Container):
    """Один ряд списка сообщений: пузырь + мета-строка (время, галочка).

    Ключевое свойство для производительности: контрол хранит прямые ссылки
    на свои дочерние Text/Icon, поэтому ``update_status_ui`` меняет статус
    за O(1) — без пересборки пузыря и без линейного поиска по списку.
    Перерисовка строго асинхронная (``await self.update_async()``) — UI-поток
    Flet не блокируется сетевыми/WS-событиями.
    """

    def __init__(
        self, message: Message, mine: bool, colors: dict, screen: "ChatScreen"
    ):
        super().__init__()
        self.message = message
        self.mine = mine
        self._colors = colors
        self._screen = screen
        c = colors

        parts: list[ft.Control] = []
        author_name = "" if mine else screen._author_name(message.sender_id)
        self._author_lbl: Optional[ft.Text] = None
        if author_name:
            self._author_lbl = ft.Text(
                author_name, size=11, weight=ft.FontWeight.BOLD, color=c["accent"]
            )
            parts.append(self._author_lbl)

        self._reply_box: Optional[ft.Container] = None
        if message.reply_preview and message.reply_to_id:
            self._reply_text = ft.Text(
                message.reply_preview,
                size=11,
                color=c["sub"],
                max_lines=1,
                overflow=ft.TextOverflow.ELLIPSIS,
            )
            self._reply_box = ft.Container(
                padding=ft.Padding(8, 4, 8, 4),
                border=ft.border.only(left=ft.BorderSide(3, c["accent"])),
                bgcolor="#00000010",
                border_radius=4,
                content=self._reply_text,
            )
            parts.append(self._reply_box)

        self._body = ft.Text(message.text, size=14, selectable=True)
        self._edited_lbl: Optional[ft.Text] = None
        if message.edited_at:
            self._edited_lbl = ft.Text("(ред.)", size=10, italic=True, color=c["sub"])
            parts.append(ft.Row([self._body, self._edited_lbl], spacing=4, tight=True))
        else:
            parts.append(self._body)

        self._reactions_row: Optional[ft.Row] = None
        if message.reactions:
            self._reactions_row = self._build_reactions(message)
            parts.append(self._reactions_row)

        # --- Мета: время + «живая галочка» (только для исходящих) ---
        self._time_lbl = ft.Text(_fmt_time(message.created_at), size=10, color=c["sub"])
        meta: list[ft.Control] = [self._time_lbl]
        self._status_icon: Optional[ft.Icon] = None
        if mine:
            self._status_icon = status_icon_control(message.status, c["sub"])
            meta.append(self._status_icon)
        parts.append(ft.Row(meta, spacing=4, alignment=ft.MainAxisAlignment.END))

        bubble = ft.Container(
            content=ft.Column(parts, spacing=4, tight=True),
            padding=ft.Padding(12, 8, 12, 8),
            bgcolor=c["bubble_me"] if mine else c["bubble_other"],
            border_radius=14,
        )
        self.content = ft.GestureDetector(
            on_tap_down=lambda e: self._screen._on_bubble_tap(e, self.message),
            on_long_press=lambda e: self._screen._open_context(self.message),
            # Спринт 3 «Reaxions»: свайп по пузырю — мгновенная быстрая реакция.
            # Свайпы активны только когда экран не в режиме ответа (reply_target
            # занят цитатой) и у сообщения есть id (черновики не реагируем).
            on_horizontal_drag_start=self._on_drag_start,
            on_horizontal_drag_end=self._on_drag_end,
            content=bubble,
        )
        self.alignment = (
            ft.MainAxisAlignment.END if mine else ft.MainAxisAlignment.START
        )

    @staticmethod
    def _build_reactions(m: Message) -> ft.Row:
        chips = [
            ft.Container(
                padding=ft.Padding(6, 2, 6, 2),
                bgcolor="#00000012",
                border_radius=10,
                content=ft.Text(f"{emoji} {len(users)}", size=11),
            )
            for emoji, users in sorted(m.reactions.items())
        ]
        return ft.Row(chips, spacing=4, wrap=True)

    # ---------- Публичный API точечных обновлений (O(1)) ----------

    async def update_status_ui(self, new_status: MessageStatus) -> bool:
        """Перекрашивает «живую галочку» в новый статус.

        Монотонный merge через next_status: запоздалое WS-событие
        «delivered» не откатит синие галочки назад к серым. Возвращает
        True, если внешний вид реально изменился (и был выполнен
        await update_async); False — no-op без перерисовки.
        """
        merged = next_status(self.message.status, new_status)
        if merged is self.message.status or self._status_icon is None:
            return False
        self.message.status = merged
        self._status_icon.icon = _STATUS_ICON(merged)
        self._status_icon.color = status_icon_color(
            merged, self._colors["sub"], _READ_COLOR
        )
        self._status_icon.tooltip = merged.value
        try:
            await self.update_async()  # только async-перерисовка — без фризов
        except Exception:
            pass  # контрол отвязан от страницы (чат закрыт) — молча деградируем
        return True

    def refresh_body(self, text: str, edited_at) -> None:
        self.message.text = text
        self.message.edited_at = edited_at
        if edited_at is not None and self._edited_lbl is None:
            self._edited_lbl = ft.Text(
                "(ред.)", size=10, italic=True, color=self._colors["sub"]
            )
            row = ft.Row([self._body, self._edited_lbl], spacing=4, tight=True)
            col = self.content.content.content
            for i, ctl in enumerate(col.controls):
                if ctl is self._body:
                    col.controls[i] = row
                    break
        self._body.value = text

    def refresh_reactions(self) -> None:
        col = self.content.content.content
        if self._reactions_row is None:
            if not self.message.reactions:
                return
            self._reactions_row = self._build_reactions(self.message)
            col.controls.insert(-1, self._reactions_row)
        else:
            self._reactions_row.controls = self._build_reactions(self.message).controls

    def refresh_reply(self, preview: Optional[str]) -> None:
        if preview and self._reply_box is not None:
            self._reply_text.value = preview
        elif preview and self._reply_box is None:
            self.message.reply_preview = preview
            self._reply_text = ft.Text(
                preview,
                size=11,
                color=self._colors["sub"],
                max_lines=1,
                overflow=ft.TextOverflow.ELLIPSIS,
            )
            self._reply_box = ft.Container(
                padding=ft.Padding(8, 4, 8, 4),
                border=ft.border.only(left=ft.BorderSide(3, self._colors["accent"])),
                bgcolor="#00000010",
                border_radius=4,
                content=self._reply_text,
            )
            col = self.content.content.content
            insert_at = 1 if self._author_lbl is not None else 0
            col.controls.insert(insert_at, self._reply_box)

    # ---------- Свайп-реакции (Спринт 3 «Reaxions») ----------

    def _on_drag_start(self, e: ft.DragStartEvent) -> None:
        """Фиксируем старт горизонтального свайпа (для дедупликации жеста)."""
        self._screen._begin_swipe(self.message, e)

    def _on_drag_end(self, e: ft.DragEndEvent) -> None:
        """Завершение свайпа: экран решает, отправлять ли быструю реакцию."""
        self._screen._end_swipe(self.message, e)


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
        # Этап 7.3 «Живая галочка»: хеш-указатель id -> MessageRow для O(1)
        # точечного обновления статусов из WS-цикла без обхода списка.
        self.rows_by_id: dict[int, "MessageRow"] = {}
        # Идемпотентность ACK на клиенте: множества уже отправленных статусов
        # (повторный delivered/read за одну сессию экрана не уйдёт в сеть).
        self._delivered_acked: set[int] = set()
        self._read_acked: set[int] = set()
        # Спринт 3 «Reaxions»: E2E-ключ чата (X25519+HKDF) для де/шифрования
        # blob'ов реакций; None => чат без E2E (реакции не шифруются сервером
        # осмысленно — UI просто не покажет эмодзи из чужих blob'ов).
        self.e2e_key: Optional[bytes] = None
        #: Дедупликация свайп-жеста: message_id -> момент последнего принятого
        #: свайпа (SWIPE_DEDUPE_SECONDS). Защита от двойного POST при дрожи.
        self._last_swipe_at: dict[int, float] = {}

    # ---------- Константы жестов (Спринт 3 «Reaxions») ----------
    SWIPE_DEDUPE_SECONDS = 0.8  # минимум между двумя свайп-реакциями одного id
    SWIPE_MIN_DELTA_PX = 40.0  # смещение, отделяющее свайп от случайного сдвига

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
        await self._setup_e2e()  # Спринт 3: ключ чата нужен для де/шифрования реакций
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
        # Этап 7.3: скролл вниз (event_type scroll_end у нижнего края) —
        # отмечаем видимые непрочитанные сообщения как прочитанные.
        # require_theme=True включает обратную связь extent/pixels в Flet 1.x.
        self.list_view.on_scroll = ft.ControlEvent(
            self._on_list_scroll, wait=50, require_theme=True
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
        # Этап 7.3: экран открыт — помечаем видимые (последние) входящие
        # непрочитанные сообщения как прочитанные (best-effort, без await).
        asyncio.ensure_future(self.mark_visible_read())
        return self.root

    # ==================== Данные ====================

    async def _setup_e2e(self) -> None:
        """Derive общего ключа чата (X25519 + HKDF) для E2EE-реакций.

        Логика идентична screens/chat_view.py::_setup_e2e: приватный ключ
        берём из локального хранилища, публичный — у собеседника. При
        отсутствии любой стороны e2e_key остаётся None — чат работает без
        шифрования реакций (эмодзи от других клиентов не дешифруются и
        молча не отображаются, UI не падает).
        """
        self.e2e_key = None
        if self.chat.get("type") != "private":
            return
        priv = getattr(self.app, "e2e_priv", None)
        if not priv:
            return
        peer_pub, _error = await self._api_peer_pubkey()
        if not peer_pub:
            return
        try:
            self.e2e_key = crypto.derive_chat_key(priv, peer_pub)
        except Exception:
            self.e2e_key = None

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
        await self._load_reaction_summaries()
        # Этап 7.3: ACK «delivered» для входящих, ещё не доставленных серверу.
        for msg in self.messages:
            if msg.sender_id != self.my_id and msg.id is not None:
                asyncio.ensure_future(self._ack_delivered(msg))
        self._render_all()
        for msg in self.messages:
            self._schedule_burn(msg)

    async def _load_reaction_summaries(self) -> None:
        """Batch-load реакций страницы ОДНИМ запросом (анти-N+1, Спринт 3).

        Сервер отдаёт summary вида {message_id: {blob: [user_id,...]}};
        эмодзи расшифровывается локальным ключом чата. Ошибки сети не должны
        ломать загрузку истории — реакции просто останутся пустыми.
        """
        ids = [m.id for m in self.messages if m.id is not None]
        if not ids:
            return
        try:
            grouped = await self.app.api.chat_reactions(self.chat_id, ids)
        except Exception:
            return
        for mid, summary in grouped.items():
            m = self.index_by_id.get(int(mid))
            if m is not None:
                apply_reaction_summary(m, summary, self.e2e_key)

    async def _api_messages(self) -> list[dict]:
        return await self.app.api.messages(self.chat_id, limit=100)

    async def _api_send(self, text: str, tx: str, reply_to: Optional[int]) -> dict:
        return await self.app.api.send_message(
            self.chat_id, text, client_tx=tx, reply_to=reply_to
        )

    async def _api_edit(self, message_id: int, text: str) -> dict:
        return await self.app.api.edit_message(message_id, text)

    async def _api_react(self, message_id: int, payload: str) -> dict:
        return await self.app.api.toggle_reaction(message_id, payload)

    async def _api_read(self, message_id: int) -> dict:
        return await self.app.api.mark_viewed(message_id)

    async def _api_status(self, message_id: int, status: str, ghost: bool) -> dict:
        """PATCH /messages/{id}/status — единая точка ACK статусов (Этап 7.3)."""
        return await self.app.api.update_message_status(message_id, status, ghost=ghost)

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
        self.rows_by_id.clear()
        for msg in self.messages:
            self.list_view.controls.append(self._bubble(msg))
        self.list_view.update()

    def _bubble(self, m: Message) -> ft.Control:
        """Строит ряд сообщения и регистрирует его в rows_by_id (O(1)-поиск)."""
        row = MessageRow(m, m.sender_id == self.my_id, self.c, self)
        m._row = row  # back-link для замены строки черновика при подтверждении
        if m.id is not None:
            self.rows_by_id[m.id] = row
        return row

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
        """Выбор из радара/меню: мгновенный optimistic-UI + E2EE POST.

        Порядок (Спринт 3): сначала локально меняем набор реакций и
        перерисовываем ряд (отклик <1 кадра), только затем уходим в сеть с
        зашифрованным blob'ом эмодзи. Ответ сервера — источник истины:
        применяем его summary; при ошибке откатываем оптимистичное изменение.
        """
        target = self.reply_target
        if target is None or target.id is None:
            return
        await self._apply_reaction(target, emoji)

    async def _apply_reaction(self, m: Message, emoji: str) -> None:
        """Оптимистичный toggle одной реакции для конкретного сообщения.

        E2EE-инвариант (Спринт 3): в сеть уходит только AES-GCM blob эмодзи,
        зашифрованный ключом чата — сервер не знает, какой именно смайл
        стоит. В чатах без общего ключа быстрые реакции запрещены: иначе
        эмодзи утёк бы серверу открытым текстом (см. _begin_swipe/_end_swipe).
        """
        if m.id is None:
            return
        snapshot = {k: set(v) for k, v in m.reactions.items()}  # для отката
        if emoji:
            bucket = m.reactions.setdefault(emoji, set())
            if self.my_id in bucket:
                bucket.discard(self.my_id)  # повторный выбор = снятие
            else:
                bucket.add(self.my_id)
        else:
            for users in m.reactions.values():
                users.discard(self.my_id)
        m.reactions = {k: v for k, v in m.reactions.items() if v}
        self._refresh_bubble(m)  # optimistic-UI: счётчик уже обновился

        payload = ""
        if emoji:
            if self.e2e_key is None:
                # Приватность важнее фичи: без ключа чата реакция не
                # покидает устройство; состояние откатываем к снимку.
                m.reactions = snapshot
                self._refresh_bubble(m)
                self._snack("Реакции доступны только в E2E-чатах")
                return
            payload = encrypt_reaction_payload(self.e2e_key, emoji)
        try:
            res = await self._api_react(m.id, payload)
        except Exception as exc:
            # Сеть/сервер упал — откатываем optimistic-UI к прежним реакциям
            # (локальный снимок делался до изменения) и показываем snack.
            m.reactions = snapshot
            self._refresh_bubble(m)
            self._snack(f"Реакция не отправлена: {exc}")
            return
        # Серверный summary — финальная инкарнация состояния (идемпотентно).
        apply_reaction_summary(m, res.get("reactions") or {}, self.e2e_key)
        self._refresh_bubble(m)

    # ---------- Свайп-реакции: дедупликация жеста (Спринт 3) ----------

    def _begin_swipe(self, m: Message, e) -> None:
        """drag_start: запоминаем стартовую точку свайпа по сообщению."""
        self._swipe_origin = getattr(e, "local_x", None)

    def _end_swipe(self, m: Message, e) -> None:
        """drag_end: если смещение достаточно велико — мгновенная 👍.

        Дедупликация: не чаще одного свайп-POST на сообщение в
        SWIPE_DEDUPE_SECONDS (защита от двойного срабатывания drag-end при
        рывках/дроби на сенсорных экранах). Повторный свайп по сообщению,
        где 👍 уже стоит у нас, работает как toggle (снятие).
        """
        origin = getattr(self, "_swipe_origin", None)
        self._swipe_origin = None
        end_x = getattr(e, "local_x", None)
        if origin is None or end_x is None:
            return
        if abs(end_x - origin) < self.SWIPE_MIN_DELTA_PX:
            return  # случайный микросдвиг пальца — не жест
        if m.id is None or self.reply_target is not None:
            return  # черновик или идёт цитирование — свайпы заняты reply-UX
        if self.e2e_key is None:
            return  # без ключа чата свайп-реакции приватно недоступны
        now = time.monotonic()
        last = self._last_swipe_at.get(m.id, 0.0)
        if now - last < self.SWIPE_DEDUPE_SECONDS:
            return  # анти-дребезг: слишком быстро после предыдущего свайпа
        self._last_swipe_at[m.id] = now
        asyncio.ensure_future(self._apply_reaction(m, QUICK_REACTIONS[0]))

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
            # Этап 7.3: собственное входящее-эхо (другое устройство в том же
            # чате) тоже требует ACK; своё сообщение серверу не «читаем».
            if confirmed.sender_id != self.my_id and confirmed.id is not None:
                asyncio.ensure_future(self._ack_delivered(confirmed))
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

    # ==================== Статусы: ACK + Ghost Mode (Этап 7.3) ====================

    def ghost_mode_enabled(self) -> bool:
        """Локальная настройка «Призрачное чтение» (crypto-хранилище клиента).

        Значение по умолчанию — False; при включённом режиме клиент шлёт
        PATCH read с ghost=True, и сервер оставляет физический статус
        delivered (синие галочки собеседник не увидит).
        """
        try:
            return bool(crypto.get_setting("ghost_mode", False))
        except Exception:
            return False

    async def _ack_status(
        self, message_id: int, status: str, acked: set[int]
    ) -> Optional[dict]:
        """Один best-effort PATCH статуса с клиентской дедупликацией.

        ``acked`` — множество id, для которых этот статус уже отправлялся
        в текущей сессии экрана: повторный вызов не уйдёт в сеть (экономия
        трафика); сервер в любом случае идемпотентен (условный UPDATE по
        числовому рангу), поэтому потеря/повтор события безопасны.
        """
        if message_id in acked:
            return None
        acked.add(message_id)
        ghost = status == "read" and self.ghost_mode_enabled()
        try:
            return await self._api_status(message_id, status, ghost)
        except Exception:
            acked.discard(message_id)  # сеть упала — разрешим повтор
            return None

    async def _ack_delivered(self, m: Message) -> None:
        """ACK «получено»: входящее сообщение доставлено на устройство."""
        if m.id is None or m.sender_id == self.my_id:
            return
        res = await self._ack_status(m.id, "delivered", self._delivered_acked)
        if res and res.get("changed"):
            # Собеседник увидит вторую серую галочку — обновим и свой UI
            # (актуально для реплик собственных сообщений других устройств).
            row = self.rows_by_id.get(m.id)
            if row is not None and row.mine:
                await row.update_status_ui(MessageStatus.DELIVERED)

    async def mark_visible_read(self) -> None:
        """Отметить прочитанными видимые непрочитанные входящие сообщения.

        ListView с auto_scroll показывает хвост истории, поэтому «видимыми»
        считаем последние VISIBLE_TAIL сообщений списка. Вызывается при
        открытии экрана и при скролле вниз (on_scroll_bottom_reached).
        """
        tail = self.messages[-self.VISIBLE_TAIL :]
        for m in tail:
            if (
                m.id is not None
                and m.sender_id != self.my_id
                and self.my_id not in m.read_by
            ):
                await self._send_read(m)

    async def _send_read(self, m: Message) -> None:
        """PATCH read (или ghost-delivered) + локальный merge статуса."""
        if m.id is None:
            return
        res = await self._ack_status(m.id, "read", self._read_acked)
        if res is None:
            return
        m.read_by.add(self.my_id)
        # Ghost Mode: сервер тихо вернул delivered — галочки у нас тоже
        # не должны «перепрыгнуть» в read (честная локальная симметрия).
        applied = MessageStatus(res.get("status", "read"))
        row = self.rows_by_id.get(m.id)
        if row is not None and row.mine:
            await row.update_status_ui(applied)
        elif m.sender_id != self.my_id:
            m.status = next_status(m.status, applied)

    def on_scroll_bottom_reached(self) -> None:
        """Хук скролла: пользователь доскроллил до низа — читаем видимое."""
        asyncio.ensure_future(self.mark_visible_read())

    def _on_list_scroll(self, e: ft.ScrollEvent) -> None:
        """on_scroll ListView: срабатывает на scroll_end у нижнего края.

        max_extent может быть None (контент ещё не измерен) — тогда событие
        игнорируем; auto_scroll сам прокрутит к хвосту и ACK придёт через
        mark_visible_read при открытии экрана / приходе нового сообщения.
        """
        if (
            e.event_type == ft.ScrollEventType.SCROLL_END
            and e.max_extent is not None
            and e.pixels is not None
            and e.pixels >= e.max_extent - 48
        ):
            self.on_scroll_bottom_reached()

    # ==================== Статусы (WS) ====================

    # ---------- v2.0 Пункт 9: Debounce-контроллер «печатает» ----------
    TYPING_DEBOUNCE_SECONDS = 2.0  # не чаще одного client_typing в 2 секунды
    TYPING_STOP_DELAY_SECONDS = 5.0  # «перестал печатать» после паузы ввода
    #: Этап 7.3: сколько последних сообщенийListView считает «видимыми»
    #: при открытии экрана / скролле вниз (эвристика высоты вьюпорта).
    VISIBLE_TAIL = 15

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
        # Этап 7.3 «Живая галочка»: серверный broadcast статуса —
        # message_status / STATUS_UPDATE (алиас). Обработка O(1): хеш id->row.
        if etype in ("message_status", "STATUS_UPDATE"):
            asyncio.ensure_future(self._handle_status_update(ev))
            return
        # Спринт 3 «Reaxions»: серверный broadcast зашифрованной реакции.
        if etype == "reaction_update":
            self._handle_reaction_update(ev)
            return
        if etype != "message":
            # Фолбэк: часть событий приходит плоским payload'ом из ws_manager.
            if "status" not in ev and etype not in ("react", "edited", "reaction"):
                return
        kind = ev.get("kind") or ev.get("status") or etype
        msg_id = ev.get("message_id") or ev.get("id")
        if kind in ("delivered", "read"):
            awaitable = self._handle_status_update(ev)
            asyncio.ensure_future(awaitable)
        elif kind == "react":
            m = self.index_by_id.get(int(msg_id)) if msg_id else None
            if m is not None:
                summary = ev.get("reactions")
                if isinstance(summary, dict) and summary:
                    # Спринт 3: сервер прислал полный шифрованный summary —
                    # единая точка применения (O(1) хеш-резолв по id).
                    apply_reaction_summary(m, summary, self.e2e_key)
                else:
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
                # Этап 7.3: WS-доставка на устройство => ACK delivered,
                # а если экран открыт и сообщение в видимом хвосте — read.
                asyncio.ensure_future(self._ack_delivered(incoming))
                if len(self.messages) <= self.VISIBLE_TAIL:
                    asyncio.ensure_future(self._send_read(incoming))

    def _handle_reaction_update(self, ev: dict) -> None:
        """Перехват WS-события reaction_update (Спринт 3).

        Payload сервера: {type, chat_id, message_id, reactions:
        {blob: [user_id,...]}} — blob'ы непрозрачны, эмодзи восстановится
        только локальным ключом чата. Резолв сообщения — O(1) через
        хеш-таблицу index_by_id; перерисовка одного ряда — через rows_by_id.
        """
        if int(ev.get("chat_id", -1)) != self.chat_id:
            return
        msg_id = ev.get("message_id") or ev.get("id")
        if msg_id is None:
            return
        m = self.index_by_id.get(int(msg_id))
        if m is None:
            return  # сообщение не из этого чата / ещё не загружено
        apply_reaction_summary(m, ev.get("reactions") or {}, self.e2e_key)
        self._refresh_bubble(m)

    async def _handle_status_update(self, ev: dict) -> None:
        """Перехват STATUS_UPDATE/message_status: O(1) поиск row + перекраска.

        Событие несёт {message_id, status('delivered'|'read'), reader/user}.
        Поиск сообщения в открытом списке — через хеш-таблицу rows_by_id
        («Грокаем алгоритмы»: dict вместо линейного скана). Статус модели
        обновляется монотонно (next_status), UI-ряд перекрашивается строго
        через await update_async() внутри MessageRow.update_status_ui.
        """
        msg_id = ev.get("message_id") or ev.get("id")
        raw_status = ev.get("status") or ev.get("kind")
        if msg_id is None or raw_status not in ("delivered", "read"):
            return
        try:
            new_status = MessageStatus(raw_status)
        except ValueError:
            return
        mid = int(msg_id)
        m = self.index_by_id.get(mid)
        if m is None:
            return  # сообщение не из этого чата/ещё не загружено
        who = int(ev.get("reader_id") or ev.get("user_id") or 0)
        if raw_status == "read" and who:
            m.read_by.add(who)
        row = self.rows_by_id.get(mid)
        if row is not None:
            await row.update_status_ui(new_status)
        else:
            # Ряд ещё не отрисован (draft без id) — только модель.
            m.status = next_status(m.status, new_status)

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
        # Черновик (MessageRow с id=None) меняем на подтверждённый ряд на
        # месте — без пересборки всего списка; rows_by_id пополняется в _bubble.
        old_row = getattr(old, "_row", None)
        controls = self.list_view.controls
        idx = -1
        if old_row is not None:
            for i, ctl in enumerate(controls):
                if ctl is old_row:
                    idx = i
                    break
        row = self._bubble(new)
        if 0 <= idx < len(controls):
            controls[idx] = row
        else:
            controls.append(row)
        self.list_view.update()

    def _refresh_bubble(self, m: Message) -> None:
        """Точечная перерисовка одного ряда (O(1) через rows_by_id).

        Используется только для контентных правок (edit/reaction): модель уже
        обновлена, нужно отправить изменённое дерево контролов на страницу.
        Статусные изменения делают MessageRow.update_status_ui напрямую.
        """
        row = self.rows_by_id.get(m.id) if m.id is not None else None
        if row is None:
            row = getattr(m, "_row", None)
        if row is not None:
            try:
                row.update()
            except Exception:
                pass

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
