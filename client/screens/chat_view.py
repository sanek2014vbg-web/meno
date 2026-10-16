"""MeNo — окно переписки: сообщения, медиа, эмодзи, ПИН-защита, E2E, исчезающие."""
import asyncio
from datetime import datetime, timezone

import flet as ft

import crypto
import themes
from api_client import ApiError

EMOJIS = ["👍", "❤️", "😂", "😮", "😢", "🔥", "🙏", "🎉"]
TTL_OPTIONS = [(None, "Без таймера"), (30, "30 секунд"), (300, "5 минут"),
               (3600, "1 час"), (86400, "24 часа")]
IMG_EXT = ("jpg", "jpeg", "png", "gif", "webp")


def _fmt_time(iso: str) -> str:
    try:
        return iso.split(" ")[1][:5]
    except Exception:
        return ""


def _remaining_seconds(created_at: str, ttl: int) -> int:
    """Сколько секунд осталось жить исчезающему сообщению (created_at — UTC)."""
    try:
        created = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        remain = ttl - (datetime.now(timezone.utc) - created).total_seconds()
        return max(0, int(remain))
    except Exception:
        return ttl


class ChatView:
    def __init__(self, app, chat: dict):
        self.app = app
        self.chat = chat
        self.chat_id = chat["id"]
        self.unlocked = False
        self.messages: list = []
        self.ttl: int | None = None
        self.view_once = False
        self.pending_tx: str = ""
        self.e2e_key: bytes | None = None  # общий секрет личного чата (X25519 + HKDF)

    @property
    def page(self):
        return self.app.page

    # ================= Сборка =================
    async def build(self) -> ft.Control:
        if crypto.has_chat_pin(self.chat_id) and not self.unlocked:
            return self._pin_screen()

        page = self.page
        c = themes.colors(page)

        # --- Заголовок ---
        self.title_lbl = ft.Text(self.chat["title"], size=18, weight=ft.FontWeight.W_600)
        self.presence_lbl = ft.Text(self._presence_text(), size=12, color=c["sub"])
        self.lock_icon = ft.Icon(
            ft.icons.LOCK_OUTLINE if crypto.has_chat_pin(self.chat_id) else ft.icons.LOCK_OPEN,
            size=18, color=c["sub"],
        )
        # E2E-бейдж только для личных чатов
        self.e2e_badge = None
        if self.chat["type"] == "personal":
            self.e2e_badge = ft.Container(
                padding=ft.padding.symmetric(horizontal=5, vertical=1),
                border_radius=6,
                bgcolor=c["field"],
                content=ft.Text("E2E", size=9, weight=ft.FontWeight.BOLD, color=themes.ACCENT),
            )
        header = ft.Row(
            [
                ft.IconButton(ft.icons.ARROW_BACK, tooltip="Назад",
                              on_click=lambda e: self.page.run_task(self.app.main_view.show_chats)),
                ft.CircleAvatar(radius=20, bgcolor=themes.ACCENT,
                                content=ft.Text(self.chat["title"][:1].upper(),
                                                color="#0B0E14", weight=ft.FontWeight.BOLD)),
                ft.Column([self.title_lbl, ft.Row([self.lock_icon, self.e2e_badge, self.presence_lbl]
                                                  if self.e2e_badge else
                                                  [self.lock_icon, self.presence_lbl],
                                                  spacing=4)],
                          spacing=0, expand=True),
                self._chat_menu(),
            ]
        )

        # --- Лента сообщений ---
        self.msgs_col = ft.Column(spacing=6, scroll=ft.ScrollMode.AUTO, expand=True,
                                  auto_scroll=True)

        # --- Панель ввода ---
        self.input = ft.TextField(
            hint_text="Сообщение…", multiline=False, expand=True,
            border_radius=20, filled=True, on_submit=lambda e: self.page.run_task(self._send),
        )
        self.file_btn = ft.IconButton(ft.icons.ATTACH_FILE, tooltip="Файл", on_click=lambda e: self._pick_file())
        self.emoji_btn = ft.PopupMenuButton(
            icon=ft.icons.SENTIMENT_SATISFIED_OUTLINED, tooltip="Эмодзи",
            items=[ft.PopupMenuItem(content=ft.Text(em, size=20), on_click=lambda e, s=em: self._add_emoji(s))
                   for em in EMOJIS],
        )
        self.ttl_btn = ft.PopupMenuButton(
            icon=ft.icons.TIMER_OUTLINED, tooltip="Исчезающее сообщение",
            items=[ft.PopupMenuItem(content=t, on_click=lambda e, v=v: self._set_ttl(v)) for v, t in TTL_OPTIONS],
        )
        self.one_btn = ft.IconButton(ft.icons.VISIBILITY_OFF_OUTLINED, tooltip="Просмотр один раз",
                                     on_click=lambda e: self._toggle_view_once())
        self.send_btn = ft.IconButton(ft.icons.SEND, tooltip="Отправить", icon_color=themes.ACCENT,
                                      on_click=lambda e: self.page.run_task(self._send))

        self.emoji_row = ft.Row(
            [ft.TextButton(em, on_click=lambda e, s=em: self._add_emoji(s)) for em in EMOJIS],
            visible=False,
        )

        input_area = ft.Column(
            [
                self.emoji_row,
                ft.Row([self.file_btn, self.emoji_btn, self.ttl_btn, self.one_btn,
                        self.input, self.send_btn]),
            ],
            spacing=2,
        )

        self.root = ft.Container(
            expand=True,
            padding=16,
            content=ft.Column(
                [header, ft.Divider(height=1), self.msgs_col, input_area],
                spacing=10,
            ),
        )

        # Файловый пикер (flet 0.85: on_result задаётся свойством, не конструктором)
        self.fp = ft.FilePicker()
        self.fp.on_result = self._on_pick
        page.overlay.append(self.fp)

        await self._setup_e2e()
        self._apply_screenshot_policy()
        await self._load_history()
        return self.root

    # ================= E2E и приватность =================
    async def _setup_e2e(self):
        """Вычисляет общий секрет E2E для личного чата (X25519 + HKDF).

        Приватный ключ устройства хранится в памяти (self.app.e2e_priv),
        публичный ключ собеседника запрашивается у сервера.
        """
        if self.chat["type"] != "personal":
            return
        priv = self.app.e2e_priv
        if not priv:
            return
        other = next((m for m in self.chat.get("members", [])
                      if m["id"] != self.app.api.user["id"]), None)
        if not other:
            return
        try:
            peer_pub = await self.app.api.e2e_get_key(other["id"])
            self.e2e_key = crypto.derive_chat_key(priv, peer_pub)
        except Exception:
            self.e2e_key = None  # собеседник без E2E — чат работает открытым

    def _apply_screenshot_policy(self):
        """Этап 3: FLAG_SECURE — запрет скриншотов в защищённых (ПИН) чатах."""
        blocked = bool(crypto.get_setting("prevent_screenshots", False)) and \
            crypto.has_chat_pin(self.chat_id)
        self.app.set_screenshot_blocked(blocked)

    # ================= ПИН-защита =================
    def _pin_screen(self) -> ft.Control:
        c = themes.colors(self.page)
        pin_f = ft.TextField(label="Введите ПИН чата", password=True, width=280,
                             keyboard_type=ft.KeyboardType.NUMBER,
                             on_submit=lambda e: self.page.run_task(self._unlock, pin_f))
        err = ft.Text(color="#FF6B6B", size=13, visible=False)

        def check(e):
            if crypto.check_chat_pin(self.chat_id, pin_f.value):
                self.unlocked = True
                self.page.run_task(self._rebuild)
            else:
                err.value = "Неверный ПИН"
                err.visible = True
                self.page.update()

        return ft.Container(
            alignment=ft.alignment.center,
            content=ft.Column(
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=14,
                controls=[
                    ft.Icon(ft.icons.LOCK_OUTLINE, size=64, color=themes.ACCENT),
                    ft.Text("Чат защищён ПИН", size=22, weight=ft.FontWeight.BOLD),
                    pin_f, err,
                    ft.FilledButton("Разблокировать", on_click=check),
                    ft.TextButton("← К списку чатов",
                                  on_click=lambda e: self.page.run_task(self.app.main_view.show_chats)),
                ],
            ),
        )

    async def _unlock(self, pin_f):
        pass  # резервный обработчик; используется синхронный check выше

    async def _rebuild(self):
        await self.app.main_view.open_chat(self.chat)

    def _chat_menu(self) -> ft.Control:
        locked = crypto.has_chat_pin(self.chat_id)
        return ft.PopupMenuButton(
            icon=ft.icons.MORE_VERT,
            items=[
                ft.PopupMenuItem(
                    content="Снять защиту ПИН" if locked else "Защитить чат ПИН",
                    on_click=lambda e: self.page.run_task(self._toggle_pin),
                ),
                ft.PopupMenuItem(content="Обновить", on_click=lambda e: self.page.run_task(self._load_history)),
            ],
        )

    async def _toggle_pin(self):
        if crypto.has_chat_pin(self.chat_id):
            crypto.remove_chat_pin(self.chat_id)
            await self.app.toast("Защита снята")
        else:
            pin = ft.TextField(label="Придумайте ПИН (4+ цифр)", password=True,
                               keyboard_type=ft.KeyboardType.NUMBER)
            dlg = ft.AlertDialog(
                title=ft.Text("Защита чата"),
                content=pin,
                actions=[
                    ft.TextButton("Отмена", on_click=lambda e: self.page.pop_dialog()),
                    ft.FilledButton("Установить", on_click=lambda e: self._save_pin(dlg, pin)),
                ],
            )
            self.page.show_dialog(dlg)
        await self._rebuild()

    def _save_pin(self, dlg, pin):
        if len(pin.value) < 4:
            return
        crypto.set_chat_pin(self.chat_id, pin.value)
        self.page.pop_dialog()
        self.page.run_task(self._rebuild)

    # ================= Сообщения =================
    async def _load_history(self):
        try:
            self.messages = await self.app.api.messages(self.chat_id)
        except ApiError as ex:
            await self.app.toast(ex.detail, error=True)
            return
        self._render_messages()

    def _render_messages(self):
        controls = [self._bubble(m) for m in self.messages]
        self.msgs_col.controls = controls
        self.page.update()

    def _decrypt(self, m: dict) -> dict:
        """Возвращает копию сообщения с расшифрованным текстом (E2E).

        Если ключ чата недоступен или расшифровка не удалась — сообщение
        остаётся помеченным e2e=True, и интерфейс показывает заглушку
        вместо шифротекста.
        """
        if not m.get("e2e") or not self.e2e_key:
            return m
        try:
            out = dict(m)
            out["content"] = crypto.decrypt_text(self.e2e_key, m.get("content") or "")
            out["e2e"] = False
            return out
        except Exception:
            return m

    def _bubble(self, m: dict) -> ft.Control:
        m = self._decrypt(m)  # расшифровываем E2E-контент для показа
        c = themes.colors(self.page)
        mine = m["sender_id"] == self.app.api.user["id"]
        bubble_color = c["bubble_me"] if mine else c["bubble_other"]

        content: ft.Control
        if m.get("e2e"):
            # Ключ чата недоступен (например, собеседник ещё не публиковал E2E-ключ)
            content = ft.Text("🔒 Зашифрованное сообщение", size=14,
                              italic=True, color=c["sub"])
        elif m["type"] == "image" and m.get("media_path"):
            content = ft.Image(src=self.app.api.file_url(m["media_path"]), width=230,
                               fit=ft.ImageFit.CONTAIN, border_radius=10)
        elif m["type"] == "emoji":
            content = ft.Text(m["content"], size=34)
        elif m["type"] in ("file", "voice") and m.get("media_path"):
            icon = "🎙️" if m["type"] == "voice" else "📎"
            content = ft.Text(f"{icon} {m['content'] or 'файл'}", size=14)
        else:
            content = ft.Text(m["content"] or "", size=15)

        extra = []
        sender_name = ""
        if self.chat["type"] == "group" and not mine:
            sender_name = m.get("sender_name") or ""
        if m.get("view_once"):
            extra.append(ft.Text(" 👁️ разовое", size=11, color=c["sub"]))
        if m.get("ttl_seconds"):
            extra.append(ft.Text(f" ⏳ {m['ttl_seconds']}с", size=11, color=c["sub"]))

        popup = ft.PopupMenuButton(
            icon=ft.icons.MORE_HORIZ, icon_size=16,
            items=[
                ft.PopupMenuItem(content="Пожаловаться",
                                 on_click=lambda e, mid=m["id"]: self.page.run_task(self._report, mid)),
                *([ft.PopupMenuItem(content="Удалить",
                                    on_click=lambda e, mid=m["id"]: self.page.run_task(self._delete, mid))]
                  if mine else []),
            ],
        )

        header = ft.Row(
            [
                ft.Text(sender_name, size=12, weight=ft.FontWeight.W_600,
                        color=themes.ACCENT if not mine else c["sub"]),
                ft.Text(_fmt_time(m["created_at"]), size=11, color=c["sub"]),
            ],
            spacing=4,
        ) if sender_name else ft.Row(
            [ft.Text(_fmt_time(m["created_at"]), size=11, color=c["sub"]), *extra],
            spacing=4,
        )

        return ft.Row(
            [
                ft.Container(expand=True) if mine else ft.Container(width=40),
                ft.Container(
                    padding=ft.padding.symmetric(10, 12),
                    border_radius=16,
                    bgcolor=bubble_color,
                    width=340 if m["type"] == "image" else None,
                    content=ft.Column(
                        [header, content, *([ft.Row(extra, spacing=2)] if extra and not sender_name else [])],
                        spacing=2,
                    ),
                ),
                popup if not mine else ft.Container(width=32),
                ft.Container(width=40) if not mine else ft.Container(expand=True),
            ],
            alignment=ft.MainAxisAlignment.START if not mine else ft.MainAxisAlignment.END,
        )

    # ---------- Действия ----------
    async def add_message(self, m: dict):
        # view_once: отметим просмотренным
        if m.get("view_once") and m["sender_id"] != self.app.api.user["id"]:
            try:
                await self.app.api.mark_viewed(m["id"])
            except Exception:
                pass
        self.messages.append(m)
        self.msgs_col.controls.append(self._bubble(m))
        self.page.update()

    async def remove_message(self, message_id: int):
        self.messages = [m for m in self.messages if m["id"] != message_id]
        self._render_messages()

    async def update_presence(self):
        self.presence_lbl.value = self._presence_text()
        self.page.update()

    def _presence_text(self) -> str:
        if self.chat["type"] == "group":
            return f"{len(self.chat.get('members', []))} участников"
        other = next((m for m in self.chat.get("members", []) if m["id"] != self.app.api.user["id"]), None)
        if other and other["id"] in self.app.online_ids:
            return "в сети"
        return "был(а) недавно"

    async def _send(self):
        text = self.input.value.strip()
        if not text and not self.pending_tx:
            return
        msg_type = "emoji" if text in EMOJIS else "text"
        content = text or self.pending_tx
        e2e = False
        # E2E (Этап 3): шифруем текст и эмодзи в личных чатах, если общий
        # секрет уже получен. Сервер хранит только шифротекст.
        if self.e2e_key and msg_type in ("text", "emoji"):
            try:
                content = crypto.encrypt_text(self.e2e_key, content)
                e2e = True
            except Exception:
                content = text or self.pending_tx  # при сбое — открытым текстом
        try:
            m = await self.app.api.send_message(
                self.chat_id, content,
                msg_type=msg_type,
                ttl_seconds=self.ttl, view_once=self.view_once,
                media_path=self.pending_tx if not text else "",
                e2e=e2e,
            )
        except ApiError as ex:
            await self.app.toast(ex.detail, error=True)
            return
        self.input.value = ""
        self.pending_tx = ""
        await self.add_message(m)

    async def _report(self, message_id: int):
        reason = ft.TextField(label="Причина жалобы", width=360)
        dlg = ft.AlertDialog(
            title=ft.Text("Пожаловаться на сообщение"),
            content=reason,
            actions=[
                ft.TextButton("Отмена", on_click=lambda e: self.page.pop_dialog()),
                ft.FilledButton(content="Отправить",
                                on_click=lambda e: self.page.run_task(self._send_report, dlg, message_id, reason)),
            ],
        )
        self.page.show_dialog(dlg)

    async def _send_report(self, dlg, message_id, reason):
        try:
            await self.app.api.report(message_id, reason.value)
            self.page.pop_dialog()
            await self.app.toast("Жалоба отправлена модератору")
        except ApiError as ex:
            await self.app.toast(ex.detail, error=True)

    async def _delete(self, message_id: int):
        try:
            await self.app.api.delete_message(message_id)
            await self.remove_message(message_id)
        except ApiError as ex:
            await self.app.toast(ex.detail, error=True)

    # ---------- Медиа, эмодзи, таймер ----------
    def _pick_file(self):
        self.fp.pick_files(allow_multiple=False)

    async def _on_pick(self, e: ft.FilePickerResultEvent):
        if not e.files:
            return
        f = e.files[0]
        ext = f.name.rsplit(".", 1)[-1].lower() if "." in f.name else ""
        try:
            path = await self.app.api.upload(f.path)
        except ApiError as ex:
            await self.app.toast(ex.detail, error=True)
            return
        msg_type = "image" if ext in IMG_EXT else "file"
        try:
            m = await self.app.api.send_message(self.chat_id, f.name, msg_type=msg_type, media_path=path)
        except ApiError as ex:
            await self.app.toast(ex.detail, error=True)
            return
        await self.add_message(m)

    def _add_emoji(self, em: str):
        self.input.value = (self.input.value or "") + em
        self.page.update()

    def _set_ttl(self, value):
        self.ttl = value
        # run_task принимает только корутинную функцию — передаём метод и аргумент
        self.page.run_task(self.app.toast, f"Таймер: {dict(TTL_OPTIONS)[value]}")

    def _toggle_view_once(self):
        self.view_once = not self.view_once
        self.one_btn.icon = (ft.icons.VISIBILITY_OFF if self.view_once
                             else ft.icons.VISIBILITY_OFF_OUTLINED)
        self.one_btn.icon_color = themes.ACCENT if self.view_once else None
        self.page.update()