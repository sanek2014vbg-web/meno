"""MeNo — список чатов."""
import flet as ft

import crypto
import themes
from api_client import ApiError


def _fmt_time(iso: str) -> str:
    try:
        h, m = iso.split(" ")[1].split(":")[:2]
        return f"{h}:{m}"
    except Exception:
        return ""


class ChatsList:
    def __init__(self, app):
        self.app = app
        self.chats: list = []
        self.list_col = ft.Column(spacing=6, scroll=ft.ScrollMode.AUTO, expand=True)

    # ---------- Сборка ----------
    def build(self) -> ft.Control:
        page = self.app.page
        c = themes.colors(page)
        header = ft.Row(
            [
                ft.Text("Чаты", size=26, weight=ft.FontWeight.BOLD),
                ft.IconButton(ft.icons.REFRESH, tooltip="Обновить",
                              on_click=lambda e: self.page.run_task(self.refresh)),
                ft.Container(expand=True),
                ft.FilledButton(content=ft.Row([
                    ft.Icon(ft.icons.ADD, size=18), ft.Text("Новый чат"),
                ]), on_click=lambda e: self._new_chat_dialog()),
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
        )
        self.root = ft.Container(
            expand=True,
            padding=20,
            content=ft.Column([header, self.list_col]),
        )
        page.run_task(self.refresh)
        return self.root

    @property
    def page(self):
        return self.app.page

    # ---------- Данные ----------
    async def refresh(self):
        try:
            self.chats = await self.app.api.chats()
        except ApiError as ex:
            await self.app.toast(f"Ошибка: {ex.detail}", error=True)
            return
        cards = [self._chat_card(ch) for ch in self.chats]
        if not cards:
            cards = [ft.Text("Пока нет чатов — создайте первый!", color=themes.colors(self.page)["sub"])]
        self.list_col.controls = cards
        self.page.update()

    def _chat_card(self, chat: dict) -> ft.Control:
        c = themes.colors(self.page)
        last = chat.get("last_message") or {}
        preview = last.get("content") or ("📷 Фото" if last.get("type") == "image" else "…")
        sender = f"{last.get('sender_name')}: " if last and last.get("sender_name") else ""
        time = _fmt_time(last.get("created_at", "")) if last else ""
        # Бейдж защиты: ПИН хранится локально на устройстве, поэтому смотрим
        # прямо в локальное хранилище клиента, а не в ответ сервера.
        badge = "🔒 " if crypto.has_chat_pin(chat["id"]) else ""
        return ft.Container(
            padding=14,
            border_radius=14,
            bgcolor=c["card"],
            ink=True,
            on_click=lambda e, ch=chat: self.page.run_task(self.app.main_view.open_chat, ch),
            content=ft.Row(
                [
                    ft.CircleAvatar(
                        radius=22,
                        bgcolor=themes.ACCENT,
                        content=ft.Text(chat["title"][:1].upper(), color="#0B0E14", weight=ft.FontWeight.BOLD),
                    ),
                    ft.Column(
                        [
                            ft.Text(badge + chat["title"], size=15, weight=ft.FontWeight.W_600, max_lines=1),
                            ft.Text(sender + preview, size=13, color=c["sub"], max_lines=1),
                        ],
                        spacing=2,
                        expand=True,
                    ),
                    ft.Text(time, size=12, color=c["sub"]),
                ]
            ),
        )

    # ---------- Новый чат ----------
    def _new_chat_dialog(self):
        c = themes.colors(self.page)
        self.seg = ft.SegmentedButton(
            segments=[
                ft.Segment(value="personal", label=ft.Text("Личный")),
                ft.Segment(value="group", label=ft.Text("Группа")),
            ],
            selected=["personal"],
            on_change=lambda e: self._toggle_group(),
        )
        self.phones = ft.TextField(
            label="Телефон собеседника (или несколько через запятую для группы)",
            hint_text="79991234567",
            width=420,
        )
        self.title_f = ft.TextField(label="Название группы", width=420, visible=False)
        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("Новый чат"),
            content=ft.Column(
                width=440,
                tight=True,
                controls=[self.seg, self.phones, self.title_f],
            ),
            actions=[
                ft.TextButton("Отмена", on_click=lambda e: self.page.pop_dialog()),
                ft.FilledButton(content="Создать",
                                on_click=lambda e: self.page.run_task(self._create, dlg)),
            ],
        )
        self.page.show_dialog(dlg)

    def _toggle_group(self):
        group = (self.seg.selected[0] if isinstance(self.seg.selected, list) else self.seg.selected) == "group"
        self.title_f.visible = group
        self.phones.label = "Телефоны участников через запятую" if group else "Телефон собеседника"
        self.page.update()

    async def _create(self, dlg):
        group = (self.seg.selected[0] if isinstance(self.seg.selected, list) else self.seg.selected) == "group"
        phones = [p.strip() for p in self.phones.value.split(",") if p.strip()]
        if not phones:
            return
        self.page.pop_dialog()
        user_ids = []
        try:
            for ph in phones:
                res = await self.app.api.search_users(ph)
                match = next((u for u in res if u["phone"] == ph), None)
                if not match:
                    await self.app.toast(f"Пользователь {ph} не найден", error=True)
                    return
                user_ids.append(match["id"])
            title = self.title_f.value.strip() if group else ""
            chat = await self.app.api.create_chat("group" if group else "personal", user_ids, title)
            await self.app.main_view.open_chat(chat)
        except ApiError as ex:
            await self.app.toast(ex.detail, error=True)