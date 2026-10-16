"""MeNo — DevMode: панель владельца (мониторинг, модерация, настройки)."""
import flet as ft

import themes
from api_client import ApiError


class DevModeView:
    def __init__(self, app):
        self.app = app
        self.stats_row = ft.Row(spacing=12)
        self.reports_col = ft.Column(spacing=8, scroll=ft.ScrollMode.AUTO, expand=True)
        self.settings_col = ft.Column(spacing=8, scroll=ft.ScrollMode.AUTO)

    @property
    def page(self):
        return self.app.page

    def build(self) -> ft.Control:
        c = themes.colors(self.page)
        self.key_f = ft.TextField(label="Ключ", width=200)
        self.val_f = ft.TextField(label="Значение", width=300, expand=True)
        self.page.run_task(self._load)
        return ft.Container(
            expand=True,
            padding=20,
            content=ft.Column(
                [
                    ft.Row([
                        ft.Text("DevMode", size=26, weight=ft.FontWeight.BOLD,
                                color=themes.ACCENT),
                        ft.Icon(ft.icons.GPP_GOOD, color=themes.ACCENT),
                        ft.Container(expand=True),
                        ft.IconButton(ft.icons.REFRESH, on_click=lambda e: self.page.run_task(self._load)),
                    ]),
                    self.stats_row,
                    ft.Divider(),
                    ft.Text("Жалобы на модерацию", size=16, weight=ft.FontWeight.W_600),
                    self.reports_col,
                    ft.Divider(),
                    ft.Text("Глобальные настройки", size=16, weight=ft.FontWeight.W_600),
                    self.settings_col,
                    ft.Row([
                        self.key_f,
                        self.val_f,
                        ft.FilledButton("Добавить", on_click=lambda e: self.page.run_task(self._add_setting)),
                    ]),
                ],
                spacing=12,
            ),
        )

    # ---------- Данные ----------
    async def _load(self):
        await self._load_stats()
        await self._load_reports()
        await self._load_settings()

    async def _load_stats(self):
        try:
            s = await self.app.api.admin_stats()
        except ApiError as ex:
            await self.app.toast(f"Нет доступа: {ex.detail}", error=True)
            return
        labels = [
            ("Пользователи", s.get("users", 0)),
            ("Чаты", s.get("chats", 0)),
            ("Сообщения", s.get("messages", 0)),
            ("Онлайн", s.get("online_now", 0)),
            ("Жалобы", s.get("open_reports", 0)),
        ]
        c = themes.colors(self.page)
        cards = [
            ft.Container(
                padding=14, border_radius=12, bgcolor=c["card"], width=150,
                content=ft.Column([
                    ft.Text(str(v), size=24, weight=ft.FontWeight.BOLD, color=themes.ACCENT),
                    ft.Text(k, size=12, color=c["sub"]),
                ]),
            )
            for k, v in labels
        ]
        self.stats_row.controls = cards
        self.page.update()

    async def _load_reports(self):
        try:
            reports = await self.app.api.admin_reports()
        except ApiError:
            return
        c = themes.colors(self.page)
        cards = []
        for r in reports:
            cards.append(ft.Container(
                padding=12, border_radius=12, bgcolor=c["card"],
                content=ft.Column([
                    ft.Text(f"Жалоба #{r['id']} · {r['reporter_name']}", weight=ft.FontWeight.W_600),
                    ft.Text(f"Чат: {r.get('chat_title') or r['chat_id']} · Сообщение: «{r.get('msg_content') or '[медиа]'}»",
                            size=13, color=c["sub"]),
                    ft.Row([
                        ft.FilledButton(content="Удалить сообщение", icon=ft.icons.DELETE_FOREVER,
                                        on_click=lambda e, rid=r["id"]: self.page.run_task(self._moderate, rid, "delete_message")),
                        ft.OutlinedButton(content="Закрыть жалобу",
                                          on_click=lambda e, rid=r["id"]: self.page.run_task(self._moderate, rid, "resolve")),
                    ]),
                ]),
            ))
        self.reports_col.controls = cards if cards else [ft.Text("Нет открытых жалоб", color=c["sub"])]
        self.page.update()

    async def _load_settings(self):
        try:
            settings = await self.app.api.admin_settings()
        except ApiError:
            return
        c = themes.colors(self.page)
        rows = [ft.Row([
            ft.Text(k, weight=ft.FontWeight.W_500, width=180),
            ft.Text(str(v), color=c["sub"], expand=True),
        ]) for k, v in settings.items()]
        self.settings_col.controls = rows if rows else [ft.Text("Пока нет настроек", color=c["sub"])]
        self.page.update()

    # ---------- Действия ----------
    async def _moderate(self, report_id: int, action: str):
        try:
            res = await self.app.api.admin_moderation(report_id, action)
            await self.app.toast(res.get("message", "Готово"))
        except ApiError as ex:
            await self.app.toast(ex.detail, error=True)
        await self._load()

    async def _add_setting(self):
        try:
            await self.app.api.admin_set_setting(self.key_f.value.strip(), self.val_f.value.strip())
            self.key_f.value = ""
            self.val_f.value = ""
            await self.app.toast("Настройка сохранена")
        except ApiError as ex:
            await self.app.toast(ex.detail, error=True)
        await self._load_settings()