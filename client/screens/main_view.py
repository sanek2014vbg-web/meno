"""MeNo — главное окно: шапка со статусом соединения, навигация и контент."""
import flet as ft

import themes


class MainView:
    def __init__(self, app):
        self.app = app
        self.chat_view = None  # открытое окно переписки (если есть)
        self.body = ft.Container(expand=True)
        self.rail = ft.NavigationRail(
            selected_index=0,
            label_type=ft.NavigationRailLabelType.ALL,
            min_width=90,
            destinations=[
                ft.NavigationRailDestination(
                    icon=ft.icons.CHAT_BUBBLE_OUTLINE, selected_icon=ft.icons.CHAT_BUBBLE,
                    label="Чаты",
                ),
                ft.NavigationRailDestination(
                    icon=ft.icons.SETTINGS_OUTLINED, selected_icon=ft.icons.SETTINGS,
                    label="Настройки",
                ),
                ft.NavigationRailDestination(
                    icon=ft.icons.ADMIN_PANEL_SETTINGS_OUTLINED,
                    selected_icon=ft.icons.ADMIN_PANEL_SETTINGS,
                    label="DevMode",
                ),
            ],
            on_change=self._on_rail_change,
        )

        # --- Шапка: мягкий индикатор статуса соединения ---
        # «Подключение…» — идёт установка/восстановление WebSocket-канала;
        # индикатор не блокирует UI и не сбрасывает позицию скролла чата.
        self.conn_dot = ft.Container(
            width=9, height=9, border_radius=5, bgcolor="#FFB020",
        )
        self.conn_lbl = ft.Text("Подключение…", size=12, color=themes.colors(app.page)["sub"])
        self.conn_row = ft.Row([self.conn_dot, self.conn_lbl], spacing=6)

        self.header = ft.Container(
            content=ft.Row(
                [
                    ft.Text(themes.APP_NAME, size=20, weight=ft.FontWeight.BOLD,
                            color=themes.ACCENT),
                    self.conn_row,
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            ),
            padding=ft.padding.symmetric(horizontal=16, vertical=8),
            bgcolor=themes.colors(app.page)["card"],
        )

        self.root = ft.Column(
            [
                self.header,
                ft.Row([self.rail, ft.VerticalDivider(width=1), self.body], expand=True),
            ],
            spacing=0,
            expand=True,
        )

    # ---------- Статус соединения ----------
    def set_conn_status(self, online: bool):
        """Обновляет индикатор «В сети / Подключение…» в шапке."""
        c = themes.colors(self.app.page)
        if online:
            self.conn_dot.bgcolor = "#4CAF50"
            self.conn_lbl.value = "В сети"
            self.conn_lbl.color = "#4CAF50"
        else:
            self.conn_dot.bgcolor = "#FFB020"
            self.conn_lbl.value = "Подключение…"
            self.conn_lbl.color = c["sub"]
        try:
            self.app.page.update()
        except Exception:
            pass

    # ---------- Навигация ----------
    async def show(self):
        page = self.app.page
        page.clean()
        page.add(self.root)
        await self.show_chats()

    async def set_body(self, control: ft.Control):
        self.body.content = control
        self.page.update()

    @property
    def page(self):
        return self.app.page

    async def _on_rail_change(self, e):
        idx = e.control.selected_index
        if idx == 0:
            await self.show_chats()
        elif idx == 1:
            from screens.settings_screen import SettingsView
            await self.set_body(SettingsView(self.app).build())
        elif idx == 2:
            from screens.devmode_screen import DevModeView
            await self.set_body(DevModeView(self.app).build())

    async def show_chats(self):
        from screens.chats_list import ChatsList
        self.chat_view = None
        await self.set_body(ChatsList(self.app).build())

    async def open_chat(self, chat: dict):
        from screens.chat_view import ChatView
        self.chat_view = ChatView(self.app, chat)
        await self.set_body(await self.chat_view.build())

    # ---------- События реалтайма ----------
    async def on_event(self, event_type: str, msg: dict):
        if event_type == "new_message":
            m = msg.get("message", {})
            if self.chat_view and self.chat_view.chat_id == m.get("chat_id"):
                await self.chat_view.add_message(m)
            else:
                await self._refresh_list()
        elif event_type == "message_deleted":
            if self.chat_view and self.chat_view.chat_id == msg.get("chat_id"):
                await self.chat_view.remove_message(msg.get("message_id"))
            else:
                await self._refresh_list()
        elif event_type == "presence":
            if self.chat_view:
                await self.chat_view.update_presence()

    async def _refresh_list(self):
        body = self.body.content
        if body is not None and hasattr(body, "refresh"):
            await body.refresh()