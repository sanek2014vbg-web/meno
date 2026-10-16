"""MeNo — настройки: темы, сервер, аккаунт, 2FA владельца."""
import flet as ft

import crypto
import themes
from api_client import ApiError


class SettingsView:
    def __init__(self, app):
        self.app = app

    @property
    def page(self):
        return self.app.page

    def build(self) -> ft.Control:
        c = themes.colors(self.page)
        user = self.app.api.user or {}
        is_admin = user.get("role") == "admin"

        # --- Тема ---
        current = crypto.get_setting("theme", "dark")
        self.theme_seg = ft.SegmentedButton(
            segments=[
                ft.Segment(value="system", label=ft.Text("Авто")),
                ft.Segment(value="light", label=ft.Text("Светлая")),
                ft.Segment(value="dark", label=ft.Text("Тёмная")),
            ],
            selected=[current],
            on_change=self._on_theme,
        )

        # --- Сервер ---
        self.server_f = ft.TextField(
            label="Адрес сервера",
            value=crypto.get_setting("server_url", "http://127.0.0.1:8000"),
            width=380,
        )

        # --- Приватность: блокировка скриншотов (FLAG_SECURE) ---
        self.ss_block = ft.Switch(
            value=bool(crypto.get_setting("prevent_screenshots", False)),
            label="Блокировать скриншоты в защищённых чатах",
            on_change=self._on_ss_block,
        )

        # --- 2FA (для владельца) ---
        self.twofa_state = ft.Text("Выключена", color=c["sub"])
        self.twofa_btn = ft.FilledButton(
            content="Включить 2FA", on_click=lambda e: self.page.run_task(self._twofa_toggle)
        )

        sections = [
            self._card("🌗 Темы оформления", [
                self.theme_seg,
                ft.Text("Авто — следует за настройками устройства", size=12, color=c["sub"]),
            ]),
            self._card("🔒 Приватность", [
                self.ss_block,
                ft.Text("FLAG_SECURE: на Android запрещает скриншоты в чатах, "
                        "защищённых ПИН (работает на мобильных устройствах)",
                        size=12, color=c["sub"]),
            ]),
            self._card("🖥 Сервер", [self.server_f, ft.Row([
                ft.FilledButton("Сохранить", on_click=lambda e: self.page.run_task(self._save_server)),
                ft.Text("Потребуется повторный вход", size=12, color=c["sub"]),
            ])]),
            self._card("👤 Аккаунт", [
                ft.Text(f"@{user.get('username', '')}", size=14),
                ft.Text(f"Имя: {user.get('display_name', '') or '—'}", size=14),
                ft.Text(f"Роль: {'Владелец (DevMode)' if is_admin else 'Пользователь'}", size=14,
                        color=themes.ACCENT if is_admin else c["sub"]),
            ]),
            *([self._card("🔐 Двухфакторная аутентификация (2FA)", [
                ft.Text("Защита входа владельца одноразовыми кодами (Google Authenticator)"),
                self.twofa_state,
                self.twofa_btn,
            ])] if is_admin else []),
            *([self._card("🛠 DevMode", [
                ft.FilledButton("Открыть панель владельца",
                                icon=ft.icons.ADMIN_PANEL_SETTINGS,
                                on_click=lambda e: self.page.run_task(self._open_devmode)),
            ])] if is_admin else []),
            self._card("Выход", [
                ft.OutlinedButton("Выйти из аккаунта", icon=ft.icons.LOGOUT,
                                  style=ft.ButtonStyle(color="#FF6B6B"),
                                  on_click=lambda e: self.page.run_task(self.app.logout)),
            ]),
        ]

        return ft.Container(
            expand=True,
            padding=20,
            content=ft.Column(
                [ft.Text("Настройки", size=26, weight=ft.FontWeight.BOLD),
                 ft.Column(sections, spacing=14, scroll=ft.ScrollMode.AUTO, expand=True)],
                spacing=14,
            ),
        )

    def _card(self, title: str, controls: list) -> ft.Control:
        c = themes.colors(self.page)
        return ft.Container(
            padding=16, border_radius=14, bgcolor=c["card"],
            content=ft.Column(
                [ft.Text(title, size=16, weight=ft.FontWeight.W_600), *controls], spacing=10,
            ),
        )

    # ---------- Логика ----------
    def _on_ss_block(self, e):
        """Переключатель FLAG_SECURE: настройка хранится локально."""
        val = bool(e.control.value)
        crypto.save_setting("prevent_screenshots", val)
        self.app.set_screenshot_blocked(val)
        self.page.update()

    async def _on_theme(self, e):
        sel = e.control.selected[0] if isinstance(e.control.selected, list) else str(e.control.selected)
        crypto.save_setting("theme", sel)
        themes.apply_theme(self.page, sel)
        # Пересобираем экран настроек, чтобы карточки и тексты
        # перекрасились под выбранную палитру.
        await self.app.main_view.set_body(SettingsView(self.app).build())

    async def _save_server(self):
        url = self.server_f.value.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        crypto.save_setting("server_url", url)
        await self.app.toast("Адрес сохранён — выполните вход заново")
        await self.app.logout()

    async def _open_devmode(self):
        from screens.devmode_screen import DevModeView
        await self.app.main_view.set_body(DevModeView(self.app).build())

    # ---------- 2FA ----------
    async def _twofa_toggle(self):
        try:
            if self.app.api.user and self.app.api.user.get("twofa_enabled"):
                # выключить
                code_f = ft.TextField(label="Текущий код 2FA", width=300)
                dlg = ft.AlertDialog(
                    title=ft.Text("Выключить 2FA"),
                    content=code_f,
                    actions=[
                        ft.TextButton("Отмена", on_click=lambda e: self.page.pop_dialog()),
                        ft.FilledButton(content="Выключить",
                                        on_click=lambda e: self.page.run_task(self._twofa_disable, dlg, code_f)),
                    ],
                )
                self.page.show_dialog(dlg)
                return
            # включить
            data = await self.app.api.totp_setup()
            dlg = ft.AlertDialog(
                title=ft.Text("Включение 2FA"),
                content=ft.Column(width=400, tight=True, controls=[
                    ft.Text("1. Добавьте секрет в Google Authenticator (или по ссылке):"),
                    ft.Text(data["uri"], size=11, selectable=True),
                    ft.Text("2. Введите текущий код из приложения:"),
                    ft.TextField(label="Код 2FA", keyboard_type=ft.KeyboardType.NUMBER, max_length=6),
                ]),
                actions=[
                    ft.TextButton("Отмена", on_click=lambda e: self.page.pop_dialog()),
                    ft.FilledButton("Активировать", on_click=lambda e: self._twofa_enable(dlg, data)),
                ],
            )
            self.page.show_dialog(dlg)
        except ApiError as ex:
            await self.app.toast(ex.detail, error=True)

    def _twofa_enable(self, dlg, data):
        code = dlg.content.controls[-1].value
        self.page.run_task(self._do_enable, dlg, code)

    async def _do_enable(self, dlg, code):
        try:
            await self.app.api.totp_enable(code)
            self.page.pop_dialog()
            self.twofa_state.value = "Включена ✅"
            self.twofa_btn.content = "Выключить 2FA"
            self.page.update()
            await self.app.toast("2FA включена")
        except ApiError as ex:
            await self.app.toast(ex.detail, error=True)

    async def _twofa_disable(self, dlg, code_f):
        try:
            await self.app.api.totp_disable(code_f.value)
            self.page.pop_dialog()
            self.twofa_state.value = "Выключена"
            self.twofa_btn.content = "Включить 2FA"
            self.page.update()
        except ApiError as ex:
            await self.app.toast(ex.detail, error=True)