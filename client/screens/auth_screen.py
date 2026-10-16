"""MeNo — экран входа/регистрации."""
import flet as ft

import crypto
import themes
from api_client import ApiClient, ApiError


class AuthScreen:
    def __init__(self, app):
        self.app = app
        self.mode = "login"

    # ---------- Сборка интерфейса ----------
    def build(self) -> ft.Control:
        page = self.app.page
        dark = page.theme_mode != ft.ThemeMode.LIGHT
        logo = "assets/logo_dark.png" if dark else "assets/logo_light.png"
        c = themes.colors(page)

        self.server = ft.TextField(
            label="Адрес сервера",
            value=crypto.get_setting("server_url", "http://127.0.0.1:8000"),
            width=360,
            prefix_icon=ft.icons.DNS,
        )
        self.username = ft.TextField(
            label="Имя пользователя",
            hint_text="например, alice_92",
            width=360,
            prefix_icon=ft.icons.PERSON,
        )
        self.password = ft.TextField(
            label="Пароль",
            password=True,
            can_reveal_password=True,
            width=360,
            on_submit=lambda e: self.app.page.run_task(self._on_submit),
        )
        self.totp = ft.TextField(label="Код 2FA (если включена)", width=360, visible=False)

        self.seg = ft.SegmentedButton(
            segments=[
                ft.Segment(value="login", label=ft.Text("Вход")),
                ft.Segment(value="register", label=ft.Text("Регистрация")),
            ],
            selected=["login"],
            on_change=self._on_mode_change,
        )

        self.btn = ft.FilledButton(
            content="Войти", width=360, height=44,
            on_click=lambda e: self.app.page.run_task(self._on_submit),
        )
        self.err = ft.Text(color="#FF6B6B", size=13, visible=False)

        return ft.Container(
            alignment=ft.alignment.center,
            content=ft.Column(
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=14,
                controls=[
                    ft.Image(src=logo, width=130, height=130),
                    ft.Text(themes.APP_NAME, size=34, weight=ft.FontWeight.BOLD,
                            color=themes.ACCENT),
                    self.seg,
                    self.server,
                    self.username,
                    self.password,
                    self.totp,
                    self.btn,
                    self.err,
                    ft.TextButton("Забыли пароль?", visible=False),
                ],
            ),
        )

    # ---------- Логика ----------
    def _on_mode_change(self, e):
        self.mode = e.control.selected[0] if isinstance(e.control.selected, list) else str(e.control.selected)
        registering = self.mode == "register"
        self.btn.content = "Создать аккаунт" if registering else "Войти"
        self.password.label = "Придумайте пароль (мин. 6 символов)" if registering else "Пароль"
        self.app.page.update()

    async def _on_submit(self):
        url = self.server.value.strip()
        username = self.username.value.strip().lower()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        if url != self.app.api.base_url:
            await self.app.api.close()
            self.app.api = ApiClient(url)
            crypto.save_setting("server_url", url)

        if not username:
            return self._show_err("Введите имя пользователя")
        if self.mode == "login":
            await self._do_login(username)
        else:
            await self._do_register(username)

    def _show_err(self, msg: str):
        self.err.value = msg
        self.err.visible = True
        self.app.page.update()

    async def _do_login(self, username: str):
        self.btn.disabled = True
        self.app.page.update()
        try:
            await self.app.api.login(username, self.password.value, self.totp.value.strip())
        except ApiError as ex:
            if "2FA" in ex.detail:
                self.totp.visible = True
                self.app.page.update()
            self._show_err(ex.detail)
            self.btn.disabled = False
            self.app.page.update()
            return
        await self._enter(self.password.value)
        self.btn.disabled = False

    async def _do_register(self, username: str):
        """Регистрация без телефона и кодов: username + пароль сразу создаёт аккаунт."""
        self.btn.disabled = True
        self.app.page.update()
        try:
            await self.app.api.register(username, self.password.value)
        except ApiError as ex:
            self._show_err(ex.detail)
            self.btn.disabled = False
            self.app.page.update()
            return
        self.btn.disabled = False
        await self._enter(self.password.value)

    async def _enter(self, password: str):
        """Вход выполнен: E2E-ключи, WebSocket и главное окно.

        WebSocket запускается фоновой задачей с авто-переподключением;
        статус «Подключение…» мягко показывается в шапке.
        """
        await self.app.after_login(password)
        await self.app.start_ws()
        await self.app.show_main()