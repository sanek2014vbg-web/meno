"""MeNo — экран подтверждения кода при регистрации."""
import flet as ft

import themes
from api_client import ApiError


class VerifyScreen:
    def __init__(self, app, phone: str):
        self.app = app
        self.phone = phone

    def build(self) -> ft.Control:
        page = self.app.page
        c = themes.colors(page)

        self.code = ft.TextField(
            label="Код из сообщения", hint_text="6 цифр", width=360,
            keyboard_type=ft.KeyboardType.NUMBER, max_length=6,
            prefix_icon=ft.icons.PIN,
        )
        self.name = ft.TextField(
            label="Ваше имя", width=360, prefix_icon=ft.icons.BADGE,
        )
        self.password = ft.TextField(
            label="Придумайте пароль (мин. 4 символа)", width=360,
            password=True, can_reveal_password=True,
        )
        self.btn = ft.FilledButton(
            content="Создать аккаунт", width=360, height=44,
            on_click=lambda e: self.app.page.run_task(self._submit),
        )
        self.err = ft.Text(color="#FF6B6B", size=13, visible=False)

        return ft.Container(
            alignment=ft.alignment.center,
            content=ft.Column(
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=14,
                controls=[
                    ft.Icon(ft.icons.VERIFIED_USER_OUTLINED, size=72, color=themes.ACCENT),
                    ft.Text("Регистрация", size=26, weight=ft.FontWeight.BOLD),
                    ft.Text(f"Номер: {self.phone}", size=14, color=c["sub"]),
                    self.code,
                    self.name,
                    self.password,
                    self.btn,
                    self.err,
                    ft.TextButton("← Назад", on_click=lambda e: self.app.page.run_task(self._back)),
                ],
            ),
        )

    async def _submit(self):
        self.btn.disabled = True
        self.app.page.update()
        try:
            await self.app.api.verify(
                self.phone, self.code.value.strip(),
                self.password.value, self.name.value.strip(),
            )
        except ApiError as ex:
            self.err.value = ex.detail
            self.err.visible = True
            self.app.page.update()
            self.btn.disabled = False
            return
        await self.app.after_login(self.password.value)
        await self.app.start_ws()
        await self.app.show_main()

    async def _back(self):
        from screens.auth_screen import AuthScreen
        await self.app.set_view(AuthScreen(self.app).build())