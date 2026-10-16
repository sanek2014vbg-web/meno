"""MeNo — точка входа Flet-приложения.

Запуск:  flet run main.py   (или  python main.py)

Боевые свойства:
- каталог данных (настройки, ключи, хранилище токенов) автоматически
  выбирается под платформу (Windows / Android / веб-сервер);
- WebSocket-канал живёт отдельной задачей: авто-переподключение
  с уведомлением «Подключение…» в шапке, без блокировки UI;
- FLAG_SECURE недоступен в веб-версии — факт логируется, приложение
  не падает (try/except).
"""
import os

import icons_compat  # noqa: F401  — восстанавливает ft.icons.* (flet 0.85+)

# На Android (Chaquopy/Flet) каталог данных задаётся окружением:
# переносим его значение в MENO_DATA_DIR до импорта crypto.
if not os.environ.get("MENO_DATA_DIR"):
    for _var in ("FLET_APP_STORAGE_DATA",):
        _val = os.environ.get(_var)
        if _val:
            os.environ["MENO_DATA_DIR"] = _val
            break

import asyncio

import flet as ft

import crypto
import themes
from api_client import ApiClient


class App:
    """Глобальное состояние клиента: страница, API, навигация."""

    def __init__(self, page: ft.Page):
        self.page = page
        self.api = ApiClient(crypto.get_setting("server_url", "http://127.0.0.1:8000"))
        self.online_ids: set[int] = set()
        self.main_view = None
        self.content = ft.Container(expand=True)
        self.e2e_priv: str | None = None  # расшифрованный приватный ключ X25519 (в памяти)
        self.ws_task: asyncio.Task | None = None
        self.conn_online: bool | None = None  # None — не запущено, False — «Подключение…»

    # ---------- Навигация ----------
    async def init(self):
        self.page.title = themes.APP_NAME
        self.page.window.width = 1020
        self.page.window.height = 720
        self.page.padding = 0
        self.page.spacing = 0
        themes.apply_theme(self.page, crypto.get_setting("theme", "dark"))
        self.page.add(self.content)
        await self.show_login()

    async def set_view(self, control: ft.Control):
        self.content.content = control
        self.page.update()

    async def toast(self, msg: str, error: bool = False):
        color = "#FF6B6B" if error else themes.PALETTES["dark"]["text"]
        self.page.show_dialog(ft.SnackBar(ft.Text(msg, color=color), duration=3000))
        self.page.update()

    async def show_login(self):
        from screens.auth_screen import AuthScreen
        await self.set_view(AuthScreen(self).build())

    async def after_login(self, password: str):
        """Этап 3 (E2E): гарантируем ключи устройства и публикуем открытый ключ на сервере.

        Ошибки шифрования не должны блокировать вход — чаты продолжат работать
        без E2E, если ключи недоступны.
        """
        try:
            priv, _pub = crypto.ensure_keys(password)
            self.e2e_priv = priv
            await self.api.e2e_set_key(crypto.get_public_key() or _pub)
        except Exception:
            self.e2e_priv = None

    def set_screenshot_blocked(self, blocked: bool):
        """Этап 3: FLAG_SECURE — запрет скриншотов в защищённых чатах (мобильные).

        В веб-версии свойство window.prevent_screenshot отсутствует —
        логируем факт недоступности и не допускаем падения приложения.
        """
        try:
            self.page.window.prevent_screenshot = bool(blocked)
        except AttributeError:
            # Веб/десктоп: нативного метода нет — только информируем
            print("[MeNo] FLAG_SECURE недоступен в текущей сборке (веб/десктоп)")
        except Exception:
            pass

    async def show_main(self):
        if self.main_view is None:
            from screens.main_view import MainView
            self.main_view = MainView(self)
        await self.main_view.show()

    # ---------- WebSocket: жизненный цикл ----------
    async def start_ws(self):
        """Запускает фоновую задачу WebSocket с авто-переподключением."""
        self.stop_ws()
        self.set_connection_status(False)  # сначала показываем «Подключение…»
        self.ws_task = asyncio.create_task(
            self.api.ws_listen(self.on_ws_event, on_status=self.set_connection_status)
        )

    def stop_ws(self):
        if self.ws_task is not None:
            self.ws_task.cancel()
            self.ws_task = None
        self.conn_online = None

    def set_connection_status(self, online: bool):
        """Мягкое уведомление о статусе соединения в шапке приложения."""
        self.conn_online = bool(online)
        if self.main_view is not None:
            try:
                self.main_view.set_conn_status(bool(online))
            except Exception:
                pass

    async def logout(self):
        self.stop_ws()
        await self.api.close()
        self.api = ApiClient(crypto.get_setting("server_url", "http://127.0.0.1:8000"))
        self.online_ids.clear()
        self.main_view = None
        self.e2e_priv = None
        self.set_screenshot_blocked(False)
        await self.show_login()

    # ---------- События WebSocket ----------
    async def on_ws_event(self, msg: dict):
        t = msg.get("type")
        if t == "presence":
            uid = msg.get("user_id")
            if msg.get("online"):
                self.online_ids.add(uid)
            else:
                self.online_ids.discard(uid)
        if self.main_view:
            await self.main_view.on_event(t, msg)


async def main(page: ft.Page):
    app = App(page)
    await app.init()


if __name__ == "__main__":
    ft.run(main)