"""MeNo — клиент API сервера (HTTP + WebSocket), асинхронный.

Боевые свойства:
- автоматические повторные попытки (Retries) с экспоненциальной
  задержкой при обрыве интернета: 1s, 2s, 4s;
- WebSocket: авто-переподключение при потере соединения;
- динамическая смена адреса сервера: reconfigure();
- токены авторизации сохраняются в изолированном зашифрованном
  хранилище (crypto.vault_*) и восстанавливаются при создании клиента.
- Автоматическое обновление токена (Token Rotation): при 401 ошибке
  клиент пытается обновить Access-токен через Refresh-токен.
"""
import asyncio
import json
from typing import Awaitable, Callable, Optional

import httpx

import crypto

MAX_RETRIES = 3          # сколько повторных попыток после первой
RETRY_BASE_DELAY = 1.0   # экспоненциальная задержка: 1, 2, 4 с
RETRY_MAX_DELAY = 8.0    # верхняя граница задержки
WS_RECONNECT_MAX = 30.0  # максимум ожидания перед переподключением WS


class ApiError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _retry_delay(attempt: int) -> float:
    return min(RETRY_BASE_DELAY * (2 ** attempt), RETRY_MAX_DELAY)


class ApiClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8000", phone: str = ""):
        self.base_url = base_url.rstrip("/")
        self.phone = phone
        self._http: Optional[httpx.AsyncClient] = None
        self.token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.user: Optional[dict] = None
        self._create_session()
        # Восстанавливаем токены из изолированного хранилища
        if phone:
            tokens = crypto.vault_load_tokens(phone)
            if tokens:
                self.token = tokens.get("access")
                self.refresh_token = tokens.get("refresh")

    # ---------- Управление сессией ----------
    def _create_session(self) -> None:
        """Создаёт новую базовую HTTP-сессию под текущий base_url."""
        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=10.0),
            follow_redirects=True,
        )

    async def reconfigure(self, base_url: str, phone: str = "") -> None:
        """Смена адреса сервера: полностью пересоздаёт базовую сессию."""
        if self._http is not None:
            try:
                await self._http.aclose()
            except Exception:
                pass
        self.base_url = base_url.rstrip("/")
        if phone:
            self.phone = phone
        self.token = None
        self.refresh_token = None
        self.user = None
        self._create_session()

    async def close(self) -> None:
        if self._http is not None:
            try:
                await self._http.aclose()
            except Exception:
                pass

    # ---------- Базовые запросы ----------
    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    async def _req(self, method: str, path: str, **kw) -> dict:
        """HTTP-запрос с ретраями и автоматическим обновлением токена."""
        r: Optional[httpx.Response] = None
        
        for attempt in range(MAX_RETRIES + 1):
            try:
                r = await self._http.request(
                    method, self.base_url + path, headers=self._headers(), **kw
                )
                
                # Если получили 401 (Unauthorized), пробуем обновить токен один раз
                if r.status_code == 401 and self.refresh_token:
                    success, new_tokens = await self._try_refresh_token()
                    if success:
                        self.token = new_tokens["access_token"]
                        self.refresh_token = new_tokens.get("refresh_token", self.refresh_token)
                        crypto.vault_save_tokens(self.phone, {
                            "access": self.token, 
                            "refresh": self.refresh_token
                        })
                        # Повторяем запрос с новым токеном
                        r = await self._http.request(
                            method, self.base_url + path, headers=self._headers(), **kw
                        )
                    else:
                        # Обновить не удалось - разлогиниваемся
                        self.token = None
                        self.refresh_token = None
                        crypto.vault_clear_tokens(self.phone)
                        raise ApiError(401, "Сессия истекла, пожалуйста, войдите снова")

            except httpx.TransportError as exc:
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(_retry_delay(attempt))
                    continue
                raise ApiError(0, f"Нет соединения с сервером ({exc.__class__.__name__})")
            
            if r and r.status_code in (502, 503, 504) and attempt < MAX_RETRIES:
                await asyncio.sleep(_retry_delay(attempt))
                continue
            break

        assert r is not None
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except Exception:
                detail = r.text
            raise ApiError(r.status_code, str(detail))
        return r.json() if r.content else {}

    async def _try_refresh_token(self) -> tuple[bool, Optional[dict]]:
        """Пытается обновить Access токен через Refresh токен."""
        try:
            # Используем внутренний httpx запрос, чтобы не попасть в рекурсию _req
            resp = await self._http.post(
                self.base_url + "/api/refresh",
                json={"refresh_token": self.refresh_token},
                timeout=10.0
            )
            if resp.status_code == 200:
                data = resp.json()
                # Сервер возвращает {"access_token": "..."}
                return True, {"access_token": data["access_token"]}
        except Exception:
            pass
        return False, None

    # ---------- Аутентификация ----------
    async def register(self, phone: str) -> str:
        """Запросить код подтверждения."""
        return (await self._req("POST", "/api/register", json={"phone": phone}))["message"]

    async def verify(self, phone: str, code: str, password: str, display_name: str) -> dict:
        data = await self._req(
            "POST", "/api/verify",
            json={"phone": phone, "code": code, "password": password, "display_name": display_name},
        )
        # Сервер возвращает {"tokens": {"access_token": "...", "refresh_token": "..."}, "user": {...}}
        tokens = data["tokens"]
        self.token = tokens["access_token"]
        self.refresh_token = tokens["refresh_token"]
        self.user = data["user"]
        self.phone = phone
        crypto.vault_save_tokens(phone, {
            "access": self.token, 
            "refresh": self.refresh_token
        })
        return data

    async def login(self, phone: str, password: str, totp: str = "") -> dict:
        data = await self._req(
            "POST", "/api/login",
            json={"phone": phone, "password": password, "totp": totp},
        )
        tokens = data["tokens"]
        self.token = tokens["access_token"]
        self.refresh_token = tokens["refresh_token"]
        self.user = data["user"]
        self.phone = phone
        crypto.vault_save_tokens(phone, {
            "access": self.token, 
            "refresh": self.refresh_token
        })
        return data

    async def logout(self) -> dict:
        """Выход из аккаунта с инвалидацией Refresh токена на сервере."""
        if not self.refresh_token:
            return {"ok": True}
        try:
            await self._req("POST", "/api/logout", json={"refresh_token": self.refresh_token})
        except Exception:
            pass
        self.token = None
        self.refresh_token = None
        crypto.vault_clear_tokens(self.phone)
        return {"ok": True}

    async def me(self) -> dict:
        self.user = await self._req("GET", "/api/me")
        return self.user

    # ---------- 2FA ----------
    async def totp_setup(self) -> dict:
        return await self._req("POST", "/api/me/totp/setup")

    async def totp_enable(self, code: str) -> dict:
        return await self._req("POST", "/api/me/totp/enable", json={"totp": code})

    async def totp_disable(self, code: str) -> dict:
        return await self._req("POST", "/api/me/totp/disable", json={"totp": code})

    # ---------- Чаты ----------
    async def chats(self) -> list:
        return await self._req("GET", "/api/chats")

    async def search_users(self, q: str) -> list:
        return await self._req("GET", "/api/users/search", params={"q": q})

    async def create_chat(self, chat_type: str, user_ids: list, title: str = "") -> dict:
        return await self._req(
            "POST", "/api/chats",
            json={"type": chat_type, "user_ids": user_ids, "title": title},
        )

    async def add_members(self, chat_id: int, user_ids: list) -> dict:
        return await self._req(
            "POST", f"/api/chats/{chat_id}/members", json={"user_ids": user_ids}
        )

    # ---------- Сообщения ----------
    async def messages(self, chat_id: int, limit: int = 100, before_id: Optional[int] = None) -> list:
        params = {"limit": limit}
        if before_id:
            params["before_id"] = before_id
        return await self._req("GET", f"/api/chats/{chat_id}/messages", params=params)

    async def send_message(
        self,
        chat_id: int,
        content: str,
        msg_type: str = "text",
        ttl_seconds: Optional[int] = None,
        view_once: bool = False,
        media_path: str = "",
        e2e: bool = False,
    ) -> dict:
        return await self._req(
            "POST", f"/api/chats/{chat_id}/messages",
            json={
                "type": msg_type,
                "content": content,
                "ttl_seconds": ttl_seconds,
                "view_once": view_once,
                "media_path": media_path,
                "e2e": e2e,
            },
        )

    async def mark_viewed(self, message_id: int) -> dict:
        return await self._req("POST", f"/api/messages/{message_id}/view", json={})

    async def delete_message(self, message_id: int) -> dict:
        return await self._req("DELETE", f"/api/messages/{message_id}")

    # ---------- E2E-ключи ----------
    async def e2e_set_key(self, public_key: str) -> dict:
        return await self._req("PUT", "/api/me/e2e-key", json={"public_key": public_key})

    async def e2e_get_key(self, user_id: int) -> str:
        data = await self._req("GET", f"/api/users/{user_id}/e2e-key")
        return data["public_key"]

    async def report(self, message_id: int, reason: str) -> dict:
        return await self._req(
            "POST", "/api/reports", json={"message_id": message_id, "reason": reason}
        )

    # ---------- Файлы ----------
    async def upload(self, file_path: str) -> str:
        filename = file_path.split("\\")[-1].split("/")[-1]
        r: Optional[httpx.Response] = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                with open(file_path, "rb") as f:
                    r = await self._http.post(
                        self.base_url + "/api/upload",
                        headers=self._headers(),
                        files={"file": (filename, f)},
                    )
            except httpx.TransportError as exc:
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(_retry_delay(attempt))
                    continue
                raise ApiError(0, f"Нет соединения с сервером ({exc.__class__.__name__})")
            if r.status_code in (502, 503, 504) and attempt < MAX_RETRIES:
                await asyncio.sleep(_retry_//_retry_delay(attempt))
                continue
            break

        assert r is not None
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except Exception:
                detail = r.text
            raise ApiError(r.status_code, str(detail))
        return r.json()["path"]

    def file_url(self, path: str) -> str:
        return f"{self.base_url}{path}?token={self.token or ''}"

    # ---------- DevMode ----------
    async def admin_stats(self) -> dict:
        return await self._req("GET", "/api/admin/stats")

    async def admin_reports(self) -> list:
        return await self._req("GET", "/api/admin/reports")

    async def admin_moderation(self, report_id: int, action: str) -> dict:
        return await self._req(
            "POST", "/api/admin/moderation",
            json={"report_id": report_id, "action": action},
        )

    async def admin_settings(self) -> dict:
        return await self._req("GET", "/api/admin/settings")

    async def admin_set_setting(self, key: str, value: str) -> dict:
        return await self._req(
            "PUT", "/api/admin/settings", json={"key": key, "value": value},
        )

    # ---------- WebSocket ----------
    async def ws_listen(
        self,
        on_event: Callable[[dict], Awaitable[None]],
        on_status: Optional[Callable[[bool], None]] = None,
    ):
        import websockets

        uri = self.base_url.replace("http", "ws") + "/ws"
        auth_headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        ws_kwargs = dict(ping_interval=20, ping_timeout=20, close_timeout=5,
                         max_size=4 * 1024 * 1024)
        try:
            ws_version = int(str(getattr(websockets, "__version__", "0")).split(".")[0])
        except Exception:
            ws_version = 0
        if ws_version >= 13:
            ws_kwargs["additional_headers"] = auth_headers
        else:
            ws_kwargs["extra_headers"] = auth_headers

        delay = 1.0
        while True:
            try:
                async with websockets.connect(uri, **ws_kwargs) as ws:
                    delay = 1.0
                    if on_status:
                        try:
                            on_status(True)
                        except Exception:
                            pass
                    while True:
                        try:
                            msg = json.loads(await ws.recv())
                        except Exception:
                            break
                        try:
                            await on_event(msg)
                        except Exception:
                            pass
            except Exception:
                pass
            if on_status:
                try:
                    on_status(False)
                except Exception:
                    pass
            await asyncio.sleep(delay)
            delay = min(delay * 2, WS_RECONNECT_MAX)
