"""MeNo Admin Center & Monitor — асинхронный сетевой слой (без Qt-зависимостей).

Два канала:
  * HTTP (httpx.AsyncClient) — логин, tap-token, REST-догон, админ-команды;
  * WebSocket (websockets) — живой стрим событий тапа с автопереподключением
    по экспоненциальному backoff и догоном пропущенных через /tap/events.

Слой чистый: никаких PyQt6-импортов — GUI подписывается на события через
asyncio.Queue, который адаптер в main.py перекачивает в Qt-сигналы.

Big O: все методы O(1)/O(N страницы); reconnect — конечный автомат без утечек
(задача стрима одна, соединения закрываются в finally).
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx
import websockets

log = logging.getLogger("meno.monitor.net")


class AuthError(RuntimeError):
    pass


class ApiError(RuntimeError):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f"HTTP {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


class MonitorClient:
    """HTTP + WS клиент монитора к MeNo серверу.

    Авторизация тапа (hardening v2): scoped-токен больше не кладётся в URL —
    каждый реконнект запрашивает ОДНОРАЗОВЫЙ 5-секундный билет
    POST /api/admin/ws-ticket и передаёт его в subprotocol ``meno-tap.<ticket>``
    (билет не попадает в access-логи прокси/сервера, replay невозможен —
    сервер гасит его GETDEL за O(1)).
    """

    def __init__(self, base_url: str) -> None:
        base_url = base_url.rstrip("/")
        self.base_url = base_url
        u = urlparse(base_url)
        ws_scheme = "wss" if u.scheme == "https" else "ws"
        self.ws_tap_url = f"{ws_scheme}://{u.netloc}/api/admin/ws/tap"
        self._http = httpx.AsyncClient(timeout=httpx.Timeout(20.0))
        self.access_token: Optional[str] = None
        self.tap_token: Optional[str] = None
        self.events: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=10000)
        self.state_changed: asyncio.Queue[str] = asyncio.Queue(maxsize=64)
        self._ws: Optional[Any] = None
        self._stream_task: Optional[asyncio.Task] = None
        self._stop = False

    # ------------------------------ HTTP ------------------------------ #

    async def close(self) -> None:
        self._stop = True
        await self.disconnect_tap()
        await self._http.aclose()

    async def login(self, username: str, password: str) -> Dict[str, Any]:
        r = await self._http.post(
            f"{self.base_url}/api/auth/login",
            json={"username": username, "password": password},
        )
        if r.status_code != 200:
            raise AuthError(self._detail(r) or f"login failed ({r.status_code})")
        data = r.json()
        self.access_token = data["tokens"]["access"]
        return data

    async def fetch_tap_token(self) -> str:
        self._require_access()
        r = await self._http.post(
            f"{self.base_url}/api/admin/tap-token",
            headers=self._auth_headers(),
        )
        self._raise_for(r)
        self.tap_token = r.json()["token"]
        return self.tap_token

    async def fetch_tap_ticket(self) -> str:
        """Одноразовый 5-секундный билет для handshake тапа (hardening v2)."""
        self._require_access()
        r = await self._http.post(
            f"{self.base_url}/api/admin/ws-ticket",
            headers=self._auth_headers(),
        )
        self._raise_for(r)
        return r.json()["ticket"]

    async def get_users(self, limit: int = 500) -> List[Dict[str, Any]]:
        return await self._get("/api/admin/users", {"limit": limit})

    async def get_sessions(self, user_id: Optional[int] = None) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if user_id is not None:
            params["user_id"] = user_id
        return await self._get("/api/admin/sessions", params)

    async def kill_sessions(self, user_id: int, reason: str = "monitor_kill") -> Dict:
        self._require_access()
        r = await self._http.post(
            f"{self.base_url}/api/admin/sessions/kill",
            headers=self._auth_headers(),
            json={"user_id": user_id, "reason": reason},
        )
        self._raise_for(r)
        return r.json()

    async def set_role(self, user_id: int, role: str) -> Dict:
        self._require_access()
        r = await self._http.put(
            f"{self.base_url}/api/admin/users/{user_id}/role",
            headers=self._auth_headers(),
            json={"role": role},
        )
        self._raise_for(r)
        return r.json()

    async def recent_messages(self, limit: int = 100) -> List[Dict[str, Any]]:
        return await self._get("/api/admin/messages/recent", {"limit": limit})

    async def janitor_jobs(self) -> List[Dict[str, Any]]:
        return await self._get("/api/admin/janitor/jobs", {})

    async def fetch_compliance_logs(
        self,
        chat_id: Optional[int] = None,
        author_id: Optional[int] = None,
        before: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Страница журнала корпоративного DLP-аудита (ComplianceAuditLog).

        GET /api/admin/compliance-logs защищён ДВОЙНЫМ контуром: admin-JWT
        (Authorization) И одноразовый superadmin-билет заголовком X-Meno-Ticket
        (тот же one-time механизм, что handshake тапа; TTL 5 с, consume O(1)).
        Поэтому билет запрашивается ЗАНОВО на каждый вызов — переиспользование
        невозможно по построению. Ответ сервера — объект
        {items, next_cursor, has_more}; в отличие от _get он НЕ сворачивается
        к списку, т.к. курсор нужен вызывающему слою для пагинации.

        Big O: серверный путь — seek по idx_compliance_logs_chat_logged,
        O(log N + limit); клиентский — O(limit) на страницу.
        """
        self._require_access()
        ticket = await self.fetch_tap_ticket()
        params: Dict[str, Any] = {"limit": limit}
        if chat_id is not None:
            params["chat_id"] = chat_id
        if author_id is not None:
            params["author_id"] = author_id
        if before:
            params["before"] = before
        r = await self._http.get(
            f"{self.base_url}/api/admin/compliance-logs",
            headers={**self._auth_headers(), "X-Meno-Ticket": ticket},
            params=params,
        )
        self._raise_for(r)
        data = r.json()
        return {
            "items": data.get("items", []),
            "next_cursor": data.get("next_cursor"),
            "has_more": bool(data.get("has_more")),
        }

    async def tap_events_backfill(self, since_seq: int, limit: int = 500) -> List[dict]:
        data = await self._get(
            "/api/admin/tap/events", {"since_seq": since_seq, "limit": limit}
        )
        return data.get("events", [])

    # ------------------------------ WS ------------------------------- #

    async def connect_tap(self) -> None:
        """Запускает фоновую задачу стрима (идемпотентно).

        WS-авторизация — one-time билеты /api/admin/ws-ticket, которые
        _tap_loop запрашивает на каждый handshake; отдельный tap-token для
        нового протокола не нужен.
        """
        if self._stream_task and not self._stream_task.done():
            return
        self._stop = False
        self._stream_task = asyncio.create_task(self._tap_loop(), name="tap-stream")

    async def disconnect_tap(self) -> None:
        self._stop = True
        if self._stream_task:
            self._stream_task.cancel()
            try:
                await self._stream_task
            except (asyncio.CancelledError, Exception):
                pass
            self._stream_task = None

    async def _tap_loop(self) -> None:
        """Конечный автомат: connect -> stream -> backoff -> reconnect -> backfill."""
        backoff = 1.0
        last_seq = 0
        while not self._stop:
            try:
                await self._state("connecting")
                # Билет выдаётся заново на КАЖДЫЙ handshake: one-time, TTL 5с —
                # переиспользование старого невозможно даже при rapid reconnect.
                ticket = await self.fetch_tap_ticket()
                async with websockets.connect(
                    self.ws_tap_url,
                    subprotocols=[f"meno-tap.{ticket}"],
                    ping_interval=20,
                    ping_timeout=10,
                    close_timeout=5,
                ) as ws:
                    self._ws = ws
                    backoff = 1.0
                    await self._state("connected")
                    async for raw in ws:
                        env = self._parse_frame(raw)
                        if env is None:
                            continue
                        if env.get("type") == "tap_hello":
                            for missed in await self.tap_events_backfill(last_seq):
                                seq = int(missed.get("seq", 0))
                                if seq > last_seq:
                                    last_seq = seq
                                    self._offer(missed)
                            continue
                        if env.get("type") == "tap_event":
                            last_seq = max(last_seq, int(env.get("seq", 0)))
                        self._offer(env)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.warning("tap stream error: %s", exc.__class__.__name__)
                await self._state("disconnected")
                if self._stop:
                    break
                try:
                    await asyncio.sleep(backoff)
                except asyncio.CancelledError:
                    break
                backoff = min(backoff * 2, 30.0)
        await self._state("stopped")

    def _parse_frame(self, raw) -> Optional[Dict[str, Any]]:
        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def _offer(self, env: Dict[str, Any]) -> None:
        """Неблокирующая публикация в очередь событий GUI.

        При переполнении (GUI не успевает за пиковым потоком) выбрасывается
        самый старый элемент — лента живая, память ограничена maxsize.
        """
        try:
            self.events.put_nowait(env)
        except asyncio.QueueFull:
            try:
                self.events.get_nowait()
            except asyncio.QueueEmpty:
                pass
            try:
                self.events.put_nowait(env)
            except asyncio.QueueFull:
                pass

    async def _state(self, value: str) -> None:
        try:
            self.state_changed.put_nowait(value)
        except asyncio.QueueFull:
            pass

    # ----------------------------- helpers --------------------------- #

    def _require_access(self) -> None:
        if not self.access_token:
            raise AuthError("no access token")

    def _auth_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}

    async def _get(self, path: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        self._require_access()
        r = await self._http.get(
            f"{self.base_url}{path}", headers=self._auth_headers(), params=params
        )
        self._raise_for(r)
        out = r.json()
        return out if isinstance(out, list) else [out]

    @staticmethod
    def _detail(r: httpx.Response) -> str:
        try:
            d = r.json().get("detail", "")
            return d if isinstance(d, str) else json.dumps(d, ensure_ascii=False)
        except Exception:
            return ""

    def _raise_for(self, r: httpx.Response) -> None:
        if r.status_code >= 400:
            raise ApiError(r.status_code, self._detail(r))
