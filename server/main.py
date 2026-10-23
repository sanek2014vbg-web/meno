"""MeNo — точка входа FastAPI-приложения (Этап 2.1 ТЗ: единый async-стек).

Запуск (сервер, например VPS):
    uvicorn main:app --host 0.0.0.0 --port 8000
или из корня проекта:
    uvicorn server.main:app --host 0.0.0.0 --port 8000

Переменные окружения (префикс MENO_):
    MENO_DATABASE_URL     — postgresql+asyncpg://user:pass@host:5432/dbname
                            (по умолчанию — локальный SQLite для разработки)
    MENO_JWT_SECRET       — секрет подписи токенов (ОБЯЗАТЕЛЬНО в проде!)
    MENO_ADMIN_USERNAME   — username, который при регистрации получает роль admin
    MENO_REDIS_URL        — Redis для кеша/лимитеров (опционально)
    MENO_UPLOAD_DIR       — каталог загруженных файлов
    MENO_S3_*             — профиль S3/MinIO (опционально)
"""

import logging
import time
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Optional

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from server import auth, config, database
from server.cache import cache
from server.logger import setup_logging
from server.routes_admin import router as admin_router
from server.routes_auth import router as auth_router
from server.routes_chats import router as chats_router
from server.routes_files import router as files_router
from server.routes_messages import router as messages_router
from server.routes_reactions import router as reactions_router
from server.ws_manager import manager

setup_logging()
log = logging.getLogger("meno.server")

IS_PROD = config.is_production()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Sentry (Этап 6.2): ошибки и трейсы стека ---
    if config.SENTRY_DSN:
        try:
            import sentry_sdk
            from sentry_sdk.integrations.fastapi import FastApiIntegration

            sentry_sdk.init(
                dsn=config.SENTRY_DSN,
                environment="production" if IS_PROD else "development",
                traces_sample_rate=0.1,
                integrations=[FastApiIntegration()],
            )
            log.info("Sentry initialized")
        except ImportError:
            log.warning("sentry-sdk not installed, skipping")

    await database.init_db()
    await cache.connect()

    # --- Фоновые задачи ---
    # v2.0 Пункт 2: сгорающие сообщения — вынесено из inline-цикла lifespan
    # в атомарный сервис server/services/janitor.py (тик 10 c, физическое
    # удаление expires_at <= now + очистка Redis + fan-out message_delete).
    from server.services.janitor import janitor_service

    await janitor_service.start()

    # Дефект-фикс v1.0.0 (зависание test_ws_endpoint_delivers_typing):
    # при включённом Redis cache fan-out user_typing/new_message идёт через
    # канал meno:ws, но подписчик (_bus_loop) нигде не запускался — событие
    # публиковалось в пустоту и получатель ждал вечно. В проде это же чинило
    # бы multi-worker доставку на единственном воркере. Идемпотентно.
    from server.ws_manager import manager as ws_manager

    await ws_manager.start_bus_listener()

    # MeNo Admin Center & Monitor: слушатель админского перехват-тапа
    # (канал Redis meno:admin:tap) — события с всех воркеров фан-аутятся
    # SuperAdmin WS-сессиям. Идемпотентно; без Redis not-a-op.
    from server.admin_tap import admin_tap

    await admin_tap.start_bus_listener()

    yield

    await admin_tap.stop_bus_listener()
    await ws_manager.stop_bus_listener()
    await janitor_service.stop()
    await cache.close()


fastapi_app = FastAPI(
    title="MeNo Messenger API",
    version="0.2.0",
    description="Self-hosted мессенджер: PostgreSQL + Redis, JWT auth, E2EE, FCM push.",
    lifespan=lifespan,
)


# --- WebSocket subprotocol echo (Фаза 2.3) -------------------------------
# WS-хэндлер валидирует JWT из заголовка Sec-WebSocket-Protocol ("bearer.<JWT>")
# и кладёт согласованный протокол в contextvar. Явный websocket.accept() внутри
# хэндлера ломает state machine Starlette-маршрута (accept выполняет сама
# route-обёртка), поэтому чистый ASGI-слой ниже дописывает "subprotocol" в
# websocket.accept-сообщение до того, как оно уйдёт клиенту. Handshake остаётся
# корректным на любой starlette (включая ту, что не умеет accept(subprotocol=)).
_ws_negotiated_protocol: ContextVar[Optional[str]] = ContextVar(
    "ws_negotiated_protocol", default=None
)


class WsSubprotocolEchoMiddleware:
    """ASGI-middleware: эхо согласованного Sec-WebSocket-Protocol в accept."""

    def __init__(self, asgi_app):
        self.asgi_app = asgi_app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "websocket":
            await self.asgi_app(scope, receive, send)
            return

        token = _ws_negotiated_protocol.set(None)

        async def send_wrapper(message):
            if message["type"] == "websocket.accept":
                protocol = _ws_negotiated_protocol.get()
                if protocol and "subprotocol" not in message:
                    message = {**message, "subprotocol": protocol}
            await send(message)

        try:
            await self.asgi_app(scope, receive, send_wrapper)
        finally:
            _ws_negotiated_protocol.reset(token)


# Оборачиваем FastAPI-приложение ASGI-слоем эха subprotocol; HTTP-маршруты
# (@fastapi_app.get и т.д.) продолжают регистрироваться на внутреннем приложении.
app = WsSubprotocolEchoMiddleware(fastapi_app)

# CORS (Этап 2.7): в проде — только явно заданные origins
fastapi_app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


@fastapi_app.middleware("http")
async def security_headers(request: Request, call_next):
    """Базовые защитные HTTP-заголовки (OWASP A05 - Security Misconfiguration)."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(self), geolocation=()"
    )
    # CSP: API + docs; 'unsafe-eval' требуется Swagger UI (redoc/swagger js)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'self'"
    )
    # HSTS только на HTTPS (через config, чтобы не ломать локальную разработку по http)
    if config.HSTS_ENABLED:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


@fastapi_app.middleware("http")
async def access_log(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    ms = (time.perf_counter() - start) * 1000
    if config.LOG_ACCESS_ENABLED:
        log.info(
            "%s %s -> %s (%.1f ms)",
            request.method,
            request.url.path,
            response.status_code,
            ms,
        )
    return response


# --- Маршруты ---
fastapi_app.include_router(auth_router)
fastapi_app.include_router(chats_router)
fastapi_app.include_router(messages_router)
fastapi_app.include_router(reactions_router)
fastapi_app.include_router(files_router)
fastapi_app.include_router(admin_router)


@fastapi_app.get("/health")
async def health():
    """Liveness/readiness: БД + Redis (если настроен)."""
    checks = {}
    try:
        async with database.get_db() as db:
            row = await database.aq1(db, "SELECT 1 AS ok")
            checks["database"] = bool(row and row["ok"] == 1)
    except Exception as e:
        checks["database"] = False
        log.error("Health DB check failed: %s", e)
    checks["redis"] = cache.enabled and await cache.ping()
    status = "ok" if checks["database"] else "degraded"
    return {"status": status, "checks": checks}


def _extract_ws_token(websocket: WebSocket) -> tuple[Optional[int], Optional[str]]:
    """Извлекает access-токен из безопасного транспорта (Фаза 2.3).

    Приоритет источников (JWT больше НЕ читается из query-параметра URL —
    query оседает в логах reverse-proxy/CDN и истории):
      1. Заголовок Sec-WebSocket-Protocol: клиент обязан заявить протокол вида
         "bearer.<JWT>" (RFC 6455; браузеры не могут задавать произвольные
         заголовки при WS-handshake — subprotocol является стандартным
         обходным путём для авторизации).
      2. Заголовок Authorization: Bearer <JWT> (небраузерные клиенты:
         python-websockets, мобильный клиент MeNo).
    Возвращает (user_id | None, negotiated_subprotocol | None).
    """
    raw_protocols = websocket.headers.get("sec-websocket-protocol", "")
    for item in (p.strip() for p in raw_protocols.split(",")):
        if item.startswith("bearer.") and len(item) > len("bearer."):
            user = auth.decode_token(item[len("bearer.") :])
            if user is not None:
                return user, item
    authorization = websocket.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        user = auth.decode_token(authorization[len("bearer ") :].strip())
        if user is not None:
            return user, None
    return None, None


@fastapi_app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    user, negotiated_protocol = _extract_ws_token(websocket)
    if not user:
        # 4401 — кастомный кодclose: «unauthorized» (аналог HTTP 401).
        await websocket.close(code=4401)
        return
    # Эхо согласованного subprotocol обязательно, если токен пришёл в нём:
    # без него websockets/flet оборвут соединение с "missing subprotocol".
    # Явный websocket.accept() здесь запрещён жизненным циклом Starlette
    # (first AcceptWebSocketSubset depends on request.scope["asgi"]["version"]==1):
    # accept() выполняет route-обёртка @app.websocket — поэтому протокол
    # передаётся через contextvar, который читает кастомный ASGI-middleware
    # WsSubprotocolEchoMiddleware (см. ниже).
    if negotiated_protocol:
        _ws_negotiated_protocol.set(negotiated_protocol)
    await manager.connect(user, websocket)
    try:
        while True:
            data = await websocket.receive_json()
            if data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
            elif data.get("type") in ("typing", "client_typing"):
                # v2.0 Пункт 9: Zero DB-touch обработка статуса «печатает».
                # chat_member_ids берёт состав чата из Redis-кеша (TTL 60 c),
                # поэтому горячий путь не трогает PostgreSQL.
                from server.deps import chat_member_ids, is_chat_member
                from server.services.typing import typing_service

                chat_id = int(data.get("chat_id", 0))
                if chat_id and await is_chat_member(chat_id, user):
                    member_ids = await chat_member_ids(chat_id)
                    await typing_service.handle_client_event(
                        chat_id=chat_id,
                        sender_user_id=user,
                        member_ids=member_ids,
                        text=data.get("text"),
                    )
    except WebSocketDisconnect:
        manager.disconnect(user, websocket)
