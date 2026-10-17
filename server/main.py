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
import asyncio
import logging
import time
from datetime import timedelta
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from server import auth, config, database
from server.cache import cache
from server.logger import setup_logging
from server.utils import as_utc
from server.routes_admin import router as admin_router
from server.routes_auth import router as auth_router
from server.routes_chats import router as chats_router
from server.routes_files import router as files_router
from server.routes_messages import router as messages_router
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
    async def janitor():
        """Каждые 60 с: чистка TTL-сообщений, устаревших refresh-токенов, кодов."""
        from sqlalchemy import text as sql_text
        from server.utils import utc_now

        while True:
            try:
                now = utc_now()
                async with database.get_db() as db:
                    # TTL: view_once-сообщения удаляются сразу после просмотра;
                    # обычные с ttl_seconds — когда срок истёк (created_at + ttl < now).
                    # Диалект-безопасно: сравнение переносится в Python.
                    expired_ids = []
                    ttl_rows = await database.aq(
                        db,
                        "SELECT id, created_at, ttl_seconds, view_once, viewed "
                        "FROM messages WHERE ttl_seconds IS NOT NULL",
                    )
                    for r in ttl_rows:
                        created = as_utc(r["created_at"])
                        if r["view_once"] and r["viewed"]:
                            expired_ids.append(r["id"])
                        elif created and created + timedelta(seconds=int(r["ttl_seconds"])) <= now:
                            expired_ids.append(r["id"])
                    if expired_ids:
                        await db.execute(
                            sql_text("DELETE FROM messages WHERE id IN ("
                                     + ",".join(str(i) for i in expired_ids) + ")")
                        )
                    await db.execute(
                        sql_text("DELETE FROM refresh_tokens WHERE expires_at < :now"),
                        {"now": now},
                    )
            except Exception as e:
                log.error("Janiter error: %s", e)
            await asyncio.sleep(60)

    janitor_task = asyncio.create_task(janitor())

    yield

    janitor_task.cancel()
    await cache.close()


app = FastAPI(
    title="MeNo Messenger API",
    version="0.2.0",
    description="Self-hosted мессенджер: PostgreSQL + Redis, JWT auth, E2EE, FCM push.",
    lifespan=lifespan,
)

# CORS (Этап 2.7): в проде — только явно заданные origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def access_log(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    ms = (time.perf_counter() - start) * 1000
    if config.LOG_ACCESS_ENABLED:
        log.info("%s %s -> %s (%.1f ms)", request.method, request.url.path,
                 response.status_code, ms)
    return response


# --- Маршруты ---
app.include_router(auth_router)
app.include_router(chats_router)
app.include_router(messages_router)
app.include_router(files_router)
app.include_router(admin_router)


@app.get("/health")
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


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket, token: str = ""):
    user = auth.decode_token(token)
    if not user:
        await websocket.close(code=4401)
        return
    await manager.connect(user, websocket)
    try:
        while True:
            data = await websocket.receive_json()
            if data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
            elif data.get("type") == "typing":
                chat_id = int(data.get("chat_id", 0))
                from server.deps import chat_member_ids

                member_ids = await chat_member_ids(chat_id)
                await manager.send_to_users(
                    [m for m in member_ids if m != user],
                    {"type": "typing", "chat_id": chat_id, "user_id": user},
                )
    except WebSocketDisconnect:
        manager.disconnect(user, websocket)
