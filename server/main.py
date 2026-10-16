"""MeNo — точка входа сервера (FastAPI + WebSocket).

Боевые свойства:
- структурированное логирование через Loguru;
- мониторинг ошибок через Sentry;
- глобальный rate limiting по IP + точечные лимиты по IP+пользователь;
- PostgreSQL в Async-режиме с SQLAlchemy 2.0;
- CORS настраивается через окружение (MENO_CORS_ORIGINS).

Запуск локально:  uvicorn main:app --reload --port 8000
"""
import asyncio
import os
import time
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from starlette.requests import Request

import auth
import config
import database
from rate_limit import client_ip, limiter
from ws_manager import manager
from server.logger import log, setup_logging, setup_sentry

# Маршруты
from routes_auth import router as auth_router
from routes_chats import router as chats_router
from routes_messages import router as messages_router
from routes_files import router as files_router
from routes_admin import router as admin_router

async def cleanup_expired():
    """Фоновая задача: удаляет исчезающие и просмотренные-один-раз сообщения."""
    while True:
        await asyncio.sleep(60)
        try:
            async with database.get_db() as db:
                await db.execute(
                    "DELETE FROM messages WHERE ttl_seconds IS NOT NULL "
                    "AND created_at + (ttl_seconds || ' seconds')::interval < CURRENT_TIMESTAMP"
                )
                await db.execute("DELETE FROM messages WHERE view_once=1 AND viewed=1")
        except Exception as e:
            log.error(f"Cleanup error: {e}")

async def cleanup_rate_limiter():
    """Периодически освобождает память от устаревших ключей rate limiting."""
    while True:
        await asyncio.sleep(300)
        try:
            limiter.cleanup()
        except Exception as e:
            log.error(f"Rate limiter cleanup error: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Инициализация систем мониторинга и логов
    setup_logging()
    setup_sentry()
    
    # Инициализация БД (создание таблиц через SQLAlchemy)
    await database.init_db()
    os.makedirs(config.UPLOAD_DIR, exist_ok=True)
    
    tasks = [
        asyncio.create_task(cleanup_expired()),
        asyncio.create_task(cleanup_rate_limiter()),
    ]
    log.info("Server lifespan started: services initialized.")
    yield
    for t in tasks:
        t.cancel()
    await database.close_pool()
    log.info("Server lifespan ended: resources released.")

app = FastAPI(title="MeNo Server", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Добавление базовых заголовков безопасности (HSTS, CSP, X-Frame-Options)."""
    response = await call_next(request)
    
    # HSTS (Strict-Transport-Security): Принудительный HTTPS (для продакшена)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    # X-Frame-Options: Защита от Clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    
    # X-Content-Type-Options: Запрет MIME-sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    
    # Content-Security-Policy (CSP): Ограничение источников контента
    # По умолчанию разрешаем только свой домен и базовые ресурсы
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none';"
    )
    response.headers["Content-Security-Policy"] = csp
    
    return response

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    ip = client_ip(request)
    if request.url.path.startswith("/api") and not limiter.allow(
        f"global:{ip}", config.RL_GLOBAL_LIMIT, config.RL_GLOBAL_WINDOW
    ):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=429, content={"detail": "Слишком много запросов"})

    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception as e:
        log.exception(f"Unhandled exception in request: {e}")
        raise e
        
    duration_ms = int((time.perf_counter() - start) * 1000)
    if config.LOG_ACCESS_ENABLED:
        log.info(
            "REQ | %s %s | %d | %dms | ip=%s",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            ip,
        )
    return response

app.include_router(auth_router)
app.include_router(chats_router)
app.include_router(messages_router)
app.include_router(files_router)
app.include_router(admin_router)

@app.get("/")
def root():
    return {"app": config.APP_NAME, "status": "ok", "version": "1.0.0"}

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    token = ws.query_params.get("token", "")
    if not token:
        auth_header = ws.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[len("Bearer "):]
    
    user_id = auth.decode_token(token)
    if user_id is None:
        await ws.close(code=4401)
        return

    user = await auth.get_user_by_id(user_id)
    if user is None:
        await ws.close(code=4401)
        return

    await manager.connect(user_id, ws)
    await auth.touch_last_seen(user_id)
    
    # Получаем всех пользователей для уведомления о присутствии
    async with database.get_db() as db:
        rows = await database.aq(db, "SELECT id FROM users")
        all_user_ids = [r["id"] for r in rows]
        
    await manager.send_to_users(
        all_user_ids,
        {"type": "presence", "user_id": user_id, "online": True},
    )
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(user_id, ws)
        # Обновляем список присутствия
        async with database.get_db() as db:
            rows = await database.aq(db, "SELECT id FROM users")
            all_user_ids = [r["id"] for r in rows]
        await manager.send_to_users(
            all_user_ids,
            {"type": "presence", "user_id": user_id, "online": False},
        )

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, access_log=False)
