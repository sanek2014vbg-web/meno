"""MeNo — точка входа сервера (FastAPI + WebSocket).

Боевые свойства:
- санитизированное логирование: без тел запросов, паролей, ключей,
  токенов и текстов сообщений (access-лог uvicorn отключён — в query
  могут попадать токены);
- глобальный rate limiting по IP + точечные лимиты по IP+пользователь;
- SQLite в WAL-режиме с пулом соединений (см. database.py);
- CORS настраивается через окружение (MENO_CORS_ORIGINS).

Запуск локально:  uvicorn main:app --reload --port 8000
"""
import asyncio
import logging
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

# Маршруты
from routes_auth import router as auth_router
from routes_chats import router as chats_router
from routes_messages import router as messages_router
from routes_files import router as files_router
from routes_admin import router as admin_router

access_log = logging.getLogger("meno.access")


def _configure_logging() -> None:
    """Отключает access-лог uvicorn (в query-параметрах может быть токен).

    Вместо него работает санитизированный лог meno.access: только метод,
    путь БЕЗ query-строки, код ответа, длительность и IP. Тела запросов,
    пароли, ключи и тексты сообщений никогда не пишутся в лог.
    Ошибки uvicorn (logger.error) оставляем видимыми для диагностики.
    """
    access = logging.getLogger("uvicorn.access")
    access.handlers.clear()
    access.propagate = False
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
        )


async def cleanup_expired():
    """Фоновая задача: удаляет исчезающие и просмотренные-один-раз сообщения."""
    while True:
        await asyncio.sleep(60)
        try:
            with database.get_db() as db:
                db.execute(
                    "DELETE FROM messages WHERE ttl_seconds IS NOT NULL "
                    "AND datetime(created_at, '+' || ttl_seconds || ' seconds') < datetime('now')"
                )
                db.execute("DELETE FROM messages WHERE view_once=1 AND viewed=1")
        except Exception:
            pass


async def cleanup_rate_limiter():
    """Периодически освобождает память от устаревших ключей rate limiting."""
    while True:
        await asyncio.sleep(300)
        try:
            limiter.cleanup()
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    _configure_logging()
    database.init_db()
    os.makedirs(config.UPLOAD_DIR, exist_ok=True)
    tasks = [
        asyncio.create_task(cleanup_expired()),
        asyncio.create_task(cleanup_rate_limiter()),
    ]
    yield
    for t in tasks:
        t.cancel()
    database.close_pool()


app = FastAPI(title="MeNo Server", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Глобальный rate limit по IP + санитизированный access-лог."""
    ip = client_ip(request)
    # Лимит применяется ко всем /api запросам; корень и health не ограничиваем жёстко
    if request.url.path.startswith("/api") and not limiter.allow(
        f"global:{ip}", config.RL_GLOBAL_LIMIT, config.RL_GLOBAL_WINDOW
    ):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=429, content={"detail": "Слишком много запросов"})

    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = int((time.perf_counter() - start) * 1000)
    if config.LOG_ACCESS_ENABLED:
        # Только путь без query-строки: токены в параметрах не попадают в лог
        access_log.info(
            "%s %s %d %dms ip=%s",
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
    """Проба для мониторинга (nginx/uptime)."""
    return {"status": "ok"}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """Реалтайм-канал.

    Авторизация — заголовок Authorization: Bearer <JWT> (токен не попадает
    в URL и в логи сервера/nginx). Для обратной совместимости принимается
    также query-параметр ?token=.
    """
    token = ws.query_params.get("token", "")
    if not token:
        auth_header = ws.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[len("Bearer "):]
    user_id = auth.decode_token(token)
    if user_id is None:
        await ws.close(code=4401)
        return

    user = auth.get_user_by_id(user_id)
    if user is None:
        await ws.close(code=4401)
        return

    await manager.connect(user_id, ws)
    auth.touch_last_seen(user_id)
    await manager.send_to_users(
        _all_user_ids(),
        {"type": "presence", "user_id": user_id, "online": True},
    )
    try:
        while True:
            # Клиент может слать пинги/статусы — пока игнорируем содержимое
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(user_id, ws)
        await manager.send_to_users(
            _all_user_ids(),
            {"type": "presence", "user_id": user_id, "online": False},
        )


def _all_user_ids() -> list:
    with database.get_db() as db:
        rows = database.q(db, "SELECT id FROM users")
    return [r["id"] for r in rows]


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, access_log=False)