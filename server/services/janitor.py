"""MeNo v2.0 — Пункт 2: фоновый процесс-дворник сгорающих сообщений.

Асинхронная задача, инициализируемая в lifespan FastAPI (см. server/main.py)
и работающая в бесконечном цикле с интервалом JANITOR_INTERVAL_SECONDS (10 c).

Ответственности дворника (физическое стирание, Physical Erasure):

1. PostgreSQL/SQLite — находит и ФИЗИЧЕСКИ удаляет сообщения, у которых
   ``expires_at <= now`` (абсолютный TTL из колонки, миграция a1f2e3d4b5c6),
   а также legacy-сообщения со ``ttl_seconds`` без заполненной ``expires_at``
   (старые строки до миграции: deadline = created_at + ttl_seconds, дедлайн
   считается в Python — диалект-безопасно, Этап 4.1 ТЗ v1.1) и просмотренные
   view_once-сообщения.
2. Redis — принудительно очищает кеш-ключи удалённых сообщений
   (``msg:{id}``, ``chat_last:{chat_id}``) через синглтон ``server.cache``.
3. Real-time — транслирует через WS-шину (Redis Pub/Sub ``meno:ws`` при
   наличии Redis → fan-out на ВСЕ воркеры; иначе локальная доставка)
   событие ``message_delete`` с массивами id, сгруппированными по чатам,
   всем участникам соответствующих чатов.

Кластер-безопасность: несколько воркеров могут запускать дворника
одновременно; гонка при DELETE безвредна (UNIQUE id, повторное удаление —
no-op), а состав чата читается из того же Redis-кеша, что и typing-сервис
(deps.chat_member_ids), поэтому лишние запросы к PG в горячем цикле
минимальны. Идемпотентность доставки на клиенте обеспечивается тем, что
Flet удаляет карточку только если она ещё присутствует в списке.

Дизайн-решения:
- цикл никогда не роняет приложение: ошибки логируются, следующий тик
  продолжается через interval (best-effort UX + гарантированная eventual
  физическая очистка);
- SELECT ... FOR UPDATE на PG отсутствует сознательно: стоимость блокировки
  выше пользы приидемпотентной операции удаления по первичному ключу;
- отмена задачи (shutdown приложения) корректно завершает цикл через
  asyncio.CancelledError.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import Dict, List, Optional

from sqlalchemy import text as sql_text

from server import database
from server.cache import cache
from server.deps import chat_member_ids
from server.utils import as_utc, utc_now
from server.ws_manager import manager

log = logging.getLogger("meno.janitor")

# Кэш результата проверки схемы на процесс (схема меняется только с миграцией).
_SCHEMA_EXPIRES_AT: Optional[bool] = None


def _probe_sync(sync_conn) -> bool:
    from sqlalchemy import inspect as sa_inspect

    try:
        return "expires_at" in {
            c["name"] for c in sa_inspect(sync_conn).get_columns("messages")
        }
    except Exception:  # нет таблицы/прав — консервативно считаем схему полной
        return True


async def _schema_has_expires_at(db) -> bool:
    """Есть ли в реальной схеме колонка messages.expires_at.

    Легаси-БД могут быть созданы до миграции a1f2e3d4b5c6; запросы с явным
    упоминанием колонки на них падают. Проба выполняется один раз через
    run_sync и кэшируется на процесс.
    """
    global _SCHEMA_EXPIRES_AT
    if _SCHEMA_EXPIRES_AT is None:
        try:
            _SCHEMA_EXPIRES_AT = bool(await db.run_sync(_probe_sync))
        except Exception:
            _SCHEMA_EXPIRES_AT = True
    return _SCHEMA_EXPIRES_AT


# --- Протокольные константы --------------------------------------------------
JANITOR_INTERVAL_SECONDS = 10  # период тика по ТЗ v2.0 Пункт 2
JANITOR_SCAN_LIMIT = 2000  # максимум строк за один скан (защита от
# длинных хвостов после простоя сервера)
JANITOR_DELETE_CHUNK = 500  # размер чанка DELETE ... WHERE id IN (...)
DELETE_EVENT_TYPE = "message_delete"  # имя WS-события (совпадает с клиентом)


class JanitorService:
    """Фоновый удалитель истёкших сообщений + рассылка message_delete."""

    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None
        self._tick_count = 0

    # ------------------------------------------------------------------ #
    # Жизненный цикл (lifespan)
    # ------------------------------------------------------------------ #

    async def start(self, interval: float = JANITOR_INTERVAL_SECONDS) -> None:
        """Запускает бесконечный цикл; повторный вызов идемпотентен."""
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self._loop(interval), name="meno-janitor")
        log.info("Janitor started (interval=%ss)", interval)

    async def stop(self) -> None:
        """Останавливает цикл и дожидается завершения текущего тика."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
            log.info("Janitor stopped")

    async def _loop(self, interval: float) -> None:
        while True:
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — дворник не роняет сервер
                log.error("Janitor tick failed: %s: %s", exc.__class__.__name__, exc)
            await asyncio.sleep(interval)

    # ------------------------------------------------------------------ #
    # Один тик: найти -> удалить -> почистить Redis -> разослать событие
    # ------------------------------------------------------------------ #

    async def run_once(self) -> int:
        """Выполняет одну волну очистки. Возвращает число удалённых сообщений."""
        now = utc_now()
        expired: List[Dict] = []

        async with database.get_db() as db:
            has_abs = await _schema_has_expires_at(db)

            # 1) Основной скан: все строки с ttl/view_once маркерами.
            #    Дедлайн считается в Python — диалект-безопасно (Этап 4.1),
            #    один round-trip вместо двух, работает и на легаси-схеме без
            #    колонки expires_at. ORDER BY id LIMIT делает проход стриминговым.
            rows = await database.aq(
                db,
                "SELECT id, chat_id, created_at, ttl_seconds, view_once, viewed"
                + (", expires_at" if has_abs else "")
                + " FROM messages "
                "WHERE ttl_seconds IS NOT NULL OR view_once = 1 "
                + ("OR expires_at IS NOT NULL " if has_abs else "")
                + "ORDER BY id LIMIT :batch",
                {"batch": JANITOR_SCAN_LIMIT},
            )
            for r in rows:
                dead = False
                exp = as_utc(r["expires_at"]) if has_abs else None
                if exp is not None and exp <= now:
                    dead = True  # абсолютный TTL v2.0
                elif r["view_once"] and r["viewed"]:
                    dead = True  # просмотрено однократное
                elif r["ttl_seconds"] is not None:
                    created = as_utc(r["created_at"])
                    if (
                        created is not None
                        and created + timedelta(seconds=int(r["ttl_seconds"])) <= now
                    ):
                        dead = True  # legacy относительный TTL
                if dead:
                    expired.append({"id": r["id"], "chat_id": r["chat_id"]})

            # 2) Гигиена refresh-токенов (перенесено из inline-цикла v1.1).
            await db.execute(
                sql_text("DELETE FROM refresh_tokens WHERE expires_at < :now"),
                {"now": now},
            )

            if not expired:
                self._tick_count += 1
                return 0

            ids = [row["id"] for row in expired]
            # Физическое удаление (не soft-delete): контент исчезает из БД.
            # Чанкуем, чтобы не строить SQL на тысячи плейсхолдеров за раз.
            for start in range(0, len(ids), JANITOR_DELETE_CHUNK):
                chunk = ids[start : start + JANITOR_DELETE_CHUNK]
                placeholders = ",".join(f":m{i}" for i in range(len(chunk)))
                params = {f"m{i}": mid for i, mid in enumerate(chunk)}
                await db.execute(
                    sql_text(f"DELETE FROM messages WHERE id IN ({placeholders})"),
                    params,
                )

        # 2) Принудительная очистка кеша Redis для удалённых сообщений.
        for row in expired:
            await cache.delete(f"msg:{row['id']}")
            await cache.delete(f"chat_last:{row['chat_id']}")

        # 3) Fan-out события message_delete всем участникам чатов.
        by_chat: Dict[int, List[int]] = {}
        for row in expired:
            by_chat.setdefault(int(row["chat_id"]), []).append(int(row["id"]))

        for chat_id, msg_ids in by_chat.items():
            member_ids = await chat_member_ids(chat_id)
            if not member_ids:
                continue
            payload = {
                "type": DELETE_EVENT_TYPE,
                "chat_id": chat_id,
                "message_ids": msg_ids,
            }
            # send_to_user сам выбирает маршрут: Redis Pub/Sub (все воркеры)
            # либо локальная доставка (single worker / без Redis).
            await manager.send_to_users(member_ids, payload)

        log.info(
            "Janitor erased %s message(s) across %s chat(s)", len(ids), len(by_chat)
        )
        self._tick_count += 1
        return len(ids)


janitor_service = JanitorService()

__all__ = [
    "JanitorService",
    "janitor_service",
    "JANITOR_INTERVAL_SECONDS",
    "DELETE_EVENT_TYPE",
]
