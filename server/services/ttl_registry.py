"""MeNo — реестр TTL-джоб дворника: загрузка, захват, телеметрия (Пункт 5 аудита).

Модуль инкапсулирует всю работу с таблицей ``janitor_jobs``:

- ``ensure_registered`` — идемпотентная регистрация стандартных регламентов
  (messages_ttl, refresh_tokens) при старте; не перетирает админские правки;
- ``due_jobs`` / ``claim_job`` / ``finish_job`` — жизненный цикл волны:
  интервальный фильтр + атомарный advisory-lock через UPDATE ... WHERE
  status='idle' (см. server/db/concurrency.py), поэтому гонка двух воркеров
  без SELECT FOR UPDATE безопасна на SQLite и PostgreSQL одинаково;
- whitelist-валидация имён таблиц/колонок из реестра перед подстановкой в SQL:
  строки janitor_jobs могут редактироваться админом напрямую — инъекция через
  метаданные реестра исключена на уровне типа (только [a-z0-9_]).

Сложность: due_jobs — O(J) c index scan по enabled+status (J — число джоб,
единицы); claim/finish — O(1) primary key seek.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import List, Optional

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncSession

from server.db.concurrency import conditional_update
from server.db.session_manager import aq
from server.utils import as_utc, utc_now

log = logging.getLogger("meno.janitor.registry")

_IDENT_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

JOB_MESSAGES_TTL = "messages_ttl"
JOB_REFRESH_TOKENS = "refresh_tokens"

# Стандартные регламенты: (job, table, ttl_column, grace_s, interval_s)
DEFAULT_JOBS = (
    (JOB_MESSAGES_TTL, "messages", "expires_at", 0, 60),
    (JOB_REFRESH_TOKENS, "refresh_tokens", "expires_at", 0, 300),
)


@dataclass(frozen=True)
class TtlJob:
    """Валидированная запись реестра janitor_jobs."""

    job: str
    table_name: str
    ttl_column: str
    grace_seconds: int
    interval_seconds: int

    def deadline_threshold(self, now):
        return now - timedelta(seconds=self.grace_seconds)


def _valid_ident(name: str) -> Optional[str]:
    """Имя таблицы/колонки из реестра пропускаем только как snake_case идентификатор."""
    if isinstance(name, str) and _IDENT_RE.match(name):
        return name
    return None


async def ensure_registered(session: AsyncSession) -> int:
    """Создаёт отсутствующие строки стандартных джоб. Возвращает число вставок.

    ON CONFLICT не используется — диалект-переносимость важнее экономии одного
    round-trip: сначала SELECT существующих имён (O(J)), затем INSERT только
    недостающих. Параллельный старт двух воркеров безопасен: повторный PK
    нарушает IntegrityError, который перехватывается и трактуется как
    «другой воркер уже зарегистрировал».
    """
    existing_rows = await aq(session, "SELECT job FROM janitor_jobs")
    existing = {r["job"] for r in existing_rows}
    inserted = 0
    for job, table, col, grace, interval in DEFAULT_JOBS:
        if job in existing:
            continue
        try:
            await session.execute(
                sql_text(
                    "INSERT INTO janitor_jobs "
                    "(job, table_name, ttl_column, grace_seconds, interval_seconds, "
                    "enabled, status, last_deleted_count) "
                    "VALUES (:job, :table, :col, :grace, :interval, 1, 'idle', 0)"
                ),
                {
                    "job": job,
                    "table": table,
                    "col": col,
                    "grace": grace,
                    "interval": interval,
                },
            )
            inserted += 1
        except Exception as exc:  # noqa: BLE001 — конкурентная регистрация идентичной строки
            from sqlalchemy.exc import IntegrityError

            if isinstance(exc, IntegrityError):
                log.info("Janitor job %s registered concurrently", job)
                continue
            raise
    if inserted:
        log.info("Janitor registry: %s new job(s)", inserted)
    return inserted


async def load_due_jobs(session: AsyncSession, now=None) -> List[TtlJob]:
    """Enabled-джобы, у которых истёк interval_seconds с прошлого успешного тика.

    last_run_at IS NULL трактуется как «ещё не выполнялась» → джоба сразу считается due.
    Невалидные идентификаторы таблиц/колонок логируются и пропускаются
    (защита от ручной порчи реестра), а не роняют весь цикл дворника.
    """
    now = now or utc_now()
    rows = await aq(
        session,
        "SELECT job, table_name, ttl_column, grace_seconds, interval_seconds, last_run_at "
        "FROM janitor_jobs WHERE enabled = 1 ORDER BY job",
    )
    due: List[TtlJob] = []
    for r in rows:
        table = _valid_ident(r["table_name"])
        col = _valid_ident(r["ttl_column"])
        if table is None or col is None:
            log.error(
                "Janitor job %s has unsafe identifiers (%r.%r) — skipped",
                r["job"],
                r["table_name"],
                r["ttl_column"],
            )
            continue
        last = as_utc(r["last_run_at"])
        interval = max(int(r["interval_seconds"] or 0), 1)
        if last is not None and (now - last) < timedelta(seconds=interval):
            continue
        due.append(
            TtlJob(
                job=r["job"],
                table_name=table,
                ttl_column=col,
                grace_seconds=max(int(r["grace_seconds"] or 0), 0),
                interval_seconds=interval,
            )
        )
    return due


async def claim_job(session: AsyncSession, job: TtlJob, owner: str) -> bool:
    """Атомарный захват джобы: idle -> running. True == эксклюзивность получена."""
    won = await conditional_update(
        session,
        table="janitor_jobs",
        set_assignments={"status": "running", "owner": owner[:64]},
        where_assignments={"job": job.job, "status": "idle"},
    )
    return won > 0


async def finish_job(
    session: AsyncSession, job: TtlJob, deleted: int, *, crashed: bool = False
) -> None:
    """Финализация волны: телеметрия + снятие лока (running -> idle).

    Условие status='running' в WHERE защищает от «чужого» finish: если лок
    уже снят параллельным сбросом, UPDATE не тронет ничего. При crash-волне
    last_run_at НЕ обновляется — следующая попытка наступит немедленно.
    """
    now = utc_now()
    sets = {"status": "idle", "owner": None, "last_deleted_count": int(deleted)}
    if not crashed:
        sets["last_run_at"] = now
    updated = await conditional_update(
        session,
        table="janitor_jobs",
        set_assignments=sets,
        where_assignments={"job": job.job, "status": "running"},
    )
    if updated == 0:
        log.warning("Janitor job %s finished without holding the lock", job.job)


async def delete_expired_rows(session: AsyncSession, job: TtlJob, now, limit: int) -> int:
    """Физическое удаление строк с ttl_column <= threshold, чанками по ``limit``.

    Диалект-безопасно: сравнение tz-aware параметра с DateTime(timezone=True)
    колонкой работает на asyncpg и aiosqlite одинаково; порог считается в
    Python (grace учтён). LIMIT в DELETE PG не поддерживает — выбираем id
    отдельным SELECT (O(limit) index scan по скан-индексу), затем удаляем
    чанком по первичному ключу (O(limit) seeks).
    """
    threshold = job.deadline_threshold(now)
    ids = await aq(
        session,
        f"SELECT id FROM {job.table_name} "
        f"WHERE {job.ttl_column} IS NOT NULL AND {job.ttl_column} <= :threshold "
        "ORDER BY id LIMIT :lim",
        {"threshold": threshold, "lim": int(limit)},
    )
    if not ids:
        return 0
    total = 0
    chunk: List[int] = []
    for row in ids:
        chunk.append(int(row["id"]))
        if len(chunk) >= 500:
            total += await _delete_chunk(session, job.table_name, chunk)
            chunk = []
    if chunk:
        total += await _delete_chunk(session, job.table_name, chunk)
    return total


async def _delete_chunk(session: AsyncSession, table: str, ids: List[int]) -> int:
    placeholders = ",".join(f":b{i}" for i in range(len(ids)))
    params = {f"b{i}": mid for i, mid in enumerate(ids)}
    result = await session.execute(
        sql_text(f"DELETE FROM {table} WHERE id IN ({placeholders})"), params
    )
    return int(result.rowcount or 0)
