"""MeNo — сервис чтения истории и поиска сообщений (Пункт 1 аудита).

SQL-конструкции курсорной пагинации и диалект-адаптивного полнотекстового
поиска вынесены из god-route; маршрут остаётся тонким HTTP-слоом.

Совместимость схем (Этап 4.1/A7): предикат «сообщение живо» строится с
учётом наличия колонки messages.expires_at в РЕАЛЬНОЙ схеме БД — легаси-БД до
миграции a1f2e3d4b5c6 не содержат её, и явное упоминание в WHERE рухнуло бы
'no such column'. Проба схемы кэшируется на процесс (sync_engine.connect —
одноразовый вне горячего пути), поэтому steady-state стоимость = 0 round-trip.

Big O:
- list_messages: index seek (chat_id,id) DESC LIMIT n+1 — O(log N + limit);
- search PG: to_tsvector('russian') по GIN-индексу (миграция 5c8d9e0f1a2b) —
  O(log N + matches); SQLite fallback LIKE '%q%' — O(N) по сообщениям чата
  (осознанная деградация self-hosted без PG, задокументирована в ТЗ Этап 4.2).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import AsyncSession

from server import config
from server.db.connection import engine
from server.db.session_manager import aq
from server.utils import utc_now

log = logging.getLogger("meno.services.history")

# v2.0 Пункт 2: SQL-предикат «сообщение ещё живо». Исключает из любых
# выдач строки, чей срок истёк, но которые ещё не успел стереть janitor
# (окно между expires_at и следующим тиком <= 10 c). Диалект-безопасно:
# сравнение tz-aware параметра с колонкой одинаково работает на asyncpg
# и aiosqlite; legacy-строки без expires_at фильтруются по created_at+ttl.
_LIVE_CLAUSE = (
    "("
    "(m.expires_at IS NOT NULL AND m.expires_at > :now) "
    "OR (m.expires_at IS NULL AND ("
    "m.ttl_seconds IS NULL "
    "OR datetime(m.created_at, '+' || CAST(m.ttl_seconds AS TEXT) || ' seconds') > :now_text"
    "))"
    ")"
)

_SCHEMA_EXPIRES_AT: Optional[bool] = None


def schema_has_expires_at() -> bool:
    """Есть ли в реальной схеме БД колонка messages.expires_at (кэш на процесс)."""
    global _SCHEMA_EXPIRES_AT
    if _SCHEMA_EXPIRES_AT is None:
        try:
            with engine.sync_engine.connect() as conn:
                cols = {c["name"] for c in sa_inspect(conn).get_columns("messages")}
            _SCHEMA_EXPIRES_AT = "expires_at" in cols
        except Exception:  # инспектор недоступен — считаем схему полной
            _SCHEMA_EXPIRES_AT = True
    return _SCHEMA_EXPIRES_AT


_SCHEMA_SHADOW: Optional[bool] = None


def schema_has_compliance_logs() -> bool:
    """Создана ли таблица compliance_audit_logs (миграция c8d9e0f1a2b3; кэш).

    Тот же приём graceful degradation, что у schema_has_expires_at: в БД,
    развёрнутой без миграций v2.0, теневой перехват молча отключается вместо
    падения hot-path отправки с 'no such table'. Инспектор читает один раз
    за жизнь процесса (схема меняется только Alembic'ом).
    """
    global _SCHEMA_SHADOW
    if _SCHEMA_SHADOW is None:
        try:
            with engine.sync_engine.connect() as conn:
                _SCHEMA_SHADOW = (
                    "compliance_audit_logs" in sa_inspect(conn).get_table_names()
                )
        except Exception:  # инспектор недоступен — считаем схему полной
            _SCHEMA_SHADOW = True
    return _SCHEMA_SHADOW


def live_clause() -> str:
    return _LIVE_CLAUSE if schema_has_expires_at() else "1=1"


def live_params(now, now_text: str) -> Dict[str, Any]:
    return {"now": now, "now_text": now_text}


async def fetch_page(
    session: AsyncSession,
    chat_id: int,
    *,
    limit: int,
    before_id: Optional[int],
    extra_where: Optional[str] = None,
    extra_params: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Одна страница истории/поиска: m.* + sender_name, ORDER BY id DESC.

    Возвращает минимум limit+1 строк маркером has_more (срез делает слой
    маршрута) — классический cursor over-fetch на один элемент.
    """
    now = utc_now()
    sql = (
        "SELECT m.*, u.display_name AS sender_name "
        "FROM messages m "
        "JOIN users u ON u.id = m.sender_id "
        f"WHERE m.chat_id = :chat_id AND {live_clause()} "
    )
    params: Dict[str, Any] = {"chat_id": chat_id, "fetch_n": limit + 1}
    params.update(live_params(now, now.strftime("%Y-%m-%d %H:%M:%S")))
    if extra_where:
        sql += f"AND ({extra_where}) "
        params.update(extra_params or {})
    if before_id:
        sql += " AND m.id < :before_id"
        params["before_id"] = before_id
    sql += " ORDER BY m.id DESC LIMIT :fetch_n"
    return await aq(session, sql, params)


def search_predicate(q_clean: str) -> tuple[str, Dict[str, Any]]:
    """Диалект-адаптивный предикат полнотекста + его параметры."""
    if config.IS_SQLITE:
        return "LOWER(m.content) LIKE LOWER(:q)", {"q": f"%{q_clean}%"}
    return (
        "to_tsvector('russian', m.content) @@ plainto_tsquery('russian', :q)",
        {"q": q_clean},
    )
