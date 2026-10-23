"""MeNo — диалект-безопасные примитивы конкурентности (архитектурный аудит, Пункт 3).

Проблема: SQLite (тесты и self-hosted без PG) не поддерживает
``SELECT ... FOR UPDATE`` — пессимистичная блокировка строки на нём физически
невозможна, а read-modify-write в двух параллельных транзакциях теряет
обновления (lost update / dirty write).

Решение проекта — два взаимодополняющих примитива:

1. ``conditional_update`` — «оптимистичная блокировка через сам UPDATE»:
   предикат ожидаемого состояния попадает в WHERE, поэтому проверка и запись
   выполняются одной атомарной операцией движка. Провигравший гонку получает
   rowcount == 0 и трактует это как конфликт (HTTP 409 / повторное чтение).
   Работает идентично на PostgreSQL и SQLite: ни FOR UPDATE, ни RETURNING,
   ни pg-специфичных операторов не используется.

2. ``cas_rank_update`` — монотонный compare-and-set числового ранга
   (по образцу messages.status_rank из Этапа 7.3): CASE гарантирует, что
   параллельные записи не могут «откатить» значение назад; итог — максимум.

Сложность обоих примитивов: O(1) на строку при наличии первичного/уникального
индекса (UPDATE по id), один round-trip к БД.

Big-O заметка для conditional_update с параметризованным IN-списком:
построение SQL — O(len(params)), план БД — index seek по каждой паре.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import AsyncSession


async def conditional_update(
    session: AsyncSession,
    table: str,
    set_assignments: Dict[str, Any],
    where_assignments: Dict[str, Any],
) -> int:
    """Атомарный UPDATE c предикатом ожидаемого состояния в WHERE.

    ``set_assignments`` — колонка -> новое значение;
    ``where_assignments`` — колонка -> ОЖИДАЕМОЕ текущее значение (CAS-условие);
    None в значении WHERE корректно транслируется в ``IS NULL``.

    Возвращает number of rows затронутых строк: 0 == гонка проиграна
    (строка отсутствует или её состояние изменилось параллельной транзакцией).

    Имена колонок проходят whitelist-проверку идентификаторов: вызывающий код
    передаёт только константы сервиса, но защита от SQL-инъекции через имя
    колонки обязательна, т.к. идентификаторы не параметризуются.
    """
    if not set_assignments or not where_assignments:
        raise ValueError("conditional_update requires non-empty SET and WHERE dicts")

    def _ident(name: str) -> str:
        if not name.replace("_", "").isalnum() or name[0].isdigit():
            raise ValueError(f"Unsafe column identifier: {name!r}")
        return name

    set_parts = []
    params: Dict[str, Any] = {}
    for col, val in set_assignments.items():
        key = f"set_{_ident(col)}"
        set_parts.append(f"{col} = :{key}")
        params[key] = val

    where_parts = []
    for i, (col, val) in enumerate(where_assignments.items()):
        key = f"wh_{_ident(col)}_{i}"
        if val is None:
            where_parts.append(f"{col} IS NULL")
        else:
            where_parts.append(f"{col} = :{key}")
            params[key] = val

    sql = f"UPDATE {_ident(table)} SET {', '.join(set_parts)} WHERE {' AND '.join(where_parts)}"
    result = await session.execute(sql_text(sql), params)
    return int(result.rowcount or 0)


async def cas_rank_update(
    session: AsyncSession,
    table: str,
    rank_column: str,
    row_id: int,
    new_rank: int,
) -> bool:
    """Монотонный CAS: увеличивает числовой ранг, никогда не уменьшает.

    Эквивалент ``UPDATE ... SET r = CASE WHEN r < :new THEN :new ELSE r END``;
    возвращает True, если строка существует (ран мог остаться прежним —
    победил конкурент с большим рангом), False если строка не найдена.
    """
    result = await session.execute(
        sql_text(
            f"UPDATE {table} SET {rank_column} = "
            f"CASE WHEN {rank_column} < :new_rank THEN :new_rank ELSE {rank_column} END "
            "WHERE id = :row_id"
        ),
        {"new_rank": int(new_rank), "row_id": int(row_id)},
    )
    return bool(result.rowcount)


async def acquire_lock_or_skip(
    session: AsyncSession,
    *,
    lock_table: str,
    name_column: str,
    job_name: str,
    owner_value: str,
    free_values: tuple[str, ...] = ("idle", ""),
    busy_value: str = "running",
) -> bool:
    """Однострочный advisory-lock поверх обычной таблицы (диалект-agnostically).

    Атомарный захват: UPDATE, который сработает только если строка «свободна».
    rowcount == 1 → локладер получил эксклюзивность задачи до release();
    rowcount == 0 → задачу уже выполняет другой воркер/тик, пропускаем волну.

    Для SQLite отсутствие SELECT FOR UPDATE не мешает: сам UPDATE блокирует
    строку на время транзакции, а между транзакциями видимость состояния
    обеспечивает READ COMMITTED семантика обоих движков.
    """
    placeholders = ",".join(f":free{i}" for i in range(len(free_values)))
    params: Dict[str, Any] = {
        "owner": owner_value,
        "busy": busy_value,
        "job": job_name,
    }
    for i, v in enumerate(free_values):
        params[f"free{i}"] = v
    result = await session.execute(
        sql_text(
            f"UPDATE {lock_table} SET {name_column} = :busy, owner = :owner "
            f"WHERE job = :job AND {name_column} IN ({placeholders})"
        ),
        params,
    )
    return bool(result.rowcount)


async def release_lock(
    session: AsyncSession,
    *,
    lock_table: str,
    name_column: str,
    job_name: str,
    idle_value: str = "idle",
) -> None:
    """Снимает advisory-lock, установленный acquire_lock_or_skip."""
    await session.execute(
        sql_text(
            f"UPDATE {lock_table} SET {name_column} = :idle, owner = NULL "
            "WHERE job = :job"
        ),
        {"idle": idle_value, "job": job_name},
    )


async def fetch_job_state(
    session: AsyncSession,
    *,
    table: str,
    columns: tuple[str, ...],
    job_name: str,
    job_column: str = "job",
) -> Optional[Dict[str, Any]]:
    """Чтение служебной строки джобы (last_run_at и пр.) — одна строка или None."""
    cols = ", ".join(columns)
    from server.db.session_manager import aq1

    return await aq1(session, f"SELECT {cols} FROM {table} WHERE {job_column} = :job", {"job": job_name})
