"""MeNo — управление refresh-сессиями (Этап 2.4 ТЗ).

Стратегия:
- refresh-токен — opaque случайная строка, хранится в БД с family/parent;
- при каждом /refresh старый токен ОТЗЫВАЕТСЯ и выдаётся новый той же семьи
  (ротация);
- если отозванный (или уже использованный) токен предъявляют повторно —
  это признак кражи: вся семья токенов отзывается, событие пишется в
  audit-лог (security_events).
"""
import logging
from datetime import timedelta
from typing import Optional

from sqlalchemy import text as sql_text

from server import auth, config, database
from server.utils import utc_now

log = logging.getLogger("meno.sessions")


async def issue_refresh_token(db, user_id: int, family: Optional[str] = None,
                              parent: Optional[str] = None) -> str:
    """Создаёт новый refresh-токен (с попыткой записи в переданную сессию db)."""
    token = auth.new_refresh_token()
    fam = family or auth.new_token_family()
    await db.execute(
        sql_text(
            "INSERT INTO refresh_tokens (token, user_id, family, parent, revoked, expires_at) "
            "VALUES (:t, :u, :f, :p, 0, :e)"
        ),
        {
            "t": token, "u": user_id, "f": fam, "p": parent,
            "e": utc_now() + timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS),
        },
    )
    return token


async def rotate_refresh_token(raw_token: str, ip: Optional[str] = None) -> Optional[dict]:
    """Атомарная ротация refresh-токена.

    Возвращает dict {"access_token", "refresh_token"} либо None, если токен
    недействителен/просрочен. При детекции переиспользования отзывает всю
    семью и пишет событие `refresh_reuse` в audit-лог.
    """
    from server.auth import create_access_token

    async with database.get_db() as db:
        row = await database.aq1(
            db,
            "SELECT * FROM refresh_tokens WHERE token=:t",
            {"t": raw_token},
        )
        if not row:
            return None

        # Переиспользование уже отозванного токена => компрометация всей семьи.
        if row["revoked"]:
            await db.execute(
                sql_text("UPDATE refresh_tokens SET revoked=1 WHERE family=:f AND revoked=0"),
                {"f": row["family"]},
            )
            await auth.log_security_event(
                "refresh_reuse", user_id=row["user_id"], ip=ip,
                detail="Отзыв всей семьи токенов из-за повторного использования",
            )
            log.warning("Refresh token reuse detected for user %s (family revoked)", row["user_id"])
            return None

        if database_is_expired(row["expires_at"]):
            return None

        # Ротация: отзываем предка, выдаём потомка той же семьи.
        result = await db.execute(
            sql_text("UPDATE refresh_tokens SET revoked=1 WHERE token=:t AND revoked=0"),
            {"t": raw_token},
        )
        if (result.rowcount or 0) == 0:
            # Гонка: параллельный запрос уже отозвал этот токен.
            await auth.log_security_event(
                "refresh_race", user_id=row["user_id"], ip=ip,
                detail="Параллельная ротация одного токена",
            )
            return None

        new_rt = await issue_refresh_token(
            db, row["user_id"], family=row["family"], parent=raw_token
        )
    return {
        "access_token": create_access_token(row["user_id"]),
        "refresh_token": new_rt,
    }


def database_is_expired(expires_at) -> bool:
    from server.utils import as_utc

    exp = as_utc(expires_at)
    return exp is None or exp <= utc_now()


async def revoke_token(db, raw_token: str, user_id: int) -> None:
    """Отзыв конкретного refresh-токена (logout). Идемпотентно."""
    await db.execute(
        sql_text("DELETE FROM refresh_tokens WHERE token=:t AND user_id=:uid"),
        {"t": raw_token, "uid": user_id},
    )


async def revoke_all_user_tokens(db, user_id: int) -> int:
    """Полный выход на всех устройствах (например, при смене пароля)."""
    result = await db.execute(
        sql_text("DELETE FROM refresh_tokens WHERE user_id=:u"), {"u": user_id}
    )
    return result.rowcount or 0
