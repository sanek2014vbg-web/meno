"""MeNo — серверная доставка push-уведомлений (FCM) + автономный outbox-fallback.

Честные ограничения:
- полноценные push возможны только в нативной сборке Android (FCM);
- если ключи FCM не заданы (MENO_FCM_SERVER_KEY / MENO_FCM_CREDENTIALS),
  уведомление кладётся в таблицу `push_outbox` — клиент забирает их через
  long-polling `/api/push/poll` (Этап 3.3 ТЗ). Никаких облачных сервисов;
- токены клиентов хранятся в БД (таблица push_tokens).
"""

import json
import logging

from sqlalchemy import text as sql_text

from server import config, database
from server.utils import utc_now

log = logging.getLogger("meno.push")


async def register_token(user_id: int, token: str, platform: str = "android") -> None:
    """Сохраняет push-токен устройства пользователя (upsert, диалект-безопасно)."""
    tok = token.strip()
    async with database.get_db() as db:
        existing = await database.aq1(
            db, "SELECT user_id FROM push_tokens WHERE token=:t", {"t": tok}
        )
        if existing:
            await db.execute(
                sql_text(
                    "UPDATE push_tokens SET user_id=:u, platform=:p WHERE token=:t"
                ),
                {"u": user_id, "p": platform[:32], "t": tok},
            )
        else:
            await db.execute(
                sql_text(
                    "INSERT INTO push_tokens (user_id, token, platform) VALUES (:u, :t, :p)"
                ),
                {"u": user_id, "t": tok, "p": platform[:32]},
            )


async def unregister_token(user_id: int, token: str) -> None:
    async with database.get_db() as db:
        await db.execute(
            sql_text("DELETE FROM push_tokens WHERE user_id=:u AND token=:t"),
            {"u": user_id, "t": token.strip()},
        )


async def _tokens_of(db, user_id: int) -> list:
    return await database.aq(
        db, "SELECT token, platform FROM push_tokens WHERE user_id=:u", {"u": user_id}
    )


def _send_legacy(token: str, title: str, body: str, data: dict) -> bool:
    """Отправка через FCM legacy HTTP API (Authorization: key=<server key>)."""
    import httpx

    payload = {
        "to": token,
        "notification": {"title": title, "body": body, "sound": "default"},
        "data": {str(k): str(v) for k, v in data.items()},
        "priority": "high",
    }
    r = httpx.post(
        "https://fcm.googleapis.com/fcm/send",
        json=payload,
        headers={
            "Authorization": f"key={config.FCM_SERVER_KEY}",
            "Content-Type": "application/json",
        },
        timeout=10,
    )
    ok = r.status_code == 200 and r.json().get("success", 0) > 0
    if not ok:
        log.warning("FCM legacy: статус %s для токена (обрезано)", r.status_code)
    return ok


async def _enqueue_outbox(user_id: int, title: str, body: str, data: dict) -> None:
    """Автономная доставка: событие в очередь outbox для long-polling клиента."""
    async with database.get_db() as db:
        await db.execute(
            sql_text(
                "INSERT INTO push_outbox (user_id, title, body, data, created_at) "
                "VALUES (:u, :t, :b, :d, :c)"
            ),
            {
                "u": user_id,
                "t": title[:200],
                "b": body[:500],
                "d": json.dumps(data or {}),
                "c": utc_now(),
            },
        )


async def send_to_user(
    user_id: int, title: str, body: str, data: dict | None = None
) -> int:
    """Отправляет уведомление на все устройства пользователя.

    Возвращает число успешно доставленных каналов. Если FCM не настроен —
    уведомление кладётся в outbox (long-polling fallback) и возвращается 0:
    приложение получает события через WebSocket или /api/push/poll.
    """
    if not (config.FCM_SERVER_KEY or config.FCM_CREDENTIALS):
        # Self-hosted без облаков: outbox-fallback (Этап 3.3)
        await _enqueue_outbox(user_id, title, body, data or {})
        return 0

    sent = 0
    async with database.get_db() as db:
        rows = await _tokens_of(db, user_id)
    for row in rows:
        try:
            if config.FCM_SERVER_KEY:
                if _send_legacy(row["token"], title, body, data or {}):
                    sent += 1
        except Exception as exc:
            log.warning("Push-отправка не удалась: %s", exc.__class__.__name__)
    return sent


async def poll_outbox(user_id: int, max_items: int = 20) -> list[dict]:
    """Выдаёт и удаляет накопленные уведомления пользователя (long-polling)."""
    async with database.get_db() as db:
        rows = await database.aq(
            db,
            "SELECT id, title, body, data, created_at FROM push_outbox "
            "WHERE user_id=:u ORDER BY id LIMIT :n",
            {"u": user_id, "n": max_items},
        )
        if rows:
            ids = [r["id"] for r in rows]
            await db.execute(
                sql_text(
                    "DELETE FROM push_outbox WHERE id IN ("
                    + ",".join(str(i) for i in ids)
                    + ")"
                )
            )
    return [
        {
            "id": r["id"],
            "title": r["title"],
            "body": r["body"],
            "data": json.loads(r["data"] or "{}"),
            "created_at": r["created_at"],
        }
        for r in rows
    ]


async def outbox_size(user_id: int) -> int:
    async with database.get_db() as db:
        row = await database.aq1(
            db, "SELECT COUNT(*) AS c FROM push_outbox WHERE user_id=:u", {"u": user_id}
        )
    return int((row or {}).get("c", 0))
