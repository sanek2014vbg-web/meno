"""MeNo — серверная доставка push-уведомлений (FCM / APNs-мост).

Честные ограничения:
- полноценные push возможны только в нативной сборке Android (FCM);
- если ключи FCM не заданы (MENO_FCM_SERVER_KEY или MENO_FCM_CREDENTIALS),
  отправка безопасно пропускается: мессенджер продолжает работать
  через WebSocket в открытом приложении;
- токены клиентов хранятся в БД (таблица push_tokens) и привязываются
  к пользователю (по одному токену на платформу).
"""
import json
import logging
from typing import Optional

import config
import database

log = logging.getLogger("meno.push")


def register_token(user_id: int, token: str, platform: str = "android") -> None:
    """Сохраняет push-токен устройства пользователя (upsert)."""
    with database.get_db() as db:
        db.execute(
            "INSERT INTO push_tokens (user_id, token, platform) VALUES (?,?,?) "
            "ON CONFLICT(token) DO UPDATE SET user_id=excluded.user_id, platform=excluded.platform",
            (user_id, token.strip(), platform[:32]),
        )


def unregister_token(user_id: int, token: str) -> None:
    with database.get_db() as db:
        db.execute(
            "DELETE FROM push_tokens WHERE user_id=? AND token=?",
            (user_id, token.strip()),
        )


def _tokens_of(user_id: int) -> list:
    with database.get_db() as db:
        rows = database.q(db, "SELECT token, platform FROM push_tokens WHERE user_id=?", (user_id,))
    return rows


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


async def send_to_user(user_id: int, title: str, body: str, data: dict = None) -> int:
    """Отправляет уведомление на все устройства пользователя.

    Возвращает число успешно отправленных токенов. Если FCM не настроен —
    возвращает 0 без ошибок (приложение работает через WebSocket).
    """
    if not (config.FCM_SERVER_KEY or config.FCM_CREDENTIALS):
        return 0  # push не настроен — тихий пропуск

    sent = 0
    for row in _tokens_of(user_id):
        try:
            if config.FCM_SERVER_KEY:
                if _send_legacy(row["token"], title, body, data or {}):
                    sent += 1
            # При credentials (OAuth2, HTTP v1) сюда добавляется отправка
            # через google.auth — реализуется после выпуска сервисного ключа.
        except Exception as exc:
            log.warning("Push-отправка не удалась: %s", exc.__class__.__name__)
    return sent