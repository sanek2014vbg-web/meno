"""MeNo — доставка кодов подтверждения.

Режимы (config.SMS_MODE):
- "test"     — код печатается в консоль (по умолчанию, для разработки)
- "telegram" — код отправляется владельцу через Telegram-бота
Позже сюда же можно добавить платный SMS-шлюз (Twilio и т.п.).
"""
import secrets
from datetime import datetime, timedelta

import config
import database


def _gen_code() -> str:
    """Шестизначный одноразовый код."""
    return f"{secrets.randbelow(1_000_000):06d}"


def request_code(phone: str, purpose: str = "register") -> tuple[bool, str]:
    """Генерирует код, сохраняет в БД и «отправляет» пользователю.

    Возвращает (успех, сообщение).
    """
    with database.get_db() as db:
        # Антиспам: не больше N кодов в час с одного номера
        hour_ago = (datetime.utcnow() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        row = db.execute(
            "SELECT COUNT(*) AS c FROM verify_codes WHERE phone=? AND created_at > ?",
            (phone, hour_ago),
        ).fetchone()
        if row["c"] >= config.SPAM_MAX_CODES_PER_HOUR:
            return False, "Слишком много запросов кода, попробуйте позже"

        code = _gen_code()
        expires = (datetime.utcnow() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
        cur = db.execute(
            "INSERT INTO verify_codes (phone, code, purpose, expires_at) VALUES (?,?,?,?)",
            (phone, code, purpose, expires),
        )
        new_id = cur.lastrowid
        # Аннулируем старые неиспользованные коды этого номера
        db.execute(
            "UPDATE verify_codes SET used=1 WHERE phone=? AND id != ? AND used=0",
            (phone, new_id),
        )

    return True, _deliver(phone, code)


def _deliver(phone: str, code: str) -> str:
    """Отправляет код выбранным способом, возвращает текст для пользователя."""
    if config.SMS_MODE == "telegram" and config.TELEGRAM_BOT_TOKEN:
        try:
            import urllib.request
            url = (
                f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
                f"?chat_id={phone}&text={config.APP_NAME}: ваш код {code}"
            )
            urllib.request.urlopen(url, timeout=5)
            return "Код отправлен в Telegram"
        except Exception:
            pass  # падаем в тестовый режим при ошибке сети

    # Тестовый режим: печатаем код в консоль/лог сервера.
    # flush=True обязателен: при перенаправлении stdout в файл
    # (server.log) без него строка остаётся в буфере Python.
    print(f"[{config.APP_NAME} TEST] Код для {phone}: {code}", flush=True)
    return "Код отправлен (тестовый режим — смотрите консоль сервера)"


def verify_code(phone: str, code: str, purpose: str) -> bool:
    """Проверяет код. Валидный код помечается использованным."""
    with database.get_db() as db:
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        row = db.execute(
            "SELECT id FROM verify_codes "
            "WHERE phone=? AND code=? AND purpose=? AND used=0 AND expires_at > ?",
            (phone, code, purpose, now),
        ).fetchone()
        if not row:
            return False
        db.execute("UPDATE verify_codes SET used=1 WHERE id=?", (row["id"],))
        return True