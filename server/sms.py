"""MeNo — доставка кодов подтверждения.

Режимы (config.SMS_MODE):
- "test"     — код печатается в консоль (по умолчанию, для разработки)
- "telegram" — код отправляется владельцу через Telegram-бота
- "sms_ru"   — отправка через API SMS.RU
"""
import secrets
import logging
from datetime import datetime, timedelta, timezone

import config
import database
from server.sms_ru import send_sms as send_sms_ru

logger = logging.getLogger("meno.sms")

def _gen_code() -> str:
    """Шестизначный одноразовый код."""
    return f"{secrets.randbelow(1_000_000):06d}"

async def request_code(phone: str, purpose: str = "register") -> tuple[bool, str]:
    """Генерирует код, сохраняет в БД и «отправляет» пользователю.

    Возвращает (успех, сообщение).
    """
    async with database.get_db() as db:
        # Антиспам: не больше N кодов в час с одного номера
        hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        
        # Используем асинхронный aq1 для проверки лимита
        res = await database.aq1(
            db, 
            "SELECT COUNT(*) AS c FROM verify_codes WHERE phone=:phone AND created_at > :time",
            {"phone": phone, "time": hour_ago}
        )
        
        if res and res["c"] >= config.SPAM_MAX_CODES_PER_HOUR:
            return False, "Слишком много запросов кода, попробуйте позже"

        code = _gen_code()
        expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
        
        # Вставка нового кода
        await db.execute(
            "INSERT INTO verify_codes (phone, code, purpose, expires_at) VALUES (:phone, :code, :purpose, :expires)",
            {"phone": phone, "code": code, "purpose": purpose, "expires": expires}
        )
        
        # Аннулируем старые неиспользованные коды этого номера
        await db.execute(
            "UPDATE verify_codes SET used=1 WHERE phone=:phone AND used=0",
            {"phone": phone}
        )

    return True, await _deliver(phone, code)

async def _deliver(phone: str, code: str) -> str:
    """Отправляет код выбранным способом, возвращает текст для пользователя."""
    
    # 1. Режим SMS.RU
    if config.SMS_MODE == "sms_ru":
        success = await send_sms_ru(phone, f"{config.APP_NAME}: ваш код {code}")
        if success:
            return "Код отправлен по SMS"
        logger.error(f"Failed to deliver SMS via SMS.RU to {phone}")

    # 2. Режим Telegram
    if config.SMS_MODE == "telegram" and config.TELEGRAM_BOT_TOKEN:
        try:
            import httpx
            url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
            payload = {"chat_id": phone, "text": f"{config.APP_NAME}: ваш код {code}"}
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code == 200:
                    return "Код отправлен в Telegram"
        except Exception as e:
            logger.warning(f"Telegram delivery failed: {e}")

    # 3. Тестовый режим (fallback)
    print(f"[{config.APP_NAME} TEST] Код для {phone}: {code}", flush=True)
    return "Код отправлен (тестовый режим — смотрите консоль сервера)"

async def verify_code(phone: str, code: str, purpose: str) -> bool:
    """Проверяет код. Валидный код помечается использованным."""
    async with database.get_db() as db:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        
        row = await database.aq1(
            db,
            "SELECT id FROM verify_codes "
            "WHERE phone=:phone AND code=:code AND purpose=:purpose AND used=0 AND expires_at > :now",
            {"phone": phone, "code": code, "purpose": purpose, "now": now}
        )
        
        if not row:
            return False
            
        await db.execute("UPDATE verify_codes SET used=1 WHERE id=:id", {"id": row["id"]})
        return True
