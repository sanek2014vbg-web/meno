"""MeNo — аутентификация: пароли (bcrypt), JWT, 2FA (TOTP)."""
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
import jwt
import pyotp

import config
import database
from server.cache import cache

# ---------- Пароли ----------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False


# ---------- JWT ----------
# Короткоживущий токен доступа (15 минут)
ACCESS_TOKEN_EXPIRE_MINUTES = 15
# Долгоживущий токен обновления (7 дней)
REFRESH_TOKEN_EXPIRE_DAYS = 7

def create_access_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "type": "access"
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGO)

def create_refresh_token(user_id: int) -> str:
    # Refresh token может быть просто случайной длинной строкой (opaque token)
    # Это безопаснее, так как мы храним его в БД и можем мгновенно отозвать.
    return secrets.token_urlsafe(64)

def decode_token(token: str) -> Optional[int]:
    """Возвращает user_id по токену или None."""
    try:
        data = jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGO])
        if data.get("type") != "access":
            return None
        return int(data["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        return None


# ---------- 2FA (TOTP) ----------
def generate_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, phone: str) -> str:
    """Ссылка/QR для добавления в Google Authenticator и подобные."""
    return pyotp.TOTP(secret).provisioning_uri(name=phone, issuer_name=config.APP_NAME)


def verify_totp(secret: str, code: str) -> bool:
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:
        return False


# ---------- Пользователи (с кешированием) ----------
async def get_user_by_id(user_id: int) -> Optional[dict]:
    cache_key = f"user:id:{user_id}"
    cached = await cache.get(cache_key)
    if cached:
        return cached

    async with database.get_db() as db:
        user = await database.aq1(db, "SELECT * FROM users WHERE id=:id", {"id": user_id})
        if user:
            await cache.set(cache_key, user, ttl=300) # кешируем на 5 минут
        return user


async def get_user_by_phone(phone: str) -> Optional[dict]:
    cache_key = f"user:phone:{phone}"
    cached = await cache.get(cache_key)
    if cached:
        return cached

    async with database.get_db() as db:
        user = await database.aq1(db, "SELECT * FROM users WHERE phone=:phone", {"phone": phone})
        if user:
            await cache.set(cache_key, user, ttl=300)
        return user


async def touch_last_seen(user_id: int) -> None:
    async with database.get_db() as db:
        await db.execute(
            "UPDATE users SET last_seen=CURRENT_TIMESTAMP WHERE id=:id", {"id": user_id}
        )
        # Инвалидируем кеш профиля, так как last_seen изменился
        await cache.delete(f"user:id:{user_id}")


def user_to_public(u: dict) -> dict:
    """Публичное представление пользователя — без пароля и секретов 2FA."""
    return {
        "id": u["id"],
        "phone": u["phone"],
        "display_name": u["display_name"],
        "role": u["role"],
        "avatar_path": u.get("avatar_path"),
        "last_seen": u["last_seen"],
        "twofa_enabled": bool(u.get("twofa_enabled")),
        "e2e_pub": u.get("e2e_pub"),
    }
