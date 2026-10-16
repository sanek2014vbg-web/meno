"""MeNo — аутентификация: пароли (bcrypt), JWT, 2FA (TOTP)."""
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
import jwt
import pyotp

import config
import database


# ---------- Пароли ----------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False


# ---------- JWT ----------
def create_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "exp": datetime.utcnow() + timedelta(days=config.JWT_EXPIRE_DAYS),
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGO)


def decode_token(token: str) -> Optional[int]:
    """Возвращает user_id по токену или None."""
    try:
        data = jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGO])
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


# ---------- Пользователи ----------
def get_user_by_id(user_id: int) -> Optional[dict]:
    with database.get_db() as db:
        return database.q1(db, "SELECT * FROM users WHERE id=?", (user_id,))


def get_user_by_phone(phone: str) -> Optional[dict]:
    with database.get_db() as db:
        return database.q1(db, "SELECT * FROM users WHERE phone=?", (phone,))


def touch_last_seen(user_id: int) -> None:
    with database.get_db() as db:
        db.execute(
            "UPDATE users SET last_seen=datetime('now') WHERE id=?", (user_id,)
        )


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