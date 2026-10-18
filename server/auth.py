"""MeNo — аутентификация: пароли (bcrypt), JWT, 2FA (TOTP), lockout, audit-лог."""
import logging
import secrets
from datetime import timedelta
from typing import Optional

import bcrypt
import jwt
import pyotp

from server import config, database
from server.database import text as sql_text
from server.cache import cache
from server.utils import as_utc, utc_now

log = logging.getLogger("meno.auth")

# ---------- Пароли ----------
# bcrypt использует только первые 72 байта пароля; всё остальное отбрасывается.
# Чтобы длинные пароли не теряли энтропию молча, пред-хешируем их SHA-256
# (digest base64 < 72 байт всегда) — стандартная практика для bcrypt.
import base64
import hashlib

# Детерминированный "фиктивный" хеш для атаки по времени (user enumeration):
# при неизвестном username мы всё равно выполняем проверку пароля, чтобы
# ответ занимал столько же времени, сколько при существующем пользователе.


def _gensalt():
    """Cost factor из конфига: прод — 12 раундов, тесты (MENO_BCRYPT_ROUNDS=4) — быстро."""
    return bcrypt.gensalt(rounds=config.BCRYPT_ROUNDS)


_DUMMY_PASSWORD_HASH = bcrypt.hashpw(b"meno-timing-equalizer", _gensalt()).decode()


def _prehash(password: str) -> bytes:
    """SHA-256 -> base64: гарантирует, что в bcrypt попадает полные 72 байта."""
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_prehash(password), _gensalt()).decode()


def check_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_prehash(password), password_hash.encode())
    except ValueError:
        return False


# ---------- JWT ----------
# Короткоживущий токен доступа и долгоживущий refresh (хранится в БД, отзываема).


def create_access_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "exp": utc_now() + timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": utc_now(),
        "type": "access",
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGO)


def new_refresh_token() -> str:
    """Refresh token — opaque random строка (не JWT): мгновенно отзывается в БД."""
    return secrets.token_urlsafe(48)


def new_token_family() -> str:
    """Идентификатор «семьи» refresh-токенов (для ротации и детекции переиспользования)."""
    return secrets.token_urlsafe(24)


def decode_token(token: str) -> Optional[int]:
    """Возвращает user_id по access-токену или None."""
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


def totp_provisioning_uri(secret: str, name: str) -> str:
    """Ссылка/QR для добавления в Google Authenticator и подобные."""
    return pyotp.TOTP(secret).provisioning_uri(name=name, issuer_name=config.APP_NAME)


def verify_totp(secret: str, code: str) -> bool:
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:
        return False


# ---------- Account Lockout ----------
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15


def is_account_locked(user: dict) -> tuple[bool, Optional[object]]:
    """Проверяет блокировку аккаунта (tz-safe: naive из БД приводим к UTC)."""
    until = as_utc(user.get("lockout_until"))
    if until and until > utc_now():
        return True, until
    return False, None


async def record_failed_attempt(user_id: int) -> None:
    """Увеличивает счётчик неудач и включает блокировку при достижении лимита.

    Атомарная реализация (без TOCTOU-гонки SELECT+UPDATE): один UPDATE
    инкрементирует счётчик в БД, затем читается актуальное значение;
    блокировка проставляется отдельным условным UPDATE только при
    достижении лимита.
    """
    async with database.get_db() as db:
        res = await db.execute(
            sql_text(
                "UPDATE users SET failed_attempts = COALESCE(failed_attempts, 0) + 1 "
                "WHERE id=:id"
            ),
            {"id": user_id},
        )
        if res.rowcount == 0:
            return
        attempts_row = await database.aq1(
            db, "SELECT failed_attempts FROM users WHERE id=:id", {"id": user_id}
        )
        attempts = attempts_row["failed_attempts"] if attempts_row else None
        if attempts is not None and attempts >= MAX_FAILED_ATTEMPTS:
            lockout_until = utc_now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            await db.execute(
                sql_text(
                    "UPDATE users SET lockout_until=:l WHERE id=:id AND lockout_until IS NULL"
                ),
                {"l": lockout_until, "id": user_id},
            )
    await _invalidate_user_cache(user_id)


async def reset_failed_attempts(user_id: int) -> None:
    """Сбрасывает счётчик попыток при успешном входе."""
    async with database.get_db() as db:
        await db.execute(
            sql_text(
                "UPDATE users SET failed_attempts=0, lockout_until=NULL WHERE id=:id"
            ),
            {"id": user_id},
        )
    await _invalidate_user_cache(user_id)


# ---------- Audit log (security_events) ----------


async def log_security_event(
    event_type: str,
    *,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    ip: Optional[str] = None,
    detail: str = "",
) -> None:
    """Пишет событие безопасности в таблицу security_events.

    Ошибка записи аудита не должна ронять основной запрос — логируем её,
    но не поднимаем исключение выше.
    """
    try:
        async with database.get_db() as db:
            await db.execute(
                sql_text(
                    "INSERT INTO security_events (event_type, user_id, username, ip, detail) "
                    "VALUES (:t, :u, :n, :i, :d)"
                ),
                {"t": event_type[:48], "u": user_id, "n": (username or "")[:64] or None,
                 "i": (ip or "")[:64] or None, "d": detail[:2000]},
            )
    except Exception as exc:  # noqa: BLE001 — аудит best-effort, но с явной записью ошибки
        log.error("Failed to write security event %s: %s", event_type, exc)


# ---------- Пользователи (с кешированием) ----------


async def _invalidate_user_cache(user_id: int) -> None:
    await cache.delete(f"user:id:{user_id}")
    await cache.delete_by_prefix("user:name:")


async def get_user_by_id(user_id: int) -> Optional[dict]:
    cache_key = f"user:id:{user_id}"
    cached = await cache.get(cache_key)
    if cached:
        return cached
    async with database.get_db() as db:
        user = await database.aq1(db, "SELECT * FROM users WHERE id=:id", {"id": user_id})
    if user:
        await cache.set(cache_key, user, ttl=300)
    return user


async def get_user_by_username(username: str) -> Optional[dict]:
    """Основной способ нахождения аккаунта — по уникальному username."""
    cache_key = f"user:name:{username}"
    cached = await cache.get(cache_key)
    if cached:
        return cached
    async with database.get_db() as db:
        user = await database.aq1(
            db, "SELECT * FROM users WHERE username=:username", {"username": username}
        )
    if user:
        await cache.set(cache_key, user, ttl=300)
    return user


async def touch_last_seen(user_id: int) -> None:
    async with database.get_db() as db:
        await db.execute(
            sql_text("UPDATE users SET last_seen=CURRENT_TIMESTAMP WHERE id=:id"),
            {"id": user_id},
        )
    await _invalidate_user_cache(user_id)


def user_to_public(u: dict) -> dict:
    """Публичное представление пользователя — без пароля и секретов 2FA."""
    return {
        "id": u["id"],
        "username": u.get("username") or "",
        "display_name": u["display_name"],
        "role": u["role"],
        "avatar_path": u.get("avatar_path"),
        "last_seen": u["last_seen"],
        "twofa_enabled": bool(u.get("twofa_enabled")),
        "e2e_pub": u.get("e2e_pub"),
    }
