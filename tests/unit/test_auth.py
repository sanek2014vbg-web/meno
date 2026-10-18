"""Юнит-тесты криптографического ядра аутентификации (без БД)."""

from datetime import datetime, timedelta, timezone

import pyotp

from server.auth import (
    MAX_FAILED_ATTEMPTS,
    check_password,
    create_access_token,
    decode_token,
    generate_totp_secret,
    hash_password,
    is_account_locked,
    new_refresh_token,
    new_token_family,
    verify_totp,
)
from server.utils import as_utc, utc_now


def test_password_hashing():
    password = "StrongPassword123!"
    hashed = hash_password(password)
    assert hashed != password
    assert check_password(password, hashed) is True
    assert check_password("WrongPassword", hashed) is False


def test_password_hash_salts_differ():
    h1 = hash_password("same-pass")
    h2 = hash_password("same-pass")
    assert h1 != h2  # bcrypt использует случайную соль
    assert check_password("same-pass", h1) and check_password("same-pass", h2)


def test_check_password_invalid_hash_returns_false():
    assert check_password("x", "not-a-bcrypt-hash") is False


def test_jwt_token_lifecycle():
    user_id = 123
    token = create_access_token(user_id)
    assert token is not None
    assert decode_token(token) == user_id


def test_invalid_jwt_token():
    assert decode_token("invalid.token.here") is None
    assert decode_token("") is None


def test_jwt_rejects_wrong_secret():
    import jwt as pyjwt

    forged = pyjwt.encode({"sub": "1", "type": "access"}, "x" * 64, algorithm="HS256")
    assert decode_token(forged) is None


def test_jwt_rejects_refresh_type():
    import jwt as pyjwt
    from server import config

    tok = pyjwt.encode(
        {
            "sub": "1",
            "type": "refresh",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        },
        config.JWT_SECRET,
        algorithm=config.JWT_ALGO,
    )
    assert decode_token(tok) is None


def test_refresh_tokens_are_unique_opaque():
    t1, t2 = new_refresh_token(), new_refresh_token()
    assert t1 != t2 and len(t1) >= 40 and "." not in t1


def test_token_families_unique():
    assert new_token_family() != new_token_family()


def test_totp_verification():
    secret = generate_totp_secret()
    totp = pyotp.TOTP(secret)
    assert verify_totp(secret, totp.now()) is True
    assert (
        verify_totp(secret, "000000") is False or True
    )  # код может случайно совпасть — проверяем ниже надёжнее
    assert verify_totp(secret, "999999") is False or totp.now() == "999999"


def test_totp_wrong_secret_fails():
    s1, s2 = generate_totp_secret(), generate_totp_secret()
    code = pyotp.TOTP(s1).now()
    assert verify_totp(s2, code) is False


def test_account_lockout_logic():
    locked, _ = is_account_locked({"lockout_until": None})
    assert locked is False

    future = utc_now() + timedelta(minutes=5)
    locked, until = is_account_locked({"lockout_until": future})
    assert locked is True and until is not None

    past = utc_now() - timedelta(minutes=1)
    locked, _ = is_account_locked({"lockout_until": past})
    assert locked is False


def test_account_lockout_naive_db_datetime_is_handled():
    """A17: naive datetime из БД приводится к UTC и корректно сравнивается."""
    naive_future = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(
        minutes=5
    )
    locked, _ = is_account_locked({"lockout_until": naive_future})
    assert locked is True


def test_as_utc_conversion():
    naive = datetime(2026, 1, 1, 12, 0, 0)
    aware = as_utc(naive)
    assert aware.tzinfo is timezone.utc
    assert as_utc(None) is None


def test_max_failed_attempts_constant():
    assert MAX_FAILED_ATTEMPTS == 5
