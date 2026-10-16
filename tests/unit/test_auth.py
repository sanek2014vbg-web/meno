import pytest
from datetime import datetime, timedelta
from server.auth import (
    hash_password, check_password, create_access_token, decode_token,
    generate_totp_secret, verify_totp, is_account_locked
)

def test_password_hashing():
    password = "StrongPassword123!"
    hashed = hash_password(password)
    assert hashed != password
    assert check_password(password, hashed) is True
    assert check_password("WrongPassword", hashed) is False

def test_jwt_token_lifecycle():
    user_id = 123
    token = create_access_token(user_id)
    assert token is not None
    assert decode_token(token) == user_id

def test_invalid_jwt_token():
    assert decode_token("invalid.token.here") is None
    assert decode_token("") is None

def test_totp_verification():
    secret = generate_totp_secret()
    import pyotp
    totp = pyotp.TOTP(secret)
    current_code = totp.now()
    
    assert verify_totp(secret, current_code) is True
    assert verify_totp(secret, "000000") is False

def test_account_lockout_logic():
    # Case 1: Not locked
    user_unlocked = {"lockout_until": None}
    locked, until = is_account_locked(user_unlocked)
    assert locked is False
    
    # Case 2: Locked in the future
    future_date = datetime.utcnow() + timedelta(minutes=10)
    user_locked = {"lockout_until": future_date}
    locked, until = is_account_locked(user_locked)
    assert locked is True
    assert until == future_date
    
    # Case 3: Lockout expired
    past_date = datetime.utcnow() - timedelta(minutes=1)
    user_expired = {"lockout_until": past_date}
    locked, until = is_account_locked(user_expired)
    assert locked is False
