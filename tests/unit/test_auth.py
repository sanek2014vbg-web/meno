import pytest
from server.auth import hash_password, check_password, create_access_token, decode_token

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
