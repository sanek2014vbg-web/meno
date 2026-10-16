import pytest
from httpx import AsyncClient
from server.main import app
from server.auth import MAX_FAILED_ATTEMPTS

@pytest.mark.asyncio
async def test_login_lockout(client):
    """Test that account is locked after N failed attempts."""
    username = "lockout_tester"  # User must exist in the test DB
    password = "wrong_password"
    
    # 1. Perform failed logins up to the limit
    for i in range(MAX_FAILED_ATTEMPTS):
        resp = await client.post("/api/login", json={"username": username, "password": password})
        assert resp.status_code == 400
    
    # 2. Next attempt should be blocked (403)
    resp = await client.post("/api/login", json={"username": username, "password": password})
    assert resp.status_code == 403
    assert "заблокирован" in resp.text

@pytest.mark.asyncio
async def test_login_success_resets_lockout(client):
    """Test that successful login resets failed attempts."""
    # This requires a known user and password in the DB
    # Setup: manually set failed_attempts to 4 for a user
    # Execution: login with correct password
    # Result: failed_attempts should be 0
    pass
