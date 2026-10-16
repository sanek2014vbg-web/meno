import asyncio
import httpx
from fastapi.testclient import TestClient
from server.main import app
import database
import config

# Using TestClient for easier FastAPI testing without needing a live server
client = TestClient(app)

def test_account_lockout():
    print("Testing Account Lockout...")
    phone = "79990000001" # Assume this user exists in your test DB
    password = "wrong_password"
    
    # 1. Attempt failed logins up to the limit (5)
    for i in range(5):
        resp = client.post("/api/login", json={"phone": phone, "password": password})
        print(f"Attempt {i+1}: {resp.status_code}")
    
    # 2. The 6th attempt should be blocked with 403
    resp = client.post("/api/login", json={"phone": phone, "password": password})
    print(f"Attempt 6 (Lockout check): {resp.status_code} - {resp.text}")
    
    if resp.status_code == 403 and "заблокирован" in resp.text:
        print("✅ Account Lockout works!")
    else:
        print("❌ Account Lockout failed!")

if __name__ == "__main__":
    test_account_lockout()
