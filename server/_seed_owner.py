"""MeNo — одноразовый скрипт: создаёт тестового владельца Owner (79990000001/1234).

Используется после пересоздания БД, чтобы test_api.py и test_devmode.py
прошли с чистыми данными. Запуск: python _seed_owner.py
"""
import pathlib
import re

import httpx

BASE = "http://127.0.0.1:8000"
LOG = pathlib.Path(__file__).parent / "server.log"

c = httpx.Client(timeout=10)

# 1. Запрашиваем код подтверждения
r = c.post(f"{BASE}/api/register", json={"phone": "79990000001"})
print("Запрос кода:", r.status_code, r.json())
assert r.status_code == 200

# 2. Достаём код из лога сервера (последнее вхождение)
text = LOG.read_text(encoding="utf-8", errors="ignore")
matches = re.findall(r"Код для 79990000001: (\d+)", text)
code = matches[-1]
print("Код из лога:", code)

# 3. Подтверждаем и создаём аккаунт Owner
r = c.post(f"{BASE}/api/verify", json={
    "phone": "79990000001", "code": code,
    "password": "1234", "display_name": "Owner",
})
data = r.json()
print("Верификация:", r.status_code, data)
assert r.status_code == 200 and "token" in data
print("Owner создан, id:", data["user"]["id"])