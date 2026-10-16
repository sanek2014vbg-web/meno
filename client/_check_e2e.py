"""MeNo — проверка полной цепочки E2E-шифрования (этап 3).

Что проверяем:
1. X25519-ключи Owner и Friend публикуются на сервере;
2. Общие секреты с двух сторон совпадают (X25519 + HKDF);
3. Текст шифруется AES-GCM и расшифровывается;
4. Сообщение отправляется с e2e=True, сервер хранит ШИФРОТЕКСТ;
5. История возвращает шифротекст (сервер не читает содержимое).

Запуск: python _check_e2e.py (сервер на 127.0.0.1:8000).
"""
import sqlite3
from pathlib import Path

import httpx

import crypto  # клиентский модуль (X25519/AES-GCM)

BASE = "http://127.0.0.1:8000"
DB = Path(__file__).parent.parent / "server" / "meno.db"

PASSED = 0
FAILED = 0


def check(name: str, cond: bool, detail=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  ✅ {name}")
    else:
        FAILED += 1
        print(f"  ❌ {name} {detail}")


def login(phone: str, password: str) -> dict:
    r = httpx.post(f"{BASE}/api/login", json={"phone": phone, "password": password}, timeout=10)
    return r.json()["token"]


def main():
    c = httpx.Client(timeout=10)

    # --- 1. Пара ключей для каждой стороны (не сохраняем на диск) ---
    owner_priv, owner_pub = crypto.generate_keys()
    friend_priv, friend_pub = crypto.generate_keys()

    t_owner = login("79990000001", "1234")
    h_owner = {"Authorization": f"Bearer {t_owner}"}
    t_friend = login("79990000002", "5678")
    h_friend = {"Authorization": f"Bearer {t_friend}"}

    r = c.put(f"{BASE}/api/me/e2e-key", json={"public_key": owner_pub}, headers=h_owner)
    check("Публикация ключа Owner", r.status_code == 200)
    r = c.put(f"{BASE}/api/me/e2e-key", json={"public_key": friend_pub}, headers=h_friend)
    check("Публикация ключа Friend", r.status_code == 200)

    # --- 2. Общий секрет с обеих сторон ---
    key_a = crypto.derive_chat_key(owner_priv, friend_pub)
    key_b = crypto.derive_chat_key(friend_priv, owner_pub)
    check("Общие секреты совпадают", key_a == key_b)

    # --- 3. Шифрование/расшифровка ---
    secret = "Секретное сообщение между двумя устройствами 🔐"
    payload = crypto.encrypt_text(key_a, secret)
    restored = crypto.decrypt_text(key_b, payload)
    check("Расшифровка текста", restored == secret)
    check("Шифротекст не похож на открытый текст", payload != secret and secret not in payload)

    # --- 4. Отправка с e2e=True в личный чат (id=1: Owner <-> Friend) ---
    r = c.post(f"{BASE}/api/chats/1/messages", json={
        "type": "text", "content": payload, "e2e": True,
    }, headers=h_owner)
    check("Отправка E2E-сообщения", r.status_code == 200, r.text)
    msg = r.json()
    check("Сервер вернул e2e=True", msg.get("e2e") is True)

    # --- 5. Сервер хранит шифротекст, а не исходный текст ---
    with sqlite3.connect(DB) as db:
        row = db.execute(
            "SELECT content, e2e FROM messages WHERE id=?", (msg["id"],)
        ).fetchone()
    check("В БД хранится шифротекст", row[0] == payload and secret not in (row[0] or ""))
    check("В БД флаг e2e=1", row[1] == 1)

    # --- 6. История отдаёт шифротекст без расшифровки ---
    r = c.get(f"{BASE}/api/chats/1/messages?limit=5", headers=h_owner)
    latest = r.json()[-1]
    check("История содержит шифротекст", latest["e2e"] is True and latest["content"] == payload)

    print(f"\nИтог E2E: {PASSED} ✅, {FAILED} ❌")
    raise SystemExit(1 if FAILED else 0)


if __name__ == "__main__":
    main()