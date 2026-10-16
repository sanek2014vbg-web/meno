"""MeNo — интеграционный тест API (локальный прогон).

Запуск: python test_api.py  (сервер должен быть запущен на 127.0.0.1:8000)
"""
import json
import pathlib
import re

import httpx

BASE = "http://127.0.0.1:8000"
LOG = pathlib.Path(__file__).parent / "server.log"

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


def last_code(phone: str) -> str:
    text = LOG.read_text(encoding="utf-8", errors="ignore")
    matches = re.findall(rf"Код для {phone}: (\d+)", text)
    return matches[-1]


def main():
    c = httpx.Client(timeout=10)

    # --- 1. Вход первого пользователя ---
    r = c.post(f"{BASE}/api/login", json={"phone": "79990000001", "password": "1234"})
    check("Логин пользователя 1", r.status_code == 200 and "token" in r.json())
    t1 = r.json()["token"]
    h1 = {"Authorization": f"Bearer {t1}"}
    uid1 = r.json()["user"]["id"]

    # --- 2. Регистрация второго пользователя ---
    r = c.post(f"{BASE}/api/register", json={"phone": "79990000002"})
    check("Запрос кода для пользователя 2", r.status_code == 200)
    code2 = last_code("79990000002")
    r = c.post(f"{BASE}/api/verify", json={
        "phone": "79990000002", "code": code2,
        "password": "5678", "display_name": "Friend",
    })
    check("Регистрация пользователя 2", r.status_code == 200 and "token" in r.json())
    t2 = r.json()["token"]
    h2 = {"Authorization": f"Bearer {t2}"}
    uid2 = r.json()["user"]["id"]

    # --- 3. Неверный код отклоняется ---
    r = c.post(f"{BASE}/api/verify", json={
        "phone": "79990000002", "code": "000000",
        "password": "5678", "display_name": "X",
    })
    check("Неверный код отклонён", r.status_code == 400)

    # --- 4. Создание личного чата ---
    r = c.post(f"{BASE}/api/chats", json={"type": "personal", "user_ids": [uid2]}, headers=h1)
    check("Создание личного чата", r.status_code == 200)
    chat = r.json()
    chat_id = chat["id"]
    check("Название личного чата = имя собеседника", chat["title"] == "Friend")

    # --- 5. Повторное создание возвращает тот же чат ---
    r2 = c.post(f"{BASE}/api/chats", json={"type": "personal", "user_ids": [uid2]}, headers=h1)
    check("Повторное создание не дублирует чат", r2.json()["id"] == chat_id)

    # --- 6. Отправка сообщений ---
    r = c.post(f"{BASE}/api/chats/{chat_id}/messages",
               json={"type": "text", "content": "Привет из MeNo!"}, headers=h1)
    check("Отправка сообщения от пользователя 1", r.status_code == 200, r.text)
    msg1 = r.json()

    r = c.post(f"{BASE}/api/chats/{chat_id}/messages",
               json={"type": "text", "content": "И тебе привет!", "ttl_seconds": 300}, headers=h2)
    check("Отправка исчезающего сообщения", r.status_code == 200 and r.json()["ttl_seconds"] == 300)

    # --- 7. История сообщений ---
    r = c.get(f"{BASE}/api/chats/{chat_id}/messages", headers=h1)
    msgs = r.json()
    check("История содержит 2 сообщения", len(msgs) == 2)
    check("Автор сообщения подставлен", msgs[0]["sender_name"] == "Owner")

    # --- 8. Доступ к чужому чату запрещён ---
    r = c.post(f"{BASE}/api/register", json={"phone": "79990000003"})
    code3 = last_code("79990000003")
    r = c.post(f"{BASE}/api/verify", json={
        "phone": "79990000003", "code": code3,
        "password": "0000", "display_name": "Intruder",
    })
    t3 = r.json()["token"]
    h3 = {"Authorization": f"Bearer {t3}"}
    r = c.get(f"{BASE}/api/chats/{chat_id}/messages", headers=h3)
    check("Чужой не видит переписку", r.status_code == 403)

    # --- 9. Групповой чат ---
    r = c.post(f"{BASE}/api/chats",
               json={"type": "group", "title": "Наша команда", "user_ids": [uid2]}, headers=h1)
    g = r.json()
    check("Создание группы", r.status_code == 200 and g["type"] == "group")
    check("В группе 2 участника", len(g["members"]) == 2)

    # --- 10. Жалоба на сообщение ---
    r = c.post(f"{BASE}/api/reports", json={})  # заглушка — маршрут появится позже
    # Проверяем статистику владельца невозможно без роли admin — пропускаем

    print(f"\nИтог: {PASSED} ✅, {FAILED} ❌")
    if FAILED:
        raise SystemExit(1)


if __name__ == "__main__":
    main()