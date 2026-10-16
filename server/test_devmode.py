"""MeNo — тест DevMode (панель владельца).

Запуск: python test_devmode.py (сервер запущен с MENO_ADMIN_PHONE=79990000004)
"""
import pathlib
import re

import httpx

BASE = "http://127.0.0.1:8000"
LOG = pathlib.Path(__file__).parent / "server.log"

OWNER_PHONE = "79990000004"
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
    return re.findall(rf"Код для {phone}: (\d+)", text)[-1]


def main():
    c = httpx.Client(timeout=10)

    # --- Регистрация владельца ---
    c.post(f"{BASE}/api/register", json={"phone": OWNER_PHONE})
    code = last_code(OWNER_PHONE)
    r = c.post(f"{BASE}/api/verify", json={
        "phone": OWNER_PHONE, "code": code,
        "password": "9999", "display_name": "Boss",
    })
    data = r.json()
    check("Владелец зарегистрирован", r.status_code == 200)
    check("Роль автоматически = admin", data["user"]["role"] == "admin", str(data))
    t = data["token"]
    h = {"Authorization": f"Bearer {t}"}

    # --- Статистика ---
    r = c.get(f"{BASE}/api/admin/stats", headers=h)
    check("Статистика системы", r.status_code == 200)
    stats = r.json()
    check("Счётчик пользователей > 0", stats.get("users", 0) > 0, str(stats))

    # --- Глобальные настройки ---
    r = c.put(f"{BASE}/api/admin/settings",
              json={"key": "welcome_message", "value": "Добро пожаловать в MeNo"}, headers=h)
    check("Сохранение настройки", r.status_code == 200)
    r = c.get(f"{BASE}/api/admin/settings", headers=h)
    check("Чтение настроек", r.json().get("welcome_message") == "Добро пожаловать в MeNo", r.text)

    # --- Обычный пользователь не имеет доступа к DevMode ---
    r = c.post(f"{BASE}/api/login", json={"phone": "79990000001", "password": "1234"})
    t1 = r.json()["token"]
    h1 = {"Authorization": f"Bearer {t1}"}
    r = c.get(f"{BASE}/api/admin/stats", headers=h1)
    check("Обычный пользователь заблокирован (403)", r.status_code == 403)

    # --- Настройка 2FA (TOTP) ---
    r = c.post(f"{BASE}/api/me/totp/setup", headers=h)
    check("Генерация секрета 2FA", r.status_code == 200 and "uri" in r.json())
    secret = r.json()["secret"]

    import pyotp
    totp_code = pyotp.TOTP(secret).now()
    r = c.post(f"{BASE}/api/me/totp/enable", json={"totp": totp_code}, headers=h)
    check("Включение 2FA по коду", r.status_code == 200, r.text)

    # --- Вход с 2FA: без кода — отказ, с кодом — успех ---
    r = c.post(f"{BASE}/api/login", json={"phone": OWNER_PHONE, "password": "9999"})
    check("Вход без 2FA отклонён", r.status_code == 400)
    r = c.post(f"{BASE}/api/login", json={
        "phone": OWNER_PHONE, "password": "9999",
        "totp": pyotp.TOTP(secret).now(),
    })
    check("Вход с 2FA успешен", r.status_code == 200 and "token" in r.json())

    print(f"\nИтог DevMode: {PASSED} ✅, {FAILED} ❌")
    if FAILED:
        raise SystemExit(1)


if __name__ == "__main__":
    main()