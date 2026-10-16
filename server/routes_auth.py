"""MeNo — маршруты аутентификации: код на телефон, регистрация, вход, 2FA.

Безопасность:
- все входные данные строго валидируются Pydantic (паттерн номера,
  длины полей, допустимые значения);
- эндпоинты защищены от брутфорса rate limiting по связке IP+телефон
  (см. rate_limit.py) — перебор конкретного номера ограничен,
  но устройства за общим NAT не блокируются.
"""
import config
import sms
import database
import auth
from deps import get_current_user
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

import push as push_service
from rate_limit import auth_key, limiter

router = APIRouter(prefix="/api", tags=["auth"])

PHONE_PATTERN = r"^\d{10,15}$"


class PhoneRequest(BaseModel):
    phone: str = Field(..., pattern=PHONE_PATTERN, description="Номер в формате 79991234567")


class VerifyRequest(BaseModel):
    phone: str = Field(..., pattern=PHONE_PATTERN)
    code: str = Field(..., min_length=6, max_length=6)
    password: str = Field(..., min_length=4, max_length=128)
    display_name: str = Field(default="", max_length=50)


class LoginRequest(BaseModel):
    phone: str = Field(..., pattern=PHONE_PATTERN)
    password: str = Field(..., max_length=128)
    totp: str = Field(default="", max_length=6)


class TotpSetupRequest(BaseModel):
    totp: str = Field(..., min_length=6, max_length=6)


class E2EKeyRequest(BaseModel):
    """Публичный ключ X25519 клиента (base64)."""

    public_key: str = Field(..., min_length=32, max_length=512)


def _public(user: dict) -> dict:
    return auth.user_to_public(user)


@router.post("/register")
def request_register(body: PhoneRequest, request: Request):
    """Шаг 1: запрос кода подтверждения на номер телефона."""
    phone = body.phone.strip()
    if not limiter.allow(
        auth_key("register", request, phone),
        config.RL_REGISTER_LIMIT,
        config.RL_REGISTER_WINDOW,
    ):
        raise HTTPException(429, "Слишком много запросов кода — попробуйте позже")
    if auth.get_user_by_phone(phone):
        raise HTTPException(400, "Аккаунт с таким номером уже существует — войдите")
    ok, msg = sms.request_code(phone, purpose="register")
    if not ok:
        raise HTTPException(429, msg)
    return {"ok": True, "message": msg}


@router.post("/verify")
def verify_and_create(body: VerifyRequest, request: Request):
    """Шаг 2: подтверждение кода и создание аккаунта."""
    phone = body.phone.strip()
    if not limiter.allow(
        auth_key("verify", request, phone),
        config.RL_VERIFY_LIMIT,
        config.RL_VERIFY_WINDOW,
    ):
        raise HTTPException(429, "Слишком много попыток — попробуйте позже")
    if auth.get_user_by_phone(phone):
        raise HTTPException(400, "Аккаунт с таким номером уже существует")
    if not sms.verify_code(phone, body.code.strip(), purpose="register"):
        raise HTTPException(400, "Неверный или просроченный код")

    role = "admin" if phone == config.ADMIN_PHONE else "user"
    with database.get_db() as db:
        cur = db.execute(
            "INSERT INTO users (phone, password_hash, display_name, role) VALUES (?,?,?,?)",
            (phone, auth.hash_password(body.password), body.display_name.strip(), role),
        )
        user_id = cur.lastrowid
        user = database.q1(db, "SELECT * FROM users WHERE id=?", (user_id,))

    return {"token": auth.create_token(user_id), "user": _public(user)}


@router.post("/login")
def login(body: LoginRequest, request: Request):
    """Вход: телефон + пароль (+ TOTP, если включена 2FA).

    Rate limit считается по связке IP+телефон и сбрасывается
    после успешного входа.
    """
    phone = body.phone.strip()
    key = auth_key("login", request, phone)
    if not limiter.allow(key, config.RL_LOGIN_LIMIT, config.RL_LOGIN_WINDOW):
        raise HTTPException(429, "Слишком много попыток входа — попробуйте позже")

    user = auth.get_user_by_phone(phone)
    if not user or not auth.check_password(body.password, user["password_hash"]):
        raise HTTPException(400, "Неверный номер или пароль")
    if user["twofa_enabled"]:
        if not body.totp or not auth.verify_totp(user["totp_secret"], body.totp.strip()):
            raise HTTPException(400, "Требуется код 2FA (Google Authenticator)")
    auth.touch_last_seen(user["id"])
    limiter.reset(key)
    return {"token": auth.create_token(user["id"]), "user": _public(user)}


@router.get("/me")
def me(user: dict = Depends(get_current_user)):
    return _public(user)


# ---------- E2E: публичные ключи шифрования (X25519) ----------
@router.put("/me/e2e-key")
def set_e2e_key(body: E2EKeyRequest, user: dict = Depends(get_current_user)):
    """Сохраняет публичный ключ X25519 пользователя для E2E личных чатов."""
    with database.get_db() as db:
        db.execute("UPDATE users SET e2e_pub=? WHERE id=?", (body.public_key.strip(), user["id"]))
    return {"ok": True}


class PushTokenRequest(BaseModel):
    token: str = Field(..., min_length=20, max_length=512)
    platform: str = Field(default="android", pattern="^(android|ios|web)$")


@router.post("/me/push-token")
def set_push_token(body: PushTokenRequest, user: dict = Depends(get_current_user)):
    """Регистрирует push-токен устройства для фоновых уведомлений (FCM)."""
    push_service.register_token(user["id"], body.token, body.platform)
    return {"ok": True}


@router.delete("/me/push-token")
def remove_push_token(body: PushTokenRequest, user: dict = Depends(get_current_user)):
    """Отменяет регистрацию push-токена (при выходе из аккаунта)."""
    push_service.unregister_token(user["id"], body.token)
    return {"ok": True}


@router.get("/users/{user_id}/e2e-key")
def get_e2e_key(user_id: int, user: dict = Depends(get_current_user)):
    """Возвращает публичный ключ пользователя для вычисления общего секрета чата."""
    target = auth.get_user_by_id(user_id)
    if not target:
        raise HTTPException(404, "Пользователь не найден")
    if not target.get("e2e_pub"):
        raise HTTPException(404, "Пользователь ещё не активировал E2E")
    return {"user_id": user_id, "public_key": target["e2e_pub"]}


# ---------- 2FA (для роли admin) ----------
@router.post("/me/totp/setup")
def totp_setup(user: dict = Depends(get_current_user)):
    """Генерирует секрет 2FA и возвращает ссылку для приложения-аутентификатора."""
    if user["role"] != "admin":
        raise HTTPException(403, "2FA доступна владельцу")
    secret = auth.generate_totp_secret()
    with database.get_db() as db:
        db.execute("UPDATE users SET totp_secret=? WHERE id=?", (secret, user["id"]))
    return {"secret": secret, "uri": auth.totp_provisioning_uri(secret, user["phone"])}


@router.post("/me/totp/enable")
def totp_enable(body: TotpSetupRequest, user: dict = Depends(get_current_user)):
    """Активирует 2FA после проверки первого кода."""
    if user["role"] != "admin":
        raise HTTPException(403, "2FA доступна владельцу")
    if not user.get("totp_secret"):
        raise HTTPException(400, "Сначала вызовите /me/totp/setup")
    if not auth.verify_totp(user["totp_secret"], body.totp.strip()):
        raise HTTPException(400, "Неверный код 2FA")
    with database.get_db() as db:
        db.execute("UPDATE users SET twofa_enabled=1 WHERE id=?", (user["id"],))
    return {"ok": True, "message": "2FA включена"}


@router.post("/me/totp/disable")
def totp_disable(body: TotpSetupRequest, user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "2FA доступна владельцу")
    if not user.get("totp_secret") or not auth.verify_totp(user["totp_secret"], body.totp.strip()):
        raise HTTPException(400, "Неверный код 2FA")
    with database.get_db() as db:
        db.execute("UPDATE users SET twofa_enabled=0 WHERE id=?", (user["id"],))
    return {"ok": True, "message": "2FA выключена"}