"""MeNo — маршруты аутентификации: код на телефон, регистрация, вход, 2FA.

Безопасность:
- все входные данные строго валидируются Pydantic;
- эндпоинты защищены от брутфорса rate limiting;
- используется стратегия Access/Refresh токенов для безопасности сессий.
"""
import config
import sms
import database
import auth
from deps import get_current_user
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from datetime import datetime, timedelta

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

class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=32)

class TotpSetupRequest(BaseModel):
    totp: str = Field(..., min_length=6, max_length=6)

class E2EKeyRequest(BaseModel):
    public_key: str = Field(..., min_length=32, max_length=512)

class PushTokenRequest(BaseModel):
    token: str = Field(..., min_length=20, max_length=512)
    platform: str = Field(default="android", pattern="^(android|ios|web)$")

def _public(user: dict) -> dict:
    return auth.user_to_public(user)

async def _issue_tokens(user_id: int, db):
    """Вспомогательная функция для выдачи пары токенов."""
    access = auth.create_access_token(user_id)
    refresh = auth.create_refresh_token(user_id)
    
    expires = datetime.utcnow() + timedelta(days=auth.REFRESH_TOKEN_EXPIRE_DAYS)
    await db.execute(
        "INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES (:t, :u, :e)",
        {"t": refresh, "u": user_id, "e": expires}
    )
    return {"access_token": access, "refresh_token": refresh}

@router.post("/register")
async def request_register(body: PhoneRequest, request: Request):
    phone = body.phone.strip()
    if not limiter.allow(auth_key("register", request, phone), config.RL_REGISTER_LIMIT, config.RL_REGISTER_WINDOW):
        raise HTTPException(429, "Слишком много запросов кода — попробуйте позже")
    if await auth.get_user_by_phone(phone):
        raise HTTPException(400, "Аккаунт с таким номером уже существует — войдите")
    ok, msg = await sms.request_code(phone, purpose="register")
    if not ok:
        raise HTTPException(429, msg)
    return {"ok": True, "message": msg}

@router.post("/verify")
async def verify_and_create(body: VerifyRequest, request: Request):
    phone = body.phone.strip()
    if not limiter.allow(auth_key("verify", request, phone), config.RL_VERIFY_LIMIT, config.RL_VERIFY_WINDOW):
        raise HTTPException(429, "Слишком много попыток — попробуйте позже")
    if await auth.get_user_by_phone(phone):
        raise HTTPException(400, "Аккаунт с таким номером уже существует")
    if not await sms.verify_code(phone, body.code.strip(), purpose="register"):
        raise HTTPException(400, "Неверный или просроченный код")

    role = "admin" if phone == config.ADMIN_PHONE else "user"
    async with database.get_db() as db:
        await db.execute(
            "INSERT INTO users (phone, password_hash, display_name, role) VALUES (:phone, :pw, :dn, :role)",
            {"phone": phone, "pw": auth.hash_password(body.password), "dn": body.display_name.strip(), "role": role},
        )
        user = await database.aq1(db, "SELECT * FROM users WHERE phone=:phone", {"phone": phone})
        tokens = await _issue_tokens(user["id"], db)

    return {"tokens": tokens, "user": _public(user)}

@router.post("/login")
async def login(body: LoginRequest, request: Request):
    phone = body.phone.strip()
    key = auth_key("login", request, phone)
    if not limiter.allow(key, config.RL_LOGIN_LIMIT, config.RL_LOGIN_WINDOW):
        raise HTTPException(429, "Слишком много попыток входа — попробуйте позже")

    user = await auth.get_user_by_phone(phone)
    if not user or not auth.check_password(body.password, user["password_hash"]):
        raise HTTPException(400, "Неверный номер или пароль")
    if user["twofa_enabled"]:
        if not body.totp or not auth.verify_totp(user["totp_secret"], body.totp.strip()):
            raise HTTPException(400, "Требуется код 2FA (Google Authenticator)")
    await auth.touch_last_seen(user["id"])
    limiter.reset(key)
    
    async with database.get_db() as db:
        tokens = await _issue_tokens(user["id"], db)
        
    return {"tokens": tokens, "user": _public(user)}

@router.post("/refresh")
async def refresh_token(body: RefreshRequest):
    """Обновление Access токена с помощью Refresh токена."""
    async with database.get_db() as db:
        token_data = await database.aq1(
            db, 
            "SELECT * FROM refresh_tokens WHERE token=:t AND expires_at > :now", 
            {"t": body.refresh_token, "now": datetime.utcnow()}
        )
        if not token_data:
            raise HTTPException(401, "Refresh token недействителен или просрочен")
        
        user_id = token_data["user_id"]
        # Выдаем новый access токен
        new_access = auth.create_access_token(user_id)
        return {"access_token": new_access}

@router.post("/logout")
async def logout(body: RefreshRequest, user: dict = Depends(get_current_user)):
    """Инвалидация сессии (удаление Refresh токена)."""
    async with database.get_db() as db:
        await db.execute("DELETE FROM refresh_tokens WHERE token=:t AND user_id=:uid", 
                         {"t": body.refresh_token, "uid": user["id"]})
    return {"ok": True}

@router.get("/me")
async def me(user: dict = Depends(get_current_user)):
    return _public(user)

@router.put("/me/e2e-key")
async def set_e2e_key(body: E2EKeyRequest, user: dict = Depends(get_current_user)):
    async with database.get_db() as db:
        await db.execute("UPDATE users SET e2e_pub=:key WHERE id=:id", {"key": body.public_key.strip(), "id": user["id"]})
    return {"ok": True}

@router.post("/me/push-token")
async def set_push_token(body: PushTokenRequest, user: dict = Depends(get_current_user)):
    push_service.register_token(user["id"], body.token, body.platform)
    return {"ok": True}

@router.delete("/me/push-token")
async def remove_push_token(body: PushTokenRequest, user: dict = Depends(get_current_user)):
    push_service.unregister_token(user["id"], body.token)
    return {"ok": True}

@router.get("/users/{user_id}/e2e-key")
async def get_e2e_key(user_id: int, user: dict = Depends(get_current_user)):
    target = await auth.get_user_by_id(user_id)
    if not target:
        raise HTTPException(404, "Пользователь не найден")
    if not target.get("e2e_pub"):
        raise HTTPException(404, "Пользователь ещё не активировал E2E")
    return {"user_id": user_id, "public_key": target["e2e_pub"]}

@router.post("/me/totp/setup")
async def totp_setup(user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "2FA доступна владельцу")
    secret = auth.generate_totp_secret()
    async with database.get_db() as db:
        await db.execute("UPDATE users SET totp_secret=:secret WHERE id=:id", {"secret": secret, "id": user["id"]})
    return {"secret": secret, "uri": auth.totp_provisioning_uri(secret, user["phone"])}

@router.post("/me/totp/enable")
async def totp_enable(body: TotpSetupRequest, user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "2FA доступна владельцу")
    if not user.get("totp_secret"):
        raise HTTPException(400, "Сначала вызовите /me/totp/setup")
    if not auth.verify_totp(user["totp_secret"], body.totp.strip()):
        raise HTTPException(400, "Неверный код 2FA")
    async with database.get_db() as db:
        await db.execute("UPDATE users SET twofa_enabled=1 WHERE id=:id", {"id": user["id"]})
    return {"ok": True, "message": "2FA включена"}

@router.post("/me/totp/disable")
async def totp_disable(body: TotpSetupRequest, user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "2FA доступна владельцу")
    if not user.get("totp_secret") or not auth.verify_totp(user["totp_secret"], body.totp.strip()):
        raise HTTPException(400, "Неверный код 2FA")
    async with database.get_db() as db:
        await db.execute("UPDATE users SET twofa_enabled=0 WHERE id=:id", {"id": user["id"]})
    return {"ok": True, "message": "2FA выключена"}
