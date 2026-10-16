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
from typing import Dict, Any

import push as push_service
from rate_limit import auth_key, limiter

router = APIRouter(prefix="/api", tags=["auth"])

PHONE_PATTERN = r"^\d{10,15}$"

# --- Схемы запросов и ответов ---

class PhoneRequest(BaseModel):
    phone: str = Field(..., pattern=PHONE_PATTERN, description="Номер телефона в международном формате (например, 79991234567)")

class VerifyRequest(BaseModel):
    phone: str = Field(..., pattern=PHONE_PATTERN)
    code: str = Field(..., min_length=6, max_length=6, description="6-значный код подтверждения")
    password: str = Field(..., min_length=4, max_length=128, description="Пароль для создания аккаунта")
    display_name: str = Field(default="", max_length=50, description="Имя пользователя")

class LoginRequest(BaseModel):
    phone: str = Field(..., pattern=PHONE_PATTERN)
    password: str = Field(..., max_length=128)
    totp: str = Field(default="", max_length=6, description="Код 2FA, если включено")

class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=32, description="Долгоживущий токен обновления")

class TotpSetupRequest(BaseModel):
    totp: str = Field(..., min_length=6, max_length=6)

class E2EKeyRequest(BaseModel):
    public_key: str = Field(..., min_length=32, max_length=512, description="Публичный ключ X25519 (base64)")

class PushTokenRequest(BaseModel):
    token: str = Field(..., min_length=20, max_length=512)
    platform: str = Field(default="android", pattern="^(android|ios|web)$")

class TokenResponse(BaseModel):
    access_token: str = Field(..., description="Краткосрочный токен доступа (Bearer)")
    refresh_token: str = Field(..., description="Долгосрочный токен для обновления сессии")

class UserResponse(BaseModel):
    id: int
    phone: str
    display_name: str
    role: str
    avatar_path: Optional[str]
    last_seen: Optional[str]
    twofa_enabled: bool
    e2e_pub: Optional[str]

class AuthResponse(BaseModel):
    tokens: TokenResponse
    user: UserResponse

def _public(user: dict) -> dict:
    return auth.user_to_public(user)

async def _issue_tokens(user_id: int, db):
    access = auth.create_access_token(user_id)
    refresh = auth.create_refresh_token(user_id)
    
    expires = datetime.utcnow() + timedelta(days=auth.REFRESH_TOKEN_EXPIRE_DAYS)
    await db.execute(
        "INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES (:t, :u, :e)",
        {"t": refresh, "u": user_id, "e": expires}
    )
    return {"access_token": access, "refresh_token": refresh}

@router.post(
    "/register", 
    response_model=Dict[str, Any],
    summary="Запрос кода регистрации",
    description="Отправляет код подтверждения на телефон пользователя. Ограничено rate-лимитом.",
    responses={429: {"description": "Too Many Requests"}, 400: {"description": "Account already exists"}}
)
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

@router.post(
    "/verify", 
    response_model=AuthResponse,
    summary="Подтверждение кода и создание аккаунта",
    description="Проверяет код из SMS и создает пользователя в системе.",
    responses={400: {"description": "Invalid code or account exists"}}
)
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

@router.post(
    "/login", 
    response_model=AuthResponse,
    summary="Вход в аккаунт",
    description="Авторизация по номеру и паролю. Если включена 2FA, требуется код TOTP.",
    responses={400: {"description": "Invalid credentials or 2FA required"}}
)
async def login(body: LoginRequest, request: Request):
    phone = body.phone.strip()
    key = auth_key("login", request, phone)
    if not limiter.allow(key, config.RL_LOGIN_LIMIT, config.RL_LOGIN_WINDOW):
        raise HTTPException(429, "Слишком много попыток входа — попробуйте позже")

    user = await auth.get_user_by_phone(phone)
    if not user:
        raise HTTPException(400, "Неверный номер или пароль")

    # Проверка блокировки
    locked, until = auth.is_account_locked(user)
    if locked:
        wait_min = int((until - datetime.utcnow()).total_seconds() / 60) + 1
        raise HTTPException(403, f"Аккаунт временно заблокирован. Попробуйте через {wait_min} мин.")

    if not auth.check_password(body.password, user["password_hash"]):
        await auth.record_failed_attempt(user["id"])
        raise HTTPException(400, "Неверный номер или пароль")

    if user["twofa_enabled"]:
        if not body.totp or not auth.verify_totp(user["totp_secret"], body.totp.strip()):
            await auth.record_failed_attempt(user["id"])
            raise HTTPException(400, "Требуется код 2FA (Google Authenticator)")
    
    await auth.touch_last_seen(user["id"])
    await auth.reset_failed_attempts(user["id"])
    limiter.reset(key)

    async with database.get_db() as db:
        tokens = await _issue_tokens(user["id"], db)

    return {"tokens": tokens, "user": _public(user)}

@router.post(
    "/refresh", 
    response_model=Dict[str, str],
    summary="Обновление Access-токена",
    description="Позволяет получить новый краткосрочный токен доступа, используя Refresh-токен.",
    responses={401: {"description": "Invalid or expired refresh token"}}
)
async def refresh_token(body: RefreshRequest):
    async with database.get_db() as db:
        token_data = await database.aq1(
            db, 
            "SELECT * FROM refresh_tokens WHERE token=:t AND expires_at > :now", 
            {"t": body.refresh_token, "now": datetime.utcnow()}
        )
        if not token_data:
            raise HTTPException(401, "Refresh token недействителен или просрочен")
        
        user_id = token_data["user_id"]
        new_access = auth.create_access_token(user_id)
        return {"access_token": new_access}

@router.post(
    "/logout", 
    summary="Выход из системы",
    description="Инвалидирует текущую сессию (удаляет Refresh-токен из БД).",
    responses={200: {"description": "Logged out successfully"}}
)
async def logout(body: RefreshRequest, user: dict = Depends(get_current_user)):
    async with database.get_db() as db:
        await db.execute("DELETE FROM refresh_tokens WHERE token=:t AND user_id=:uid", 
                         {"t": body.refresh_token, "uid": user["id"]})
    return {"ok": True}

@router.get(
    "/me", 
    response_model=UserResponse,
    summary="Данные текущего пользователя",
    description="Возвращает публичный профиль авторизованного пользователя."
)
async def me(user: dict = Depends(get_current_user)):
    return _public(user)

@router.put(
    "/me/e2e-key", 
    summary="Установка E2E-ключа",
    description="Регистрирует публичный ключ X25519 пользователя для шифрования личных чатов."
)
async def set_e2e_key(body: E2EKeyRequest, user: dict = Depends(get_current_user)):
    async with database.get_db() as db:
        await db.execute("UPDATE users SET e2e_pub=:key WHERE id=:id", {"key": body.public_key.strip(), "id": user["id"]})
    return {"ok": True}

class PushTokenRequest(BaseModel):
    token: str = Field(..., min_length=20, max_length=512)
    platform: str = Field(default="android", pattern="^(android|ios|web)$")

@router.post(
    "/me/push-token", 
    summary="Регистрация Push-токена",
    description="Привязывает токен устройства (FCM) к аккаунту для отправки уведомлений."
)
async def set_push_token(body: PushTokenRequest, user: dict = Depends(get_current_user)):
    push_service.register_token(user["id"], body.token, body.platform)
    return {"ok": True}

@router.delete(
    "/me/push-token", 
    summary="Отвязка Push-токена",
    description="Удаляет токен устройства при выходе из аккаунта."
)
async def remove_push_token(body: PushTokenRequest, user: dict = Depends(get_current_user)):
    push_service.unregister_token(user["id"], body.token)
    return {"ok": True}

@router.get(
    "/users/{user_id}/e2e-key", 
    summary="Получение E2E-ключа пользователя",
    description="Возвращает публичный ключ другого пользователя для вычисления общего секрета."
)
async def get_e2e_key(user_id: int, user: dict = Depends(get_current_user)):
    target = await auth.get_user_by_id(user_id)
    if not target:
        raise HTTPException(404, "Пользователь не найден")
    if not target.get("e2e_pub"):
        raise HTTPException(404, "Пользователь ещё не активировал E2E")
    return {"user_id": user_id, "public_key": target["e2e_pub"]}

@router.post(
    "/me/totp/setup", 
    summary="Настройка 2FA",
    description="Генерирует секрет TOTP и URI для QR-кода (доступно только админу).",
    responses={403: {"description": "Forbidden - Admin only"}}
)
async def totp_setup(user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "2FA доступна владельцу")
    secret = auth.generate_totp_secret()
    async with database.get_db() as db:
        await db.execute("UPDATE users SET totp_secret=:secret WHERE id=:id", {"secret": secret, "id": user["id"]})
    return {"secret": secret, "uri": auth.totp_provisioning_uri(secret, user["phone"])}

@router.post(
    "/me/totp/enable", 
    summary="Активация 2FA",
    description="Активирует 2FA после проверки первого корректного кода из приложения.",
    responses={400: {"description": "Invalid code"}}
)
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

@router.post(
    "/me/totp/disable", 
    summary="Отключение 2FA",
    description="Отключает 2FA после проверки текущего кода.",
    responses={400: {"description": "Invalid code"}}
)
async def totp_disable(body: TotpSetupRequest, user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "2FA доступна владельцу")
    if not user.get("totp_secret") or not auth.verify_totp(user["totp_secret"], body.totp.strip()):
        raise HTTPException(400, "Неверный код 2FA")
    async with database.get_db() as db:
        await db.execute("UPDATE users SET twofa_enabled=0 WHERE id=:id", {"id": user["id"]})
    return {"ok": True, "message": "2FA выключена"}
