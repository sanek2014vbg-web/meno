"""MeNo — маршруты аутентификации: регистрация по username, вход, 2FA.

Регистрация БЕЗ номера телефона: достаточно уникального username и пароля.
SMS / коды подтверждения не используются — никаких платных сервисов.

Безопасность:
- все входные данные строго валидируются Pydantic;
- эндпоинты защищены от брутфорса rate limiting (Redis или in-process);
- регистрация атомарна: UNIQUE(username) + обработка IntegrityError (Этап 2.2);
- refresh-токены ротируются с детекцией переиспользования (Этап 2.4);
- всё время — tz-aware UTC (server.utils.utc_now, Этап 2.5);
- значимые события пишутся в audit-лог security_events (Этап 2.3).
"""
import re
import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text as sql_text
from sqlalchemy.exc import IntegrityError

from server import auth, config, database, sessions
from server.deps import get_current_user
from server.rate_limit import auth_key, limiter
from server.utils import utc_now

from server import push as push_service

router = APIRouter(prefix="/api", tags=["auth"])

USERNAME_PATTERN = r"^[a-zA-Z0-9_.]{3,32}$"
_USERNAME_RE = re.compile(USERNAME_PATTERN)


# --- Схемы запросов и ответов ---


class RegisterRequest(BaseModel):
    username: str = Field(..., pattern=USERNAME_PATTERN,
                          description="Уникальное имя пользователя (латиница, цифры, _ .), 3–32 символа")
    password: str = Field(..., min_length=6, max_length=128, description="Пароль")
    display_name: str = Field(default="", max_length=50, description="Отображаемое имя")


class LoginRequest(BaseModel):
    username: str = Field(..., pattern=USERNAME_PATTERN)
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
    username: str
    display_name: str
    role: str
    avatar_path: str | None = None
    last_seen: str | None = None
    twofa_enabled: bool
    e2e_pub: str | None = None


class AuthResponse(BaseModel):
    tokens: TokenResponse
    user: UserResponse


def _public(user: dict) -> dict:
    return auth.user_to_public(user)


async def _issue_tokens(db, user_id: int) -> dict:
    """Пара токенов: короткоживущий JWT access + ротационный refresh (новая семья)."""
    access = auth.create_access_token(user_id)
    refresh = await sessions.issue_refresh_token(db, user_id)
    return {"access_token": access, "refresh_token": refresh}


@router.post(
    "/register",
    response_model=AuthResponse,
    summary="Регистрация по username (без телефона)",
    responses={429: {"description": "Too Many Requests"}, 400: {"description": "Username already taken"}},
)
async def register(body: RegisterRequest, request: Request):
    username = body.username.strip().lower()
    key = auth_key("register", request, username)
    if not await limiter.allow_async(key, config.RL_REGISTER_LIMIT, config.RL_REGISTER_WINDOW):
        raise HTTPException(429, "Слишком много запросов — попробуйте позже")
    if not _USERNAME_RE.match(username):
        raise HTTPException(400, "Некорректное имя пользователя")

    role = "admin" if username == config.ADMIN_USERNAME.lower() else "user"
    # bcrypt выполняется ДО открытия транзакции: хеширование занимает
    # сотни миллисекунд, и удержание write-локации SQLite на это время
    # вызывало "database is locked" при конкурентной регистрации.
    pw_hash = await asyncio.to_thread(auth.hash_password, body.password)

    # Атомарная регистрация (Этап 2.2): единственный INSERT опирается на
    # UNIQUE(username); гонка двойной регистрации ловится через IntegrityError.
    # Транзакция открывается ПОСЛЕ хеширования и закрывается ДО записи
    # audit-лога и выдачи токенов: при конкурентной регистрации это сводит
    # время удержания write-локации SQLite к минимуму (дефект 'database is
    # locked' под параллельными запросами).
    async with database.get_db() as db:
        try:
            await db.execute(
                sql_text(
                    "INSERT INTO users (username, password_hash, display_name, role) "
                    "VALUES (:username, :pw, :dn, :role)"
                ),
                {
                    "username": username,
                    "pw": pw_hash,
                    "dn": body.display_name.strip() or username,
                    "role": role,
                },
            )
        except IntegrityError:
            conflict = True
        else:
            user = await database.aq1(db, "SELECT * FROM users WHERE username=:username", {"username": username})
            conflict = False

    if conflict:
        await auth.log_security_event(
            "register_conflict", username=username, ip=request.client.host if request.client else None,
            detail="Попытка регистрации занятого username (гонка)",
        )
        raise HTTPException(400, "Такое имя уже занято — войдите")

    # Выдача токенов — отдельная короткая транзакция (refresh_tokens INSERT).
    async with database.get_db() as db:
        tokens = await _issue_tokens(db, user["id"])

    await auth.log_security_event("register", user_id=user["id"], username=username,
                                  ip=request.client.host if request.client else None,
                                  detail=f"role={role}")
    return {"tokens": tokens, "user": _public(user)}


@router.post(
    "/login",
    response_model=AuthResponse,
    summary="Вход в аккаунт",
    responses={400: {"description": "Invalid credentials or 2FA required"},
               403: {"description": "Account locked"}},
)
async def login(body: LoginRequest, request: Request):
    username = body.username.strip().lower()
    key = auth_key("login", request, username)
    if not await limiter.allow_async(key, config.RL_LOGIN_LIMIT, config.RL_LOGIN_WINDOW):
        raise HTTPException(429, "Слишком много попыток входа — попробуйте позже")

    user = await auth.get_user_by_username(username)
    if not user:
        # Защита от user enumeration: выполняем проверку пароля против
        # фиктивного хеша, чтобы ответ для несуществующего пользователя
        # занимал столько же времени, сколько для существующего.
        await asyncio.to_thread(
            auth.check_password, body.password, auth._DUMMY_PASSWORD_HASH
        )
        await auth.log_security_event("login_failed", username=username,
                                      ip=request.client.host if request.client else None,
                                      detail="unknown user")
        raise HTTPException(400, "Неверное имя или пароль")

    locked, until = auth.is_account_locked(user)
    if locked:
        wait_min = int((until - utc_now()).total_seconds() / 60) + 1
        raise HTTPException(403, f"Аккаунт временно заблокирован. Попробуйте через {wait_min} мин.")

    # bcrypt — CPU-интенсивная операция (~300мс); выносим в поток,
    # чтобы не блокировать event loop под нагрузкой.
    password_matches = await asyncio.to_thread(
        auth.check_password, body.password, user["password_hash"]
    )
    if not password_matches:
        await auth.record_failed_attempt(user["id"])
        await auth.log_security_event("login_failed", user_id=user["id"], username=username,
                                      ip=request.client.host if request.client else None,
                                      detail="wrong password")
        raise HTTPException(400, "Неверное имя или пароль")

    if user["twofa_enabled"]:
        if not body.totp or not auth.verify_totp(user["totp_secret"], body.totp.strip()):
            await auth.record_failed_attempt(user["id"])
            await auth.log_security_event("2fa_failed", user_id=user["id"], username=username,
                                          ip=request.client.host if request.client else None)
            raise HTTPException(400, "Требуется код 2FA (Google Authenticator)")

    await auth.touch_last_seen(user["id"])
    await auth.reset_failed_attempts(user["id"])
    await limiter.reset_async(key)
    await auth.log_security_event("login_success", user_id=user["id"], username=username,
                                  ip=request.client.host if request.client else None)

    async with database.get_db() as db:
        tokens = await _issue_tokens(db, user["id"])

    return {"tokens": tokens, "user": _public(user)}


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Ротация токенов доступа",
    description=(
        "Обменивает refresh-токен на новую пару access/refresh (ротация). "
        "Переиспользование старого токена отзывает всю сессию (защита от кражи)."
    ),
    responses={401: {"description": "Invalid, expired or reused refresh token"}},
)
async def refresh_token(body: RefreshRequest, request: Request):
    result = await sessions.rotate_refresh_token(
        body.refresh_token, ip=request.client.host if request.client else None
    )
    if result is None:
        raise HTTPException(401, "Refresh token недействителен, просрочен или уже использован")
    return result


@router.post(
    "/logout",
    summary="Выход из системы",
    description="Инвалидирует текущую сессию (удаляет Refresh-токен из БД).",
)
async def logout(body: RefreshRequest, request: Request, user: dict = Depends(get_current_user)):
    async with database.get_db() as db:
        await sessions.revoke_token(db, body.refresh_token, user["id"])
    await auth.log_security_event("logout", user_id=user["id"], username=user.get("username"),
                                  ip=request.client.host if request.client else None)
    return {"ok": True}


@router.post(
    "/logout-all",
    summary="Выход на всех устройствах",
    description="Отзывает все refresh-токены пользователя.",
)
async def logout_all(request: Request, user: dict = Depends(get_current_user)):
    async with database.get_db() as db:
        n = await sessions.revoke_all_user_tokens(db, user["id"])
    await auth.log_security_event("logout_all", user_id=user["id"], username=user.get("username"),
                                  ip=request.client.host if request.client else None,
                                  detail=f"revoked={n}")
    return {"ok": True, "revoked": n}


@router.get("/me", response_model=UserResponse, summary="Данные текущего пользователя")
async def me(user: dict = Depends(get_current_user)):
    return _public(user)


@router.put("/me/e2e-key", summary="Установка E2E-ключа",
            description="Регистрирует публичный ключ X25519 пользователя для личных чатов.")
async def set_e2e_key(body: E2EKeyRequest, user: dict = Depends(get_current_user)):
    async with database.get_db() as db:
        await db.execute(sql_text("UPDATE users SET e2e_pub=:key WHERE id=:id"),
                         {"key": body.public_key.strip(), "id": user["id"]})
    await auth._invalidate_user_cache(user["id"])
    return {"ok": True}


@router.post("/me/push-token", summary="Регистрация Push-токена",
             description="Привязывает токен устройства (FCM) к аккаунту. Опционально: без FCM ключей пропускается.")
async def set_push_token(body: PushTokenRequest, user: dict = Depends(get_current_user)):
    await push_service.register_token(user["id"], body.token, body.platform)
    return {"ok": True}


@router.delete("/me/push-token", summary="Отвязка Push-токена")
async def remove_push_token(body: PushTokenRequest, user: dict = Depends(get_current_user)):
    await push_service.unregister_token(user["id"], body.token)
    return {"ok": True}


@router.get("/users/{user_id}/e2e-key", summary="Получение E2E-ключа пользователя")
async def get_e2e_key(user_id: int, user: dict = Depends(get_current_user)):
    target = await auth.get_user_by_id(user_id)
    if not target:
        raise HTTPException(404, "Пользователь не найден")
    if not target.get("e2e_pub"):
        raise HTTPException(404, "Пользователь ещё не активировал E2E")
    return {"user_id": user_id, "public_key": target["e2e_pub"]}


@router.post("/me/totp/setup", summary="Настройка 2FA",
             description="Генерирует секрет TOTP и URI для QR-кода.",
             responses={403: {"description": "Forbidden - Admin only"}})
async def totp_setup(user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "2FA доступна владельцу")
    secret = auth.generate_totp_secret()
    async with database.get_db() as db:
        await db.execute(sql_text("UPDATE users SET totp_secret=:secret WHERE id=:id"),
                         {"secret": secret, "id": user["id"]})
    await auth._invalidate_user_cache(user["id"])
    return {"secret": secret, "uri": auth.totp_provisioning_uri(secret, user["username"])}


@router.post("/me/totp/enable", summary="Активация 2FA")
async def totp_enable(body: TotpSetupRequest, user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "2FA доступна владельцу")
    if not user.get("totp_secret"):
        raise HTTPException(400, "Сначала вызовите /me/totp/setup")
    if not auth.verify_totp(user["totp_secret"], body.totp.strip()):
        raise HTTPException(400, "Неверный код 2FA")
    async with database.get_db() as db:
        await db.execute(sql_text("UPDATE users SET twofa_enabled=1 WHERE id=:id"), {"id": user["id"]})
    await auth._invalidate_user_cache(user["id"])
    await auth.log_security_event("2fa_enabled", user_id=user["id"], username=user.get("username"))
    return {"ok": True, "message": "2FA включена"}


@router.post("/me/totp/disable", summary="Отключение 2FA")
async def totp_disable(body: TotpSetupRequest, user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "2FA доступна владельцу")
    if not user.get("totp_secret") or not auth.verify_totp(user["totp_secret"], body.totp.strip()):
        raise HTTPException(400, "Неверный код 2FA")
    async with database.get_db() as db:
        await db.execute(sql_text("UPDATE users SET twofa_enabled=0 WHERE id=:id"), {"id": user["id"]})
    await auth._invalidate_user_cache(user["id"])
    await auth.log_security_event("2fa_disabled", user_id=user["id"], username=user.get("username"))
    return {"ok": True, "message": "2FA выключена"}
