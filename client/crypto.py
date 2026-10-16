"""MeNo — локальная защита данных клиента.

Что хранится и как:
- ПИН-защита чатов: хэш ПИН хранится только на устройстве;
- E2E-шифрование личных чатов (X25519 + HKDF + AES-GCM);
- настройки (тема, адрес сервера, приватность) — meno_data.json;
- ТОКЕНЫ авторизации — в изолированном зашифрованном хранилище
  meno_vault.bin (AES-GCM с устройственным ключом .meno_key),
  отдельно от настроек, с правами 0600 там, где это возможно.

Каталог данных:
- на десктопе/разработке — рядом с кодом (обратная совместимость);
- на Android — переменная окружения MENO_DATA_DIR / FLET_APP_STORAGE_DATA
  либо домашний каталог приложения (Path.home()/.meno).
"""
import base64
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _is_android() -> bool:
    """Определяет Android-сборку (Chaquopy выставляет getandroidapilevel)."""
    return hasattr(sys, "getandroidapilevel")


def _data_dir() -> Path:
    """Каталог данных приложения (зависит от платформы)."""
    for var in ("MENO_DATA_DIR", "FLET_APP_STORAGE_DATA"):
        v = os.environ.get(var)
        if v:
            p = Path(v)
            try:
                p.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
            return p
    if _is_android():
        # На мобильной платформе каталог рядом с кодом может быть
        # недоступен для записи — используем домашний каталог приложения.
        try:
            d = Path.home() / ".meno"
            d.mkdir(parents=True, exist_ok=True)
            return d
        except Exception:
            pass
    return Path(__file__).parent


DATA_DIR = _data_dir()
DATA_FILE = DATA_DIR / "meno_data.json"

# --- Изолированное хранилище токенов ---
VAULT_FILE = DATA_DIR / "meno_vault.bin"
KEY_FILE = DATA_DIR / ".meno_key"


def _device_key() -> bytes:
    """Устройственный ключ для шифрования хранилища токенов (32 байта)."""
    if KEY_FILE.exists():
        try:
            raw = KEY_FILE.read_bytes()
            if len(raw) == 32:
                return raw
        except Exception:
            pass
    key = secrets.token_bytes(32)
    try:
        KEY_FILE.write_bytes(key)
        os.chmod(KEY_FILE, 0o600)
    except Exception:
        pass
    return key


def _vault_load() -> dict:
    """Читает и расшифровывает хранилище токенов (при повреждении — пусто)."""
    if not VAULT_FILE.exists():
        return {}
    try:
        raw = VAULT_FILE.read_bytes()
        if len(raw) <= 12:
            return {}
        nonce, ct = raw[:12], raw[12:]
        plain = AESGCM(_device_key()).decrypt(nonce, ct, None)
        return json.loads(plain.decode("utf-8"))
    except Exception:
        return {}


def _vault_save(data: dict) -> None:
    """Шифрует и записывает хранилище токенов."""
    plain = json.dumps(data, ensure_ascii=False).encode("utf-8")
    nonce = secrets.token_bytes(12)
    ct = AESGCM(_device_key()).encrypt(nonce, plain, None)
    VAULT_FILE.write_bytes(nonce + ct)
    try:
        os.chmod(VAULT_FILE, 0o600)
    except Exception:
        pass


def vault_save_token(phone: str, token: str) -> None:
    """Сохраняет токен авторизации в изолированном хранилище."""
    data = _vault_load()
    data.setdefault("tokens", {})[phone] = token
    _vault_save(data)


def vault_load_token(phone: str) -> Optional[str]:
    """Возвращает сохранённый токен по номеру телефона (или None)."""
    return _vault_load().get("tokens", {}).get(phone)


def vault_remove_token(phone: str) -> None:
    data = _vault_load()
    data.get("tokens", {}).pop(phone, None)
    _vault_save(data)


def vault_clear() -> None:
    _vault_save({})


# ---------- Локальное хранилище ----------
def _load() -> dict:
    if DATA_FILE.exists():
        try:
            return json.loads(DATA_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save(data: dict) -> None:
    DATA_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# ---------- ПИН-защита чатов ----------
def set_chat_pin(chat_id: int, pin: str) -> None:
    data = _load()
    locks = data.setdefault("chat_locks", {})
    locks[str(chat_id)] = hashlib.sha256(pin.encode()).hexdigest()
    _save(data)


def check_chat_pin(chat_id: int, pin: str) -> bool:
    data = _load()
    stored = data.get("chat_locks", {}).get(str(chat_id))
    return bool(stored) and secrets.compare_digest(stored, hashlib.sha256(pin.encode()).hexdigest())


def has_chat_pin(chat_id: int) -> bool:
    return str(chat_id) in _load().get("chat_locks", {})


def remove_chat_pin(chat_id: int) -> None:
    data = _load()
    data.get("chat_locks", {}).pop(str(chat_id), None)
    _save(data)


def save_setting(key: str, value) -> None:
    data = _load()
    data.setdefault("settings", {})[key] = value
    _save(data)


def get_setting(key: str, default=None):
    return _load().get("settings", {}).get(key, default)


# ---------- E2E: ключи и шифрование (Этап 3) ----------
def generate_keys() -> tuple[str, str]:
    """Возвращает (приватный ключ b64, публичный ключ b64)."""
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    return (
        base64.b64encode(priv.private_bytes_raw()).decode(),
        base64.b64encode(pub.public_bytes_raw()).decode(),
    )


def derive_shared_secret(priv_b64: str, peer_pub_b64: str) -> bytes:
    priv = x25519.X25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64))
    peer = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(peer_pub_b64))
    shared = priv.exchange(peer)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"MeNo-e2e-v1",
    ).derive(shared)


# Алиас, используемый в окне переписки
derive_chat_key = derive_shared_secret


def encrypt_bytes(key: bytes, data: bytes) -> str:
    """Шифрует произвольные байты AES-GCM, возвращает b64(nonce + ct)."""
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, data, None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_bytes(key: bytes, payload_b64: str) -> bytes:
    raw = base64.b64decode(payload_b64)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None)


def encrypt_text(key: bytes, text: str) -> str:
    return encrypt_bytes(key, text.encode())


def decrypt_text(key: bytes, payload_b64: str) -> str:
    return decrypt_bytes(key, payload_b64).decode()


# ---------- E2E: ключи устройства ----------
def _master_key(password: str, salt: bytes) -> bytes:
    """Мастер-ключ из пароля для шифрования приватного ключа на устройстве."""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    return kdf.derive(password.encode())


def ensure_keys(password: str) -> tuple[str, str]:
    """Гарантирует наличие пары ключей; возвращает (priv_b64, pub_b64).

    Приватный ключ хранится на устройстве зашифрованным мастер-ключом
    из пароля (PBKDF2 + AES-GCM). Сервер знает только публичный ключ.
    """
    data = _load()
    e2e = data.setdefault("e2e", {})
    pub = e2e.get("pub")
    priv_enc = e2e.get("priv_enc")
    salt_b64 = e2e.get("salt")
    if pub and priv_enc and salt_b64:
        priv = decrypt_private_key(password, salt_b64, priv_enc)
        if priv:
            return priv, pub

    # Новой пары ещё нет (или пароль не подошёл к старой) — создаём.
    priv, pub = generate_keys()
    salt = secrets.token_bytes(16)
    mk = _master_key(password, salt)
    e2e["pub"] = pub
    e2e["priv_enc"] = encrypt_bytes(mk, base64.b64decode(priv))
    e2e["salt"] = base64.b64encode(salt).decode()
    _save(data)
    return priv, pub


def decrypt_private_key(password: str, salt_b64: str, priv_enc_b64: str) -> Optional[str]:
    """Расшифровывает приватный ключ паролем; None при неверном пароле/повреждении."""
    try:
        salt = base64.b64decode(salt_b64)
        mk = _master_key(password, salt)
        return base64.b64encode(decrypt_bytes(mk, priv_enc_b64)).decode()
    except Exception:
        return None


def get_public_key() -> Optional[str]:
    return _load().get("e2e", {}).get("pub")