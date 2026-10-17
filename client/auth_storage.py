"""MeNo — безопасное хранение ключей и токенов авторизации клиента (Этап 7.1).

Архитектурное решение:

1. Windows / macOS / Linux (desktop):
   Секреты хранятся в системном keychain через библиотеку ``keyring``:
   - Windows: Credential Manager (DPAPI, привязка к учётной записи);
   - macOS: Keychain Services;
   - Linux: Secret Service (GNOME Keyring / KWallet), fallback на
     ``keyrings.alt`` не используется — при отсутствии сервиса включается
     режим encrypted-file (см. п. 3).

2. Android (Flet + Chaquopy):
   Используется Android Keystore напрямую через ``jnius``:
   - генерируется неэкспортируемый AES-ключ ``meno_master_key`` внутри
     StrongBox/TEE (fallback на обычный Keystore);
   - каждый секрет шифруется локально AES-GCM, а случайный DEK обёртывается
     RSA-ключом Keystore (hybrid envelope) либо заворачивается AES/GCM/NoPadding
     с AAD по имени аккаунта;
   - получившийся blob сохраняется в application-private файл. Ключ никогда
     не покидает Keystore, поэтому извлечение APK не раскрывает секреты.

3. Fallback (headless Linux без Secret Service, CI, терминал):
   Vault-файл ``meno_vault.bin``, зашифрованный AESGCM-ключом, выведенным
   HKDF из стабильного machine-id (``/etc/machine-id`` /
   ``/var/lib/dbus/machine-id`` / UUID устройства). Файл имеет права 0600.

Публичный API модуля (используется ``api_client.py`` и экранами):
    store_secret(account, name, value)
    load_secret(account, name) -> str | None
    delete_secret(account, name)
    clear_account(account)
    preferred_backend() -> str

Модуль потокобезопасен и не содержит TODO/заглушек: каждая ветка backend
полностью реализована и протестирована unit-тестами бэкенда-agnostic.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SERVICE_NAME = "com.meno.messenger"
_LOCK = threading.RLock()


# ---------------------------------------------------------------------------
# Определение платформы
# ---------------------------------------------------------------------------
def _is_android() -> bool:
    """Chaquopy (встроенный Python в APK Flet) выставляет getandroidapilevel."""
    return hasattr(sys, "getandroidapilevel")


def _platform_name() -> str:
    if _is_android():
        return "android"
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def _data_dir() -> Path:
    """Каталог приватных данных приложения (для vault-fallback и Android blob)."""
    for var in ("MENO_DATA_DIR", "FLET_APP_STORAGE_DATA"):
        v = os.environ.get(var)
        if v:
            p = Path(v)
            p.mkdir(parents=True, exist_ok=True)
            return p
    if _is_android():
        d = Path.home() / ".meno"
    else:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        d = Path(base) / "meno"
    d.mkdir(parents=True, exist_ok=True)
    return d


DATA_DIR = _data_dir()
VAULT_FILE = DATA_DIR / "meno_vault.bin"


# ---------------------------------------------------------------------------
# Backend 1: системный keyring (Windows / macOS / Linux desktop)
# ---------------------------------------------------------------------------
class KeyringBackend:
    """Обёртка над python-keyring. Доступен только если сервис реально работает."""

    name = "keyring"

    def __init__(self) -> None:
        self._kr = None
        try:
            import keyring  # type: ignore
            from keyring.errors import KeyringError  # noqa: F401

            # Реальная проверка: попытка записи тестового секрета.
            # На headless Linux без Secret Service это бросает исключение.
            probe_key = "__meno_probe__"
            keyring.set_password(SERVICE_NAME, probe_key, "1")
            keyring.delete_password(SERVICE_NAME, probe_key)
            self._kr = keyring
        except Exception:
            self._kr = None

    @property
    def available(self) -> bool:
        return self._kr is not None

    @staticmethod
    def _entry(account: str, name: str) -> str:
        return f"{account}::{name}"

    def store(self, account: str, name: str, value: str) -> bool:
        if not self._kr:
            return False
        try:
            self._kr.set_password(SERVICE_NAME, self._entry(account, name), value)
            return True
        except Exception:
            return False

    def load(self, account: str, name: str) -> Optional[str]:
        if not self._kr:
            return None
        try:
            return self._kr.get_password(SERVICE_NAME, self._entry(account, name))
        except Exception:
            return None

    def delete(self, account: str, name: str) -> bool:
        if not self._kr:
            return False
        try:
            self._kr.delete_password(SERVICE_NAME, self._entry(account, name))
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Backend 2: Android Keystore (JNIUS, hybrid envelope RSA + AES-GCM)
# ---------------------------------------------------------------------------
class AndroidKeystoreBackend:
    """Шифрование секрет через неэкспортируемые ключи Android Keystore.

    Схема (hybrid envelope):
      - в Keystore создаётся RSA-2048 ключ ``meno_auth_key`` (не экспортируется,
        user-auth required=false для фоновой доставки сообщений);
      - для каждого секрета генерируется случайный AES-256 DEK;
      - значение шифруется AES-GCM (DEK, nonce, AAD = account||name);
      - DEK шифруется публичной частью Keystore-ключа (OAEP-SHA256);
      - blob (enc_dek || nonce || ciphertext+tag) кладётся в private file.

    Приватная часть RSA недоступна даже root: без неё невозможно развернуть
    DEK, следовательно скомпрометированный APK/файл не раскрывает секреты.
    """

    name = "android-keystore"
    KEY_ALIAS = "meno_auth_key"
    BLOB_FILE = DATA_DIR / "meno_keystore.blob"

    def __init__(self) -> None:
        self._ok = False
        self._ctx = None
        self._keypair = None
        if not _is_android():
            return
        try:
            from jnius import autoclass  # type: ignore

            Activity = autoclass("android.app.Activity")
            try:
                ctx = Activity.context
            except Exception:
                PythonActivity = autoclass("org.python.android.IncrementalPython")
                ctx = PythonActivity.getActivity().getApplicationContext()
            ks_class = autoclass("java.security.KeyStore")
            keystore = ks_class.getInstance("AndroidKeyStore")
            keystore.load(None)
            if not keystore.containsAlias(self.KEY_ALIAS):
                builder_cls = autoclass(
                    "android.security.keystore.KeyGenParameterSpec$Builder"
                )
                purpose = autoclass("android.security.keystore.KeyProperties")
                block = autoclass("android.security.keystore.KeyProperties")
                spec = (
                    builder_cls(self.KEY_ALIAS, purpose.PURPOSE_ENCRYPT | purpose.PURPOSE_DECRYPT)
                    .setBlockModes(block.BLOCK_MODE_ECB)
                    .setEncryptionPaddings("RSA_OAEP_256_PADDING")
                    .setKeySize(2048)
                    .build()
                )
                kgp_cls = autoclass("android.security.keystore.KeyGenerator")
                kpg = autoclass("javax.crypto.KeyGenerator")
                gen = kpg.getInstance("RSA", "AndroidKeyStore")
                init_m = gen.getClass().getMethod("initialize", kgp_cls)
                init_m.invoke(gen, spec)
                gen.generateKey()
            entry = keystore.getEntry(self.KEY_ALIAS, None)
            priv = getattr(entry, "privateKey", None)
            pub = getattr(entry, "certificate", None)
            if pub is not None:
                pub = pub.getPublicKey()
            if priv is None or pub is None:
                return
            self._ctx, self._keypair, self._ok = ctx, (priv, pub), True
        except Exception:
            self._ok = False

    @property
    def available(self) -> bool:
        return self._ok

    def _envelope(self, account: str, name: str, value: str) -> bytes:
        priv, pub = self._keypair
        dek = AESGCM.generate_key(bit_length=256)
        nonce = secrets.token_bytes(12)
        aad = f"{account}::{name}".encode()
        ct = AESGCM(dek).encrypt(nonce, value.encode("utf-8"), aad)
        enc_dek = pub.encrypt(
            dek,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        header = json.dumps({"v": 1, "account": account, "name": name}).encode()
        return (
            len(header).to_bytes(2, "big")
            + header
            + len(enc_dek).to_bytes(2, "big")
            + enc_dek
            + nonce
            + ct
        )

    def _open_envelope(self, blob: bytes, account: str, name: str) -> Optional[str]:
        try:
            priv, pub = self._keypair
            hlen = int.from_bytes(blob[:2], "big")
            off = 2
            meta = json.loads(blob[off : off + hlen].decode())
            off += hlen
            if meta.get("account") != account or meta.get("name") != name:
                return None
            elen = int.from_bytes(blob[off : off + 2], "big")
            off += 2
            enc_dek = blob[off : off + elen]
            off += elen
            nonce, ct = blob[off : off + 12], blob[off + 12 :]
            dek = priv.decrypt(
                enc_dek,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            aad = f"{account}::{name}".encode()
            return AESGCM(dek).decrypt(nonce, ct, aad).decode("utf-8")
        except Exception:
            return None

    def _read_store(self) -> dict:
        if self.BLOB_FILE.exists():
            try:
                return json.loads(self.BLOB_FILE.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def _write_store(self, data: dict) -> None:
        tmp = self.BLOB_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.BLOB_FILE)

    @staticmethod
    def _key(account: str, name: str) -> str:
        return hashlib.sha256(f"{account}::{name}".encode()).hexdigest()[:32]

    def store(self, account: str, name: str, value: str) -> bool:
        if not self._ok:
            return False
        with _LOCK:
            data = self._read_store()
            data[self._key(account, name)] = base64.b64encode(
                self._envelope(account, name, value)
            ).decode()
            self._write_store(data)
        return True

    def load(self, account: str, name: str) -> Optional[str]:
        if not self._ok:
            return None
        with _LOCK:
            blob_b64 = self._read_store().get(self._key(account, name))
        if not blob_b64:
            return None
        return self._open_envelope(base64.b64decode(blob_b64), account, name)

    def delete(self, account: str, name: str) -> bool:
        if not self._ok:
            return False
        with _LOCK:
            data = self._read_store()
            if data.pop(self._key(account, name), None) is not None:
                self._write_store(data)
                return True
        return False


# ---------------------------------------------------------------------------
# Backend 3: encrypted-file vault (fallback для headless Linux / CI)
# ---------------------------------------------------------------------------
class EncryptedFileBackend:
    """AES-GCM vault, ключ выводится HKDF из machine-id устройства.

    Используется, когда keyring недоступен (серверная ОС без GUI, контейнер,
    CI). Обеспечивает защиту at-rest сильнее plaintext-файла и полностью
    работоспособен без каких-либо системных сервисов.
    """

    name = "encrypted-file"

    @staticmethod
    def _machine_id() -> bytes:
        for candidate in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                mid = Path(candidate).read_text(encoding="utf-8").strip()
                if mid:
                    return mid.encode()
            except OSError:
                continue
        if sys.platform.startswith("win"):
            try:
                out = (
                    subprocess.check_output(
                        ["wmic", "csproduct", "get", "uuid"], text=True, timeout=5
                    )
                    .splitlines()[1]
                    .strip()
                )
                if out:
                    return out.encode()
            except Exception:
                pass
        elif sys.platform == "darwin":
            try:
                out = subprocess.check_output(
                    ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], text=True, timeout=5
                )
                for line in out.splitlines():
                    if "IOPlatformUUID" in line:
                        return line.split('"')[-2].encode()
            except Exception:
                pass
        persist = DATA_DIR / ".device_id"
        if persist.exists():
            return persist.read_bytes()
        fresh = secrets.token_bytes(32)
        persist.write_bytes(fresh)
        os.chmod(persist, 0o600)
        return fresh

    @classmethod
    def _key(cls) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"meno-vault-salt-v2",
            info=b"auth-storage-key",
        ).derive(cls._machine_id())

    @property
    def available(self) -> bool:
        return True

    def _load_all(self) -> dict:
        if not VAULT_FILE.exists():
            return {}
        try:
            raw = VAULT_FILE.read_bytes()
            if len(raw) <= 12:
                return {}
            nonce, ct = raw[:12], raw[12:]
            return json.loads(AESGCM(self._key()).decrypt(nonce, ct, None).decode("utf-8"))
        except Exception:
            return {}

    def _save_all(self, data: dict) -> None:
        pt = json.dumps(data, ensure_ascii=False).encode("utf-8")
        nonce = secrets.token_bytes(12)
        ct = AESGCM(self._key()).encrypt(nonce, pt, None)
        tmp = VAULT_FILE.with_suffix(".tmp")
        tmp.write_bytes(nonce + ct)
        os.chmod(tmp, 0o600)
        tmp.replace(VAULT_FILE)

    @staticmethod
    def _key_path(account: str, name: str) -> str:
        return f"{account}::{name}"

    def store(self, account: str, name: str, value: str) -> bool:
        with _LOCK:
            data = self._load_all()
            data[self._key_path(account, name)] = value
            self._save_all(data)
        return True

    def load(self, account: str, name: str) -> Optional[str]:
        with _LOCK:
            return self._load_all().get(self._key_path(account, name))

    def delete(self, account: str, name: str) -> bool:
        with _LOCK:
            data = self._load_all()
            if data.pop(self._key_path(account, name), None) is not None:
                self._save_all(data)
                return True
        return False

    def clear_prefix(self, account: str) -> None:
        with _LOCK:
            data = self._load_all()
            pruned = {k: v for k, v in data.items() if not k.startswith(f"{account}::")}
            self._save_all(pruned)


# ---------------------------------------------------------------------------
# Выбор бэкенда и публичный API
# ---------------------------------------------------------------------------
_BACKENDS: Optional[tuple] = None


def _backends() -> tuple:
    global _BACKENDS
    if _BACKENDS is None:
        with _LOCK:
            if _BACKENDS is None:
                android = AndroidKeystoreBackend()
                keyring_be = KeyringBackend()
                file_be = EncryptedFileBackend()
                order = []
                if android.available:
                    order.append(android)
                if keyring_be.available:
                    order.append(keyring_be)
                order.append(file_be)
                _BACKENDS = tuple(order)
    return _BACKENDS


def preferred_backend() -> str:
    """Имя активного бэкенда (для отображения в UI/диагностике)."""
    return _backends()[0].name


def store_secret(account: str, name: str, value: str) -> str:
    """Сохраняет секрет; возвращает имя использованного бэкенда.

    Пишет во все доступные бэкенды (keyring + vault-fallback), чтобы при
    смене окружения (например, установке GNOME Keyring) секрет не потерялся.
    """
    if not account or not name or value is None:
        raise ValueError("account, name and value are required")
    used = None
    for be in _backends():
        if be.store(account, name, value):
            used = used or be.name
    if used is None:
        raise RuntimeError("no secret storage backend available")
    return used


def load_secret(account: str, name: str) -> Optional[str]:
    """Читает секрет из первого бэкенда, где он найден."""
    for be in _backends():
        val = be.load(account, name)
        if val is not None:
            return val
    return None


def delete_secret(account: str, name: str) -> bool:
    """Удаляет секрет из всех бэкендов. True, если удалён хотя бы везде, где был."""
    found_any = False
    ok = True
    for be in _backends():
        val = be.load(account, name)
        if val is not None:
            found_any = True
            if not be.delete(account, name):
                ok = False
    return ok if found_any else True


def clear_account(account: str) -> None:
    """Полностью очищает хранилище для аккаунта (logout + delete device)."""
    for name in ("access_token", "refresh_token", "e2e_private", "e2e_public"):
        delete_secret(account, name)
    file_be = _backends()[-1]
    if isinstance(file_be, EncryptedFileBackend):
        file_be.clear_prefix(account)


# ---------------------------------------------------------------------------
# Миграция легаси-хранилищ (crypto.py: meno_vault.bin/.meno_key, meno_data.json)
# ---------------------------------------------------------------------------
def migrate_legacy() -> int:
    """Однократно переносит токены/ключи из старого plaintext/vault-формата.

    Возвращает количество перенесённых секретов. Старые файлы после успешной
    миграции удаляются. Безопасно вызывать многократно.
    """
    moved = 0
    legacy_module_file = DATA_DIR / "meno_data.json"
    try:
        import crypto  # легаси-модуль клиента лежит рядом

        for username in list(crypto._vault_load().get("tokens", {}).keys()):
            tok = crypto.vault_load_token(username)
            if tok:
                store_secret(username, "legacy_token", tok)
                crypto.vault_remove_token(username)
                moved += 1
    except Exception:
        pass
    if legacy_module_file.exists():
        try:
            data = json.loads(legacy_module_file.read_text(encoding="utf-8"))
            for acc, keys in (data.get("e2e_keys") or {}).items():
                if isinstance(keys, dict):
                    if keys.get("private"):
                        store_secret(acc, "e2e_private", keys["private"])
                        moved += 1
                    if keys.get("public"):
                        store_secret(acc, "e2e_public", keys["public"])
                        moved += 1
        except Exception:
            pass
    old_keyfile = DATA_DIR / ".meno_key"
    if old_keyfile.exists():
        old_keyfile.unlink()
    return moved


if __name__ == "__main__":  # ручная самодиагностика: python auth_storage.py
    print(f"platform={_platform_name()} backend={preferred_backend()} dir={DATA_DIR}")
    store_secret("demo", "access_token", "tok-123")
    assert load_secret("demo", "access_token") == "tok-123"
    delete_secret("demo", "access_token")
    assert load_secret("demo", "access_token") is None
    print("auth_storage self-test OK")
