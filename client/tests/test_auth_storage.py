"""Unit-тесты безопасного клиентского хранилища секретов (client/auth_storage.py).

Этап стабилизации (микро-спринт 2, вариант «Безопасность важнее фич»):
покрываем критический E2EE-модуль изолированными тестами без реальных
системных keychain/Keystore.

Стратегия изоляции:
- фикстура ``vault_env`` направляет ``DATA_DIR``/``VAULT_FILE`` модуля в
  временную папку pytest'а (``tmp_path``) — тесты никогда не трогают
  реальную ФС и файлы проекта;
- ``keyring`` и Android-бэкенд принудительно отключаются (в CI их нет),
  поэтому детерминированным путём проверяется ``EncryptedFileBackend``
  (AES-GCM vault с HKDF-ключом из machine-id);
- все тесты async (pytest-asyncio, asyncio_mode=auto): блокирующий код
  хранилища вызывается через ``asyncio.to_thread``, как это делает UI-слой,
  плюс отдельный стресс-тест конкурентных задач.

Сценарии: roundtrip, перезапись, изоляция аккаунтов, отсутствие plaintext
на диске, права 0600, потокобезопасность, очистка аккаунта, валидация API.
"""
from __future__ import annotations

import asyncio
import json
import stat
import sys
from pathlib import Path

import pytest

# Клиентский пакет лежит в client/ — добавляем его в sys.path точечно,
# чтобы тесты работали и из корня репозитория, и из CI.
CLIENT_DIR = Path(__file__).resolve().parents[1]
if str(CLIENT_DIR) not in sys.path:
    sys.path.insert(0, str(CLIENT_DIR))

import auth_storage as store  # noqa: E402


# ---------------------------------------------------------------------------
# Фикстуры
# ---------------------------------------------------------------------------
@pytest.fixture()
def vault_env(tmp_path, monkeypatch):
    """Полная изоляция хранилища: временный DATA_DIR/VAULT_FILE, без keyring."""
    data_dir = tmp_path / "meno-data"
    data_dir.mkdir()
    vault_file = data_dir / "meno_vault.bin"

    monkeypatch.setattr(store, "DATA_DIR", data_dir)
    monkeypatch.setattr(store, "VAULT_FILE", vault_file)
    monkeypatch.setattr(
        store.EncryptedFileBackend, "_machine_id",
        classmethod(lambda cls: b"test-machine-id-isolated"),
    )

    # Сбрасываем кэш бэкендов -> пересобираем только encrypted-file backend
    # (keyring недоступен: пакета нет в CI; android: не Android-платформа).
    monkeypatch.setattr(store, "_BACKENDS", None)
    file_be = store.EncryptedFileBackend()
    monkeypatch.setattr(store, "_backends", lambda: (file_be,))
    yield {"dir": data_dir, "vault": vault_file, "backend": file_be}
    monkeypatch.setattr(store, "_BACKENDS", None)


# ---------------------------------------------------------------------------
# Сценарий 1: Roundtrip — сохранение / чтение / удаление
# ---------------------------------------------------------------------------
async def test_roundtrip_store_load_delete(vault_env):
    """Секрет проходит полный жизненный цикл через асинхронный API."""
    account, name, value = "alice", "access_token", "eyJhbGciOi.Test-K3y"

    backend = await asyncio.to_thread(store.store_secret, account, name, value)
    assert backend == "encrypted-file"
    assert await asyncio.to_thread(store.load_secret, account, name) == value

    deleted = await asyncio.to_thread(store.delete_secret, account, name)
    assert deleted is True
    assert await asyncio.to_thread(store.load_secret, account, name) is None


async def test_overwrite_returns_latest_value(vault_env):
    """Повторное сохранение того же ключа безопасно перезаписывает значение."""
    await asyncio.to_thread(store.store_secret, "bob", "refresh_token", "v1")
    await asyncio.to_thread(store.store_secret, "bob", "refresh_token", "v2")
    assert await asyncio.to_thread(store.load_secret, "bob", "refresh_token") == "v2"


async def test_load_missing_secret_returns_none(vault_env):
    """Чтение несуществующего секрета — None, без исключения (важно для UI)."""
    assert await asyncio.to_thread(store.load_secret, "ghost", "token") is None


async def test_delete_missing_secret_is_true(vault_env):
    """Идемпотентный logout: удаление отсутствующего секрета не роняет клиента."""
    assert await asyncio.to_thread(store.delete_secret, "nobody", "token") is True


# ---------------------------------------------------------------------------
# Сценарий 2: Изоляция аккаунтов (Пользователь А vs Пользователь Б)
# ---------------------------------------------------------------------------
async def test_accounts_are_isolated(vault_env):
    """Ключи alice не видны и не затираются действиями bob (параноидальный E2EE)."""
    await asyncio.to_thread(
        store.store_secret, "alice", "e2e_private", "PRIVATE-ALICE-KEY"
    )
    await asyncio.to_thread(
        store.store_secret, "bob", "e2e_private", "PRIVATE-BOB-KEY"
    )

    assert await asyncio.to_thread(store.load_secret, "alice", "e2e_private") == (
        "PRIVATE-ALICE-KEY"
    )
    assert await asyncio.to_thread(store.load_secret, "bob", "e2e_private") == (
        "PRIVATE-BOB-KEY"
    )

    # Перезапись у bob не должна влиять на alice.
    await asyncio.to_thread(store.store_secret, "bob", "e2e_private", "ROTATED-BOB")
    assert await asyncio.to_thread(store.load_secret, "alice", "e2e_private") == (
        "PRIVATE-ALICE-KEY"
    )

    # Удаление у alice не должно затрагивать bob.
    await asyncio.to_thread(store.delete_secret, "alice", "e2e_private")
    assert await asyncio.to_thread(store.load_secret, "alice", "e2e_private") is None
    assert await asyncio.to_thread(store.load_secret, "bob", "e2e_private") == (
        "ROTATED-BOB"
    )


async def test_clear_account_removes_only_target_account(vault_env):
    """clear_account (logout+delete device) чистит префикс только своего аккаунта."""
    for name in ("access_token", "refresh_token", "e2e_private", "e2e_public"):
        await asyncio.to_thread(store.store_secret, "alice", name, f"a-{name}")
        await asyncio.to_thread(store.store_secret, "bob", name, f"b-{name}")

    await asyncio.to_thread(store.clear_account, "alice")

    for name in ("access_token", "refresh_token", "e2e_private", "e2e_public"):
        assert await asyncio.to_thread(store.load_secret, "alice", name) is None
        assert await asyncio.to_thread(store.load_secret, "bob", name) == f"b-{name}"


# ---------------------------------------------------------------------------
# Сценарий 3: Шифрование vault — на диске нет plaintext/JSON
# ---------------------------------------------------------------------------
async def test_vault_file_is_encrypted_not_plaintext(vault_env):
    """Секрет реально шифруется AES-GCM: ни значения, ни JSON-структуры на диске."""
    secret_value = "SUPER-SECRET-TOKEN-do-not-leak"
    await asyncio.to_thread(store.store_secret, "eve-victim", "access_token", secret_value)

    vault: Path = vault_env["vault"]
    assert vault.exists(), "vault-файл должен быть создан при первой записи"
    raw = vault.read_bytes()

    # 1. Значение и имя аккаунта не встречаются в открытом виде (ни ASCII, ни UTF-8).
    assert secret_value.encode("utf-8") not in raw
    assert secret_value not in raw.decode("latin-1")
    assert b"eve-victim" not in raw

    # 2. Это не JSON: первый байл — не '{', файл не парсится как текст.
    assert not raw.lstrip().startswith(b"{")
    with pytest.raises(Exception):
        json.loads(raw.decode("utf-8"))

    # 3. Структура AES-GCM blob: 12-байтовый nonce + ciphertext, длина > nonce.
    assert len(raw) > 12

    # 4. Подделка файла (garbage) читается как пусто, без падения клиента.
    vault.write_bytes(b"\x00" * 64)
    assert await asyncio.to_thread(store.load_secret, "eve-victim", "access_token") is None


async def test_vault_file_permissions_0600(vault_env):
    """Файл хранилища доступен только владельцу (защита от чтения соседями)."""
    await asyncio.to_thread(store.store_secret, "mallory", "token", "t0k3n")
    mode = stat.S_IMODE(vault_env["vault"].stat().st_mode)
    assert mode == 0o600


# ---------------------------------------------------------------------------
# Сценарий 4: Потоко/таско-безопасность
# ---------------------------------------------------------------------------
async def test_concurrent_async_tasks_no_loss(vault_env):
    """Одновременные PATCH-подобные записи из множества задач не теряют данные.

    Каждый «ток» пишет уникальный секрет; после join все значения обязаны
    читаться корректно — признак корректной сериализации read-modify-write
    под RLock (гонок check-then-act на уровне файла недопустима).
    """
    n_tasks = 20
    accounts = [f"user_{i}" for i in range(n_tasks)]

    async def write_and_read(account: str) -> bool:
        value = f"secret-for-{account}"
        await asyncio.to_thread(store.store_secret, account, "access_token", value)
        return await asyncio.to_thread(store.load_secret, account, "access_token") == value

    results = await asyncio.gather(*(write_and_read(a) for a in accounts))
    assert all(results), "часть конкурентных записей потеряна — гонка в хранилище!"

    # Финальная сверка состояния файла после шторма записей.
    for account in accounts:
        assert await asyncio.to_thread(
            store.load_secret, account, "access_token"
        ) == f"secret-for-{account}"


async def test_concurrent_writes_same_key_last_writer_wins(vault_env):
    """Конкурентная перезапись одного ключа не повреждает vault-файл."""
    async def writer(idx: int) -> None:
        await asyncio.to_thread(store.store_secret, "shared", "token", f"val-{idx}")

    await asyncio.gather(*(writer(i) for i in range(10)))

    final = await asyncio.to_thread(store.load_secret, "shared", "token")
    assert final in {f"val-{i}" for i in range(10)}, "vault повреждён гонкой записей"


# ---------------------------------------------------------------------------
# Сценарий 5: Валидация публичного API (Clean Code: guard clauses)
# ---------------------------------------------------------------------------
async def test_store_secret_rejects_empty_arguments(vault_env):
    """Пустой account/name или None-value — ValueError, а не тихая порча данных."""
    with pytest.raises(ValueError):
        await asyncio.to_thread(store.store_secret, "", "token", "value")
    with pytest.raises(ValueError):
        await asyncio.to_thread(store.store_secret, "alice", "", "value")
    with pytest.raises(ValueError):
        await asyncio.to_thread(store.store_secret, "alice", "token", None)
