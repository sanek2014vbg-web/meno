"""Тесты E2EE-модуля клиента (client/crypto.py) — Блок C ТЗ (Фаза 3).

Покрытие: генерация ключей, X25519/HKDF-согласование, AES-GCM шифрование,
раундтрек текст→шифр→текст, отказ на неверном ключе/повреждённых данных,
мастер-ключ PBKDF2 и защищённое хранилище приватного ключа.

Все файловые операции изолируются в tmp_path через monkeypatch env
(MENO_DATA_DIR читается crypto._data_dir() при импорте модуля, поэтому для
каждого теста криптография перезагружается с новым каталогом данных).
"""
import importlib
import json
from pathlib import Path

import pytest

import client.crypto as crypto


@pytest.fixture()
def c(tmp_path, monkeypatch):
    """crypto-модуль с изолированным каталогом данных в tmp_path."""
    data_dir = tmp_path / "meno_data"
    monkeypatch.setenv("MENO_DATA_DIR", str(data_dir))
    return importlib.reload(crypto)


# ---------- Генерация ключей ----------

class TestGenerateKeys:
    def test_returns_b64_pair_with_correct_lengths(self, c):
        priv_b64, pub_b64 = c.generate_keys()
        # X25519: приватный и публичный ключи — ровно 32 байта
        assert len(c.base64.b64decode(priv_b64)) == 32
        assert len(c.base64.b64decode(pub_b64)) == 32

    def test_keys_are_unique_per_call(self, c):
        a = c.generate_keys()
        b = c.generate_keys()
        assert a != b

    def test_public_key_derives_from_private(self, c):
        from cryptography.hazmat.primitives.asymmetric import x25519

        priv_b64, pub_b64 = c.generate_keys()
        priv = x25519.X25519PrivateKey.from_private_bytes(
            c.base64.b64decode(priv_b64)
        )
        derived_pub = c.base64.b64encode(
            priv.public_key().public_bytes_raw()
        ).decode()
        assert derived_pub == pub_b64


# ---------- Согласование общего секрета (X25519 + HKDF) ----------

class TestSharedSecret:
    def test_both_sides_derive_same_key(self, c):
        priv_a, pub_a = c.generate_keys()
        priv_b, pub_b = c.generate_keys()
        k_ab = c.derive_shared_secret(priv_a, pub_b)
        k_ba = c.derive_shared_secret(priv_b, pub_a)
        assert k_ab == k_ba
        assert len(k_ab) == 32

    def test_different_peers_yield_different_keys(self, c):
        priv_a, _ = c.generate_keys()
        _, pub_b = c.generate_keys()
        _, pub_c = c.generate_keys()
        assert c.derive_shared_secret(priv_a, pub_b) != \
               c.derive_shared_secret(priv_a, pub_c)

    def test_derive_chat_key_is_alias_of_derive_shared_secret(self, c):
        assert c.derive_chat_key is c.derive_shared_secret

    def test_invalid_base64_material_raises(self, c):
        priv_b64, _ = c.generate_keys()
        with pytest.raises(Exception):
            c.derive_shared_secret(priv_b64, "не-base64!!!")


# ---------- AES-GCM: раундтрек и отказы ----------

class TestEncryptDecryptBytes:
    def test_roundtrip(self, c):
        key = c.secrets.token_bytes(32)
        data = b"\x00\x01\x02 MeNo \xff" * 100
        payload = c.encrypt_bytes(key, data)
        assert isinstance(payload, str)
        assert c.decrypt_bytes(key, payload) == data

    def test_empty_data_roundtrip(self, c):
        key = c.secrets.token_bytes(32)
        payload = c.encrypt_bytes(key, b"")
        assert c.decrypt_bytes(key, payload) == b""

    def test_nonce_randomized_each_call(self, c):
        key = c.secrets.token_bytes(32)
        p1 = c.encrypt_bytes(key, b"same text")
        p2 = c.encrypt_bytes(key, b"same text")
        assert p1 != p2  # свежий nonce каждый раз
        assert c.decrypt_bytes(key, p1) == c.decrypt_bytes(key, p2)

    def test_wrong_key_fails(self, c):
        k1 = c.secrets.token_bytes(32)
        k2 = c.secrets.token_bytes(32)
        payload = c.encrypt_bytes(k1, b"secret")
        from cryptography.exceptions import InvalidTag

        with pytest.raises(InvalidTag):
            c.decrypt_bytes(k2, payload)

    @pytest.mark.parametrize("mutate", ["flip_byte", "truncate", "too_short"])
    def test_corrupted_ciphertext_fails(self, c, mutate):
        from cryptography.exceptions import InvalidTag

        key = c.secrets.token_bytes(32)
        raw = bytearray(c.base64.b64decode(c.encrypt_bytes(key, b"hello world")))
        if mutate == "flip_byte":
            raw[-1] ^= 0x01                      # подделан тег GCM
        elif mutate == "truncate":
            del raw[-5:]                          # обрезан тег
        else:
            raw = raw[:8]                         # меньше длины nonce
        bad = c.base64.b64encode(bytes(raw)).decode()
        with pytest.raises((InvalidTag, ValueError)):
            c.decrypt_bytes(key, bad)

    def test_non_base64_payload_raises(self, c):
        key = c.secrets.token_bytes(32)
        with pytest.raises(Exception):
            c.decrypt_bytes(key, "%%%not base64%%%")


class TestTextApi:
    def test_unicode_roundtrip(self, c):
        key = c.derive_shared_secret(*[t for t in c.generate_keys()][:1] +
                                     [c.generate_keys()[1]])
        text = "Привет, мир! 🌍 <b>&amp;</b>"
        payload = c.encrypt_text(key, text)
        assert c.decrypt_text(key, payload) == text

    def test_wrong_key_text_raises(self, c):
        k1, k2 = c.secrets.token_bytes(32), c.secrets.token_bytes(32)
        payload = c.encrypt_text(k1, "секрет")
        from cryptography.exceptions import InvalidTag

        with pytest.raises(InvalidTag):
            c.decrypt_text(k2, payload)


# ---------- Мастер-ключ PBKDF2 и хранение приватного ключа ----------

class TestMasterKeyAndKeystore:
    def test_master_key_deterministic_and_password_sensitive(self, c):
        salt = c.secrets.token_bytes(16)
        k1 = c._master_key("password", salt)
        k2 = c._master_key("password", salt)
        k3 = c._master_key("Password!", salt)
        assert k1 == k2 and len(k1) == 32
        assert k1 != k3

    def test_ensure_keys_creates_and_reuses_storage(self, c):
        priv, pub = c.ensure_keys("top-secret-pin")
        # повторный вызов с тем же паролем возвращает сохранённую пару
        priv2, pub2 = c.ensure_keys("top-secret-pin")
        assert (priv, pub) == (priv2, pub2)
        assert c.get_public_key() == pub

        data = json.loads(Path(c.DATA_FILE).read_text(encoding="utf-8"))
        e2e = data["e2e"]
        assert set(e2e) == {"pub", "priv_enc", "salt"}
        # приватный ключ НИКОГДА не хранится в открытом виде
        assert priv not in json.dumps(data)
        assert "priv" not in e2e

    def test_decrypt_private_key_wrong_password_returns_none(self, c):
        c.ensure_keys("correct horse battery staple")
        data = json.loads(Path(c.DATA_FILE).read_text(encoding="utf-8"))["e2e"]
        assert c.decrypt_private_key(
            "wrong-password", data["salt"], data["priv_enc"]
        ) is None

    def test_decrypt_private_key_garbage_inputs_return_none(self, c):
        assert c.decrypt_private_key("p", "%%%", "%%%") is None

    def test_ensure_keys_with_wrong_password_rotates_gracelessly(self, c):
        # ensure_keys с неверным паролем не может расшифровать хранимый ключ
        # и генерирует новую пару (документированное поведение fallback-ветки)
        _, pub_old = c.ensure_keys("pass-1")
        priv_new, pub_new = c.ensure_keys("pass-2")
        assert pub_new != pub_old
        assert c.decrypt_private_key("pass-2", *_stored_args(c)) == priv_new


def _stored_args(c):
    data = json.loads(Path(c.DATA_FILE).read_text(encoding="utf-8"))["e2e"]
    return data["salt"], data["priv_enc"]


# ---------- Vault и ПИН-хранилище (работают без сети) ----------

class TestVaultAndPins:
    def test_token_lifecycle(self, c, monkeypatch):
        # фиксируем machine id: vault-ключ выводен из него, тест не зависит
        # от реальной ОС (wmic есть только на Windows)
        monkeypatch.setattr(c, "_get_machine_id", lambda: b"test-device-id")
        assert c.vault_load_token("alice") is None
        c.vault_save_token("alice", "jwt.alice")
        c.vault_save_token("bob", "jwt.bob")
        assert c.vault_load_token("alice") == "jwt.alice"
        # файл на диске — зашифрованный blob, токен не читается глазами
        raw = Path(c.VAULT_FILE).read_bytes()
        assert b"jwt.alice" not in raw
        c.vault_remove_token("alice")
        assert c.vault_load_token("alice") is None
        assert c.vault_load_token("bob") == "jwt.bob"
        c.vault_clear()
        assert c.vault_load_token("bob") is None

    def test_vault_survives_reload_same_device(self, c, monkeypatch):
        # стабильный machine id -> тот же вывод ключа после «перезапуска»
        monkeypatch.setattr(c, "_get_machine_id", lambda: b"stable-id")
        c.vault_save_token("alice", "tok")
        key_before = c._device_key()
        mod2 = importlib.reload(c)                     # новый экземпляр модуля
        monkeypatch.setattr(mod2, "_get_machine_id", lambda: b"stable-id")
        assert mod2._device_key() == key_before        # ключ детерминирован
        assert mod2.vault_load_token("alice") == "tok"

    def test_vault_load_returns_empty_on_foreign_device(self, c, monkeypatch):
        monkeypatch.setattr(c, "_get_machine_id", lambda: b"device-A")
        c.vault_save_token("alice", "tok")
        monkeypatch.setattr(c, "_get_machine_id", lambda: b"device-B")
        # чужое устройство -> другой HKDF-ключ -> GCM-tag невалиден -> {}
        assert c._vault_load() == {}

    def test_chat_pin_lifecycle(self, c):
        assert not c.has_chat_pin(7)
        c.set_chat_pin(7, "1234")
        assert c.has_chat_pin(7)
        assert c.check_chat_pin(7, "1234")
        assert not c.check_chat_pin(7, "0000")
        c.remove_chat_pin(7)
        assert not c.has_chat_pin(7)

    def test_settings_roundtrip(self, c):
        c.save_setting("theme", "dark")
        assert c.get_setting("theme") == "dark"
        assert c.get_setting("missing", default="fallback") == "fallback"
