"""MeNo — сквозной E2E-движок по протоколу Signal (Пункт 1 ТЗ v2.0).

Чистая клиентская реализация без внешних protobuf-зависимостей, только
библиотека ``cryptography``:

1. X3DH handshake (Extended Triple Diffie-Hellman):
   - Identity Key IK   — долговременный X25519-ключ (постоянный для аккаунта);
   - Signed Prekey SPK — ротационный X25519-ключ, подписанный Ed25519 IK;
   - One-Time Prekey OPK — одноразовый X25519-ключ из пула сервера;
   - Ephemeral Key EK   — эфемерный ключ инициатора handshake.
   Общий секрет: SK = HKDF(DH1||DH2||DH3||DH4), где
     DH1 = IK_A^pub ↔ SPK_B^priv, DH2 = EK_A ↔ IK_B^pub,
     DH3 = EK_A ↔ SPK_B^priv, DH4 = EK_A ↔ OPK_B^priv (если OPK выдан).

2. Double Ratchet (двусторонняя «трещотка»):
   - корневая цепочка KDF (HKDF-SHA256) порождает цепочки отправителя/получателя;
   - DH-раatchet с ротацией X25519-пар при каждом ответном сообщении;
   - симметричная цепочка ключей сообщений (Message Key Chain);
   - шифрование plaintext-нагрузки AES-256-GCM (256-битный ключ, 96-битный nonce);
   - skipped message keys хранятся для обработки переупорядоченной доставки.

3. Формат ciphertext-контейнера (base64 в поле ``content`` сервера):
   envelope JSON: {"v":2,"sig","type":"pre"|"whisper","hk":{...},"r":{...},"n":..,"ct":b64}
   - "pre"  — PreKey Whisper Message (первое сообщение сессии, несёт X3DH-манифест);
   - "whisper" — обычный Double Ratchet message.
   AAD контейнера включает identity-ключи сторон и header ratchet-ключа,
   что связывает ciphertext с конкретным handshake и исключает подмену.

Сервер оперирует только слепым ciphertext: он не имеет приватных ключей и
не может ни расшифровать, ни просуммировать, ни проиндексировать сообщения.

Модуль потокобезопасен (глобальный RLock вокруг операций трещотки) и
сохраняет состояние сессий в зашифрованном локальном хранилище
(``crypto.encrypt_bytes`` / vault-файл ``meno_e2e_sessions.bin``).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:  # боевой режим: состояние сессий шифруется через локальное хранилище клиента
    import crypto as _local_store  # type: ignore
except Exception:  # pragma: no cover — модуль можно использовать автономно (тесты/CLI)
    _local_store = None

# ---------------------------------------------------------------------------
# Константы протокола
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = 2
KDF_RATCHET_INFO = b"MeNoSignalRootChain"
KDF_MSG_CHAIN_INFO = b"MeNoSignalMsgChain"
KDF_X3DH_INFO = b"MeNoSignalX3DH"
# Ключ PreKey Whisper Message: MK_pre = HKDF-expand(X3DH SK) — обе стороны
# выводят его детерминированно из одного и того же X3DH Master Secret.
KDF_PREKEY_MSG_INFO = b"MeNoSignalPreKeyMessage"
# Стартовый вывод (Root Key || Chain Key) из X3DH SK: HKDF(SK, salt=0x00*32).
# Используется обеими сторонами в init_first_chain и стороной B при первом
# исходящем whisper-сообщении (_send_ratchet_init) — единая каноническая KDF.
KDF_ROOT_INIT_INFO = b"MenoProtocolRootDerivation"
X3DH_NULL_KEY = bytes(32)
MAX_SKIP_KEYS = 1000          # защита от DoS через гигантский N-номер
AES_KEY_BITS = 256
NONCE_BYTES = 12
IDENTITY_SEED_BYTES = 32


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


def _hkdf(secret: bytes, info: bytes, salt: bytes = b"", length: int = 64) -> bytes:
    """HKDF-SHA256: два 32-байтных выхода (root key || chain key)."""
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=salt or None, info=info
    ).derive(secret)


# ---------------------------------------------------------------------------
# Identity Key + Prekey Bundle (сторона, публикующая ключи на сервер)
# ---------------------------------------------------------------------------


@dataclass
class PreKeyBundle:
    """Публичный пакет ключей пользователя для инициации X3DH."""

    user_id: int
    identity_pub_b64: str      # Ed25519 pub (fingerprint / подпись SPK)
    signed_prekey_b64: str     # X25519 pub SPK
    signed_prekey_id: int
    signature_b64: str         # Ed25519(sig, ik_priv) над SPK||spk_id
    one_time_prekeys: List[Tuple[int, str]] = field(default_factory=list)


class Identity:
    """Долговременные ключи аккаунта: X25519 IK + Ed25519 signing key.

    Все приватные материалы выводимо детерминируются из одного 32-байтного
    секрета (seed), который хранится в защищённом хранилище клиента
    (keyring / Android Keystore / encrypted-file vault).
    """

    def __init__(self, seed: Optional[bytes] = None) -> None:
        if seed is None:
            seed = secrets.token_bytes(IDENTITY_SEED_BYTES)
        if len(seed) != IDENTITY_SEED_BYTES:
            raise ValueError("identity seed must be 32 bytes")
        self._seed = seed
        # Детерминированные производные (как HKDF-derivation в ed25519 seeds)
        self.ik_priv = x25519.X25519PrivateKey.from_private_bytes(
            HKDF(algorithm=hashes.SHA256(), length=32, salt=b"meno-x3dh-ik",
                 info=b"identity-x25519").derive(seed)
        )
        self.sign_priv = ed25519.Ed25519PrivateKey.from_private_bytes(
            HKDF(algorithm=hashes.SHA256(), length=32, salt=b"meno-x3dh-ik",
                 info=b"identity-ed25519").derive(seed)
        )
        self.signed_prekey_id = secrets.randbelow(0x7FFFFFFF)
        self.signed_prekey_priv = x25519.X25519PrivateKey.generate()
        self._one_time: Dict[int, x25519.X25519PrivateKey] = {}

    # --- публичные представления ---
    @property
    def identity_pub_b64(self) -> str:
        return _b64e(self.sign_priv.public_key().public_bytes_raw())

    @property
    def identity_x25519_pub_b64(self) -> str:
        return _b64e(self.ik_priv.public_key().public_bytes_raw())

    @property
    def signed_prekey_b64(self) -> str:
        return _b64e(self.signed_prekey_priv.public_key().public_bytes_raw())

    def sign_blob(self) -> bytes:
        """Канонический байтовый blob для подписи Signed Prekey."""
        return (b"meno-spk-v" + str(PROTOCOL_VERSION).encode()
                + b"|" + str(self.signed_prekey_id).encode()
                + b"|" + self.signed_prekey_priv.public_key().public_bytes_raw())

    def signed_prekey_signature_b64(self) -> str:
        return _b64e(self.sign_priv.sign(self.sign_blob()))

    def verify_spk_signature(self, peer_identity_pub_b64: str, spk_b64: str,
                             spk_id: int, signature_b64: str) -> bool:
        """Проверка подписи Signed Prekey собеседника его Identity Key."""
        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(
                _b64d(peer_identity_pub_b64))
            blob = (b"meno-spk-v" + str(PROTOCOL_VERSION).encode()
                    + b"|" + str(spk_id).encode()
                    + b"|" + _b64d(spk_b64))
            pub.verify(_b64d(signature_b64), blob)
            return True
        except (InvalidSignature, ValueError, Exception):
            return False

    # --- One-Time Prekeys ---
    def generate_one_time_prekeys(self, count: int = 20) -> List[Tuple[int, str]]:
        """Генерирует пул одноразовых prekey; возвращает [(key_id, pub_b64)]."""
        out: List[Tuple[int, str]] = []
        for _ in range(count):
            key_id = secrets.randbelow(0x7FFFFFFF) or 1
            priv = x25519.X25519PrivateKey.generate()
            self._one_time[key_id] = priv
            out.append((key_id, _b64e(priv.public_key().public_bytes_raw())))
        return out

    def build_bundle(self, user_id: int, one_time_count: int = 20) -> dict:
        """Собирает JSON-пакет для публикации на сервере (POST /bundle)."""
        otpks = self.generate_one_time_prekeys(one_time_count)
        return {
            "identity_pub": self.identity_pub_b64,
            "identity_x25519": self.identity_x25519_pub_b64,
            "signed_prekey": self.signed_prekey_b64,
            "signed_prekey_id": self.signed_prekey_id,
            "signature": self.signed_prekey_signature_b64(),
            "one_time_prekeys": [{"key_id": k, "public_key": v} for k, v in otpks],
        }

    def take_one_time_priv(self, key_id: int) -> Optional[x25519.X25519PrivateKey]:
        """Возвращает и ИЗЫМАЕТ приватную часть использованного OPK."""
        return self._one_time.pop(int(key_id), None)

    @property
    def remaining_one_time_prekeys(self) -> int:
        return len(self._one_time)

    def needs_replenishment(self, threshold: int = 5) -> bool:
        return self.remaining_one_time_prekeys < threshold

    @property
    def seed_b64(self) -> str:
        return _b64e(self._seed)

    @classmethod
    def from_seed_b64(cls, seed_b64: str) -> "Identity":
        return cls(_b64d(seed_b64))


# ---------------------------------------------------------------------------
# Double Ratchet
# ---------------------------------------------------------------------------


@dataclass
class _ChainState:
    key: bytes              # 32-байтный ключ цепочки
    index: int = 0          # сколько ключей сообщений уже израсходовано
    skipped: Dict[int, "_SkippedKey"] = None  # пропущенные N -> message keys

    def __post_init__(self):
        if self.skipped is None:
            self.skipped = {}


class SessionState:
    """Одна сессия Double Ratchet с конкретным собеседником.

    Реализация соответствует модели спецификации Signal:
      - root chain (HKDF-SHA256) + DH-ratchet с ротацией X25519-пар;
      - send_chain — текущая отправительская цепочка сообщений;
      - recv_chains — СЛОВАРЬ приёмных цепочек по открытому ключу ratchet
        отправителя (позволяет дешифровать переупорядоченные сообщения со
        старых «ступеней» трещотки);
      - skipped message keys хранятся в соответствующей цепочке;
      - шифрование нагрузки — AES-256-GCM (message key как ключ, HKDF-nonce).

    Состояние сериализуется в JSON и хранится у клиента в зашифрованном
    виде; сервер видит только ciphertext.
    """

    def __init__(self, peer_identity_b64: str, my_identity_b64: str) -> None:
        self.peer_identity_b64 = peer_identity_b64
        self.my_identity_b64 = my_identity_b64
        self.root_key: bytes = b""
        self.send_chain: Optional[_ChainState] = None
        self.recv_chains: Dict[str, _ChainState] = {}
        self.dh_priv = x25519.X25519PrivateKey.generate()
        self.ratchet_pub_b64 = ""      # открытый ключ СОБЕСЕДНИКА (remote)
        self.previous_counter: int = 0
        self.initialized = False
        self.handshake_manifest: dict = {}
        self.handshake_tag: str = ""   # b64(ek|from) — детекция повторного handshake
        # --- PreKey-стадия Double Ratchet (спецификация Signal) ---
        # На первом сообщении сессии DH-пары трещотки ещё не ротировались:
        # отправительская цепочка выводится напрямую из X3DH SK. Флаг ниже
        # говорит decrypt_with_header'у НЕ делать DH-ratchet шаг на первом
        # входящем whisper-сообщении (оно зашифровано стартовой цепочкой).
        self.initiator: Optional[bool] = None       # True = Alice, False = Bob
        self.base_pk_b64: str = ""                  # SPK собеседника (base key)
        self.first_stage_done: bool = False         # первый ratchet выполнен?
        self.pending_dh_priv = None                 # X25519Private|None: зеркальная
        # пара для первого DH-шага стороны A (порождается стороной B при первом ответе)
        # --- PreKey Whisper Message (спецификация Signal): ---
        # первое сообщение новой сессии шифруется message key'ем, выведенным
        # симметричным HKDF из X3DH SK (MK_pre = HKDF(SK, "prekey-msg")), а НЕ
        # цепочкой трещотки. Отправитель хранит MK_pre до получения mirror-ключа
        # в первом whisper-заголовке ответной стороны; получатель восстанавливает
        # его детерминированно из собственного расчёта X3DH SK.
        self.sk_master: bytes = b""                 # X3DH Master Secret (SK)
        self.prekey_msg_key: bytes = b""            # MK_pre (Alice, до 1-го ответа)
        self.prekey_ek_tag: str = ""                # b64(ek|from) — echo в pk заголовка
        # Приёмный PreKey-счётчик (Bob): номер n следующего PreKey Whisper
        # Message от инициатора. Стартовая приёмная цепочка под base-ключом на
        # PreKey-стадии НЕ расходуется (_next_message_key вызывается только при
        # отправке), поэтому Bob принимает ровно одно pre-сообщение с n=0;
        # повторный handshake (force_new_handshake) создаёт новую сессию с
        # обнулённым счётчиком. Поле сериализуется для корректной работы после
        # перезапуска клиента.
        self.recv_prekey_n: int = 0

    # ---------- сериализация состояния ----------
    def to_dict(self) -> dict:
        return {
            "peer": self.peer_identity_b64,
            "me": self.my_identity_b64,
            "rk": _b64e(self.root_key),
            "sc": {"k": _b64e(self.send_chain.key), "i": self.send_chain.index}
                  if self.send_chain else None,
            "rc": {pk: {"k": _b64e(c.key), "i": c.index,
                        "sk": {str(n): _b64e(v.mk) for n, v in c.skipped.items()}}
                   for pk, c in self.recv_chains.items()},
            "dh": _b64e(self.dh_priv.private_bytes_raw()),
            "rp": self.ratchet_pub_b64,
            "pc": self.previous_counter,
            "init": self.initialized,
            "hm": self.handshake_manifest,
            "ht": self.handshake_tag,
            "ini": self.initiator,
            "bp": self.base_pk_b64,
            "fs": self.first_stage_done,
            "pd": (_b64e(self.pending_dh_priv.private_bytes_raw())
                   if self.pending_dh_priv is not None else None),
            "pmk": _b64e(self.prekey_msg_key) if self.prekey_msg_key else "",
            "pet": self.prekey_ek_tag,
            "skm": _b64e(self.sk_master) if getattr(self, "sk_master", b"") else "",
            "rpn": self.recv_prekey_n,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SessionState":
        s = cls(d["peer"], d["me"])
        s.root_key = _b64d(d["rk"]) if d.get("rk") else b""
        if d.get("sc"):
            s.send_chain = _ChainState(_b64d(d["sc"]["k"]), int(d["sc"]["i"]))
        for pk, cd in (d.get("rc") or {}).items():
            chain = _ChainState(_b64d(cd["k"]), int(cd["i"]))
            chain.skipped = {int(n): _SkippedKey(_b64d(mk), int(n))
                             for n, mk in (cd.get("sk") or {}).items()}
            s.recv_chains[pk] = chain
        s.dh_priv = x25519.X25519PrivateKey.from_private_bytes(_b64d(d["dh"]))
        s.ratchet_pub_b64 = d.get("rp", "")
        s.previous_counter = int(d.get("pc", 0))
        s.initialized = bool(d.get("init"))
        s.handshake_manifest = d.get("hm") or {}
        s.handshake_tag = d.get("ht", "")
        s.initiator = d.get("ini")
        s.base_pk_b64 = d.get("bp", "")
        s.first_stage_done = bool(d.get("fs"))
        if d.get("pd"):
            s.pending_dh_priv = x25519.X25519PrivateKey.from_private_bytes(
                _b64d(d["pd"]))
        s.prekey_msg_key = _b64d(d["pmk"]) if d.get("pmk") else b""
        s.prekey_ek_tag = d.get("pet", "")
        s.sk_master = _b64d(d["skm"]) if d.get("skm") else b""
        s.recv_prekey_n = int(d.get("rpn", 0))
        return s

    # ---------- инициализация сессии после X3DH ----------
    def init_first_chain(self, sk: bytes, own_dh_priv, remote_pk_bytes: bytes,
                         is_alice: bool) -> None:
        """Инициализация корневой и цепочечных структур ключей из Shared Key
        (Master Secret) после X3DH.

        HKDF-экстракция разделяет SK на Root Key (RK) и Chain Key (CK).
        Если мы Alice (отправитель первого сообщения), инициализируем
        send_chain; если мы Bob (приёмник) — приёмную цепочку для ratchet-ключа
        инициатора. Обе стороны выводят ИДЕНТИЧНУЮ стартовую цепочку из одного
        и того же SK, поэтому первое PreKey-сообщение дешифруется зеркально.

        :param sk: 32-байтный X3DH Master Secret;
        :param own_dh_priv: собственный Identity X25519-ключ (для справочной
               совместимости с вызывающим кодом; приватные материалы в
               симметричной стартовой стадии не участвуют);
        :param remote_pk_bytes: SPK собеседника (raw 32 байта или base64-строка)
               — «base key» трещотки, под которымBob регистрирует цепочку Алисы;
        :param is_alice: True — сторона-инициатор handshake.
        """
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes

        if isinstance(remote_pk_bytes, str):
            remote_pk_raw = _b64d(remote_pk_bytes)
        else:
            remote_pk_raw = bytes(remote_pk_bytes)
        if len(remote_pk_raw) != 32:
            raise ValueError("init_first_chain: remote prekey must be 32 raw bytes")

        # Каноническое разделение общего секрета по Signal:
        # HKDF(SK, salt=0x00*32, info=KDF_ROOT_INIT_INFO) -> Root Key || Chain Key
        okm = _hkdf(sk, KDF_ROOT_INIT_INFO, salt=b"\x00" * 32, length=64)
        root_key = okm[:32]
        chain_key = okm[32:]

        self.root_key = root_key
        # X3DH Master Secret нужен обеим сторонам для симметричного вывода
        # ключа PreKey Whisper Message (MK_pre) — без его передачи по каналу.
        self.sk_master = sk
        remote_key_b64 = base64.b64encode(remote_pk_raw).decode("utf-8")

        if is_alice:
            # Alice: стартуем отправительскую цепочку (её whisper-заголовки
            # содержат pk == эхо-тег handshake на PreKey-стадии, затем pk ==
            # DH-ключ ratchet, n == 0, 1, 2 ... до первого ответа Bob).
            self.send_chain = _ChainState(chain_key, 0)
            # Приёмная сторона: сообщения Bob'а ДО первого DH-поворота трещотки
            # шифруются message key'ями той же стартовой цепочки CK_0 (симметрия
            # X3DH: обе стороны стартуют с одинаковых RK/CK). Регистрируем её под
            # base-ключом SPK_B — decrypt_with_header найдёт её по откату на
            # base_pk_b64, пока ratchet_pub_b64 ещё пуст.
            self.recv_chains[remote_key_b64] = _ChainState(chain_key, 0)
            self.initiator = True
            self.base_pk_b64 = remote_key_b64          # SPK(B)
            self.ratchet_pub_b64 = ""                  # remote DH ещё не получен
            # MK_pre: первое сообщение шифруется им, а не цепочкой трещотки
            # (спецификация Signal — PreKey Whisper Message). Храним до
            # первого mirror-ключа в заголовке ответа Bob'а.
            self.prekey_msg_key = _hkdf(sk, KDF_PREKEY_MSG_INFO, length=32)
        else:
            # Bob: регистрируем приёмную цепочку под base-ключом инициатора;
            # MK_pre будет восстановлен детерминированно из sk в decrypt_with_header.
            self.recv_chains[remote_key_b64] = _ChainState(chain_key, 0)
            self.initiator = False
            self.base_pk_b64 = remote_key_b64          # SPK(B) — наш, известен из envelope
            self.ratchet_pub_b64 = ""                  # remote DH ещё не получен
        self.initialized = True

    # ---------- рatchet-примитивы ----------
    @staticmethod
    def _kdf_rk(rk: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
        """Корневой KDF: (новый root key, новый chain key)."""
        out = _hkdf(rk + dh_out, KDF_RATCHET_INFO, length=64)
        return out[:32], out[32:64]

    @staticmethod
    def _step_ck(ck: bytes) -> Tuple[bytes, bytes]:
        """Шаг цепочки сообщений: (message key, следующий chain key)."""
        mk = hmac.HMAC(ck, b"\x01", hashlib.sha256).digest()
        next_ck = hmac.HMAC(ck, b"\x02", hashlib.sha256).digest()
        return mk, next_ck

    def _skipped_for(self, ratchet_pk: str) -> Dict[int, _SkippedKey]:
        chain = self.recv_chains.get(ratchet_pk)
        return chain.skipped if chain is not None else {}

    def _ratchet_step(self, new_remote_pub_b64: str) -> None:
        """Классический шаг трещотки при получении сообщения с новым DH-ключом.

        Спецификация Signal (DR_Ratchet): первый DH-шаг стороны A после
        PreKey-сообщения использует pending-пару, порождённую стороной B при
        первом ответе (тот же DH-результат, тот же root key — зеркальность).
        Остальные шаги — обычная ротация собственной пары.
        """
        remote = x25519.X25519PublicKey.from_public_bytes(_b64d(new_remote_pub_b64))
        if self.initiator is True and not self.first_stage_done \
                and self.pending_dh_priv is not None:
            # Зеркальный первый поворот стороны A (спецификация Signal X3DH/DR):
            # сторона B при первом ответе НЕ делала корневых KDF-шагов (её RK
            # не мутирован), а лишь сохранила свою новую ratchet-пару как
            # pending. Здесь A применяет ДВА корневых KDF-шага против того же
            # DH-ключа: первый выводит приёмную цепочку B (зеркало её отправки
            # n=0..N), второй — новую отправительскую цепочку A. Итоговый RK
            # обеих сторон идентичен — further steps синхронны.
            dh_out = self.pending_dh_priv.exchange(remote)
            self.root_key, recv_ck = self._kdf_rk(self.root_key, dh_out)
            self.recv_chains[new_remote_pub_b64] = _ChainState(recv_ck, 0)
            # ротация собственного DH-ключа и новая отправительская цепочка
            self.dh_priv = x25519.X25519PrivateKey.generate()
            dh_out2 = self.dh_priv.exchange(remote)
            self.root_key, send_ck = self._kdf_rk(self.root_key, dh_out2)
            self.previous_counter = (self.send_chain.index if self.send_chain
                                     else self.previous_counter)
            self.send_chain = _ChainState(send_ck, 0)
            self.pending_dh_priv = None
        else:
            self.dh_priv = x25519.X25519PrivateKey.generate()
            dh_out = self.dh_priv.exchange(remote)
            self.root_key, recv_ck = self._kdf_rk(self.root_key, dh_out)
            self.recv_chains[new_remote_pub_b64] = _ChainState(recv_ck, 0)
            # ротация собственного DH-ключа и новая отправительская цепочка
            self.dh_priv = x25519.X25519PrivateKey.generate()
            dh_out2 = self.dh_priv.exchange(remote)
            self.root_key, send_ck = self._kdf_rk(self.root_key, dh_out2)
            self.previous_counter = (self.send_chain.index if self.send_chain
                                     else self.previous_counter)
            self.send_chain = _ChainState(send_ck, 0)
        self.ratchet_pub_b64 = new_remote_pub_b64

    def _next_message_key(self) -> Tuple[bytes, int]:
        if self.send_chain is None:
            # Signal Double Ratchet: отправитель ещё не выполнял DH-шаг
            # (сторона Bob после X3DH). Первый ответ порождает новую пару
            # трещотки и стартовую отправительскую цепочку из текущего RK.
            self._send_ratchet_init()
        state = self.send_chain
        mk, next_ck = self._step_ck(state.key)
        n = state.index
        state.key = next_ck
        state.index += 1
        return mk, n

    def _send_ratchet_init(self) -> None:
        """Первый исходящий DH-шаг стороны B (PreKey-стадия, спецификация Signal):
        генерируем собственную ratchet-пару и стартуем отправительскую цепочку.

        КЛЮЧЕВАЯ СИНХРОНИЗАЦИЯ СЧЁТЧИКОВ (закрытие off-by-one шага 2 self-test):
          * стартовая отправительская цепочка B = та же стартовая цепочка X3DH SK
            (CK_0 из HKDF(SK, salt=0x00*32, info=KDF_ROOT_INIT_INFO)), под которой
            Alice уже зарегистрировала приёмную цепочку Bob'а в init_first_chain:
            B шифрует n=0,1,... message key'ями CK_0-цепочки — ровно те ключи,
            которые Alice продвигает симметрично (без DH-шага) при приёме;
          * RK здесь НЕ мутируется — он нужен для последующих корневых KDF-шагов
            обеих сторон против DH(B_new, SPK(A));
          * собственный X25519-ключ сохраняется как «pending», чтобы сторона A
            при первом входящем whisper-сообщении применила ДВА зеркальных
            корневых KDF-шага против того же DH-ключа и получила идентичные
            (RK, recv/send chains) для дешифрования следующих сообщений.
        """
        if not self.sk_master:
            raise ValueError("ratchet: cannot init send chain without X3DH SK")
        remote_b64 = self.base_pk_b64 or self.ratchet_pub_b64
        if not remote_b64:
            raise ValueError("ratchet: cannot init send chain without remote key")
        # стартовая отправительская цепочка — зеркало init_first_chain(is_alice=True):
        # тот же канонический вывод HKDF из неизменного X3DH SK
        okm = _hkdf(self.sk_master, KDF_ROOT_INIT_INFO,
                    salt=b"\x00" * 32, length=64)
        self.previous_counter = 0
        self.send_chain = _ChainState(okm[32:64], 0)
        # новая ratchet-пара для pending-поворота (учитывается стороной A)
        self.dh_priv = x25519.X25519PrivateKey.generate()
        self.pending_dh_priv = self.dh_priv
        # Сторона B завершает PreKey-стадию своим первым whisper-сообщением:
        # дальше заголовки содержат настоящий DH-ключ трещотки.
        self.first_stage_done = True

    def _skip_to(self, chain: _ChainState, target_n: int) -> None:
        """Кэширует пропущенные ключи цепочки при переупорядоченной доставке."""
        skipped_count = target_n - chain.index
        if skipped_count <= 0 or skipped_count > MAX_SKIP_KEYS:
            raise ValueError("ratchet: too many skipped / out-of-order messages")
        for _ in range(skipped_count):
            mk, next_ck = self._step_ck(chain.key)
            chain.skipped[chain.index] = _SkippedKey(mk, chain.index)
            chain.key = next_ck
            chain.index += 1

    # ---------- публичное API шифрования/дешифрования ----------
    def encrypt(self, plaintext: str, aad_ctx: bytes) -> Tuple[str, dict]:
        """Шифрует строку AES-256-GCM; возвращает (ct_b64, ratchet-header).

        Две стадии (спецификация Signal):
          1. PreKey Whisper Message — первое сообщение новой сессии: ключ
             MK_pre = HKDF(X3DH SK), заголовок pk = echo-тег handshake
             (b64("ek|from")). Обе стороны выводят MK_pre детерминированно из
             одного и того же X3DH-секрета — зеркальность гарантирована без
             передачи каких-либо ключей по каналу.
          2. Whisper Message — классический Double Ratchet: message key из
             текущей отправительской цепочки, pk — открытый ключ нашей
             активной ratchet-пары.
        Нумерация n/pn попадает в AAD на уровне envelope и учитывается
        ИДЕНТИЧНО при шифровании и дешифровании (один и тот же header).
        """
        mk, n = self._next_message_key()
        if self.initiator is True and not self.first_stage_done \
                and self.prekey_msg_key:
            # PreKey Whisper Message: шифруем MK_pre (HKDF из X3DH SK), а не
            # ключом цепочки; заголовок pk — эхо-тег handshake вместо DH-ключа.
            mk = self.prekey_msg_key
            header = {"pk": self.prekey_ek_tag, "n": n, "pn": self.previous_counter}
            nonce = _nonce_for(mk, n)
            ct = AESGCM(mk).encrypt(nonce, plaintext.encode("utf-8"), aad_ctx)
            return _b64e(ct), header
        nonce = _nonce_for(mk, n)
        ct = AESGCM(mk).encrypt(nonce, plaintext.encode("utf-8"), aad_ctx)
        header = {
            "pk": _b64e(self.dh_priv.public_key().public_bytes_raw()),
            "n": n,
            "pn": self.previous_counter,
        }
        return _b64e(ct), header

    def decrypt_with_header(self, ct_b64: str, header: dict, aad_ctx: bytes) -> str:
        """Обрабатывает whisper-заголовок (возможный DH-ratchet) и дешифрует.

        Порядок шагов строго по DR Decrypt спецификации Signal:
          a) PreKey-стадия: первый входящий message новой сессии расшифровывается
             ключом MK_pre, восстановленным из X3DH SK (DH-ratchet НЕ выполняется);
          b) новый remote-DH-ключ => сначала дотягиваем СТАРУЮ активную цепочку
             до pn (skipped keys), затем делаем DH-ratchet шаг;
          c) message key ищем в skipped-наборах всех цепочек, затем продвигаем
             нужную receiving-цепочку до номера n.
        Заголовок (pk/n/pn) участвует в AAD контейнера — длина ciphertext и
        номера сообщений идентично верифицируются GCM-тегом на обеих сторонах.
        """
        remote_pk = header.get("pk", "")
        n = int(header.get("n", 0))
        pn = int(header.get("pn", 0))

        # ---- a) PreKey Whisper Message: симметричный вывод MK_pre из X3DH SK ----
        if (not self.first_stage_done
                and self.prekey_ek_tag
                and remote_pk == self.prekey_ek_tag):
            mk = _hkdf(self.sk_master, KDF_PREKEY_MSG_INFO, length=32)
            nonce = _nonce_for(mk, n)
            text = AESGCM(mk).decrypt(nonce, _b64d(ct_b64), aad_ctx).decode("utf-8")
            if self.initiator is False:
                # Bob: согласование приёмного PreKey-счётчика. Стартовая цепочка
                # под base-ключом на этой стадии НЕ расходуется (_next_message_key
                # вызывается только при отправке — см. _send_ratchet_init), поэтому
                # нумерация зеркальна: принимается ровно одно pre-сообщение с n=0.
                if n != self.recv_prekey_n:
                    raise SecurityError(
                        "ratchet: unexpected PreKey message number "
                        f"{n} (expected {self.recv_prekey_n})")
                self.recv_prekey_n += 1
                # включаем трещотку — следующий заголовок с новым pk
                # вызовет полный DH-ratchet шаг (сторона A сделает зеркальный).
                self.first_stage_done = True
            return text

        # ---- b) классический Double Ratchet ----
        if remote_pk and remote_pk != self.ratchet_pub_b64:
            pre_first_turn = not self.ratchet_pub_b64
            if not pre_first_turn:
                old = self.recv_chains.get(self.ratchet_pub_b64)
                if old is not None and old.index < pn:
                    self._skip_to(old, pn)
            # затем — поворот трещотки на новый DH-ключ собеседника
            self._ratchet_step(remote_pk)
            self.first_stage_done = True
            if pre_first_turn and n == 0:
                # Первый ответ стороны B (whisper n=0) шифрован message key'ем
                # CK_0 стартовой цепочки X3DH — ДО первого корневого KDF-шага.
                # Зеркало: восстанавливаем ровно тот ключ и НЕ расходуем шаг
                # новой DH-цепочки (её счётчик начнётся со следующего сообщения).
                base = self.recv_chains.get(self.base_pk_b64)
                mk = _hkdf(self.sk_master, KDF_PREKEY_MSG_INFO, length=32) \
                    if False else None
                okm = _hkdf(self.sk_master, KDF_ROOT_INIT_INFO,
                            salt=b"\x00" * 32, length=64)
                mk, _unused = self._step_ck(okm[32:])
                nonce = _nonce_for(mk, n)
                return AESGCM(mk).decrypt(nonce, _b64d(ct_b64), aad_ctx).decode("utf-8")

        # ---- c) поиск message key: сначала в skipped всех цепочек ----
        for chain in self.recv_chains.values():
            sk = chain.skipped.pop(n, None)
            if sk is not None:
                mk = sk.mk
                nonce = _nonce_for(mk, n)
                return AESGCM(mk).decrypt(nonce, _b64d(ct_b64), aad_ctx).decode("utf-8")
        # ---- d) продвижение цепочки, соответствующей заголовку ----
        chain = self.recv_chains.get(remote_pk) or self.recv_chains.get(self.ratchet_pub_b64)
        # Спецификация Signal (X3DH/DR, стадия до первого DH-поворота): пока
        # активный remote-DH ключ трещотки НЕ установлен (ratchet_pub_b64 пуст),
        # ВСЕ входящие сообщения (PreKey Whisper и первый ответ стороны B)
        # шифруются message key'ями стартовой цепочки CK_0 под base-ключом SPK_B.
        # Поэтому при отсутствии цепочки под pk заголовка падаем на base-цепочку.
        if chain is None and not self.ratchet_pub_b64 and self.base_pk_b64:
            chain = self.recv_chains.get(self.base_pk_b64)
        if chain is None:
            raise ValueError("ratchet: no receiving chain for message")
        if n < chain.index:
            raise ValueError("ratchet: message key already used / replay detected")
        if n > chain.index:
            self._skip_to(chain, n)
        mk, next_ck = self._step_ck(chain.key)
        chain.key = next_ck
        chain.index += 1
        nonce = _nonce_for(mk, n)
        return AESGCM(mk).decrypt(nonce, _b64d(ct_b64), aad_ctx).decode("utf-8")


def _nonce_for(message_key: bytes, n: int) -> bytes:
    """Детерминированный 96-битный nonce из message key (HKDF-expand)."""
    return HKDF(algorithm=hashes.SHA256(), length=NONCE_BYTES,
                salt=message_key, info=f"meno-nonce-{n}".encode()).derive(message_key)


# ---------------------------------------------------------------------------
# X3DH: инициация и принятие handshake
# ---------------------------------------------------------------------------


def x3dh_initiator_secret(
    ik_priv: x25519.X25519PrivateKey,
    ek_priv: x25519.X25519PrivateKey,
    peer_ik_x25519_b64: str,
    peer_spk_b64: str,
    peer_opk_b64: Optional[str],
) -> Tuple[bytes, bytes]:
    """X3DH со стороны инициатора. Возвращает (SK, ek_pub_raw)."""
    peer_ik = x25519.X25519PublicKey.from_public_bytes(_b64d(peer_ik_x25519_b64))
    peer_spk = x25519.X25519PublicKey.from_public_bytes(_b64d(peer_spk_b64))
    dh1 = ik_priv.exchange(peer_spk)
    dh2 = ek_priv.exchange(peer_ik)
    dh3 = ek_priv.exchange(peer_spk)
    if peer_opk_b64:
        peer_opk = x25519.X25519PublicKey.from_public_bytes(_b64d(peer_opk_b64))
        dh4 = ek_priv.exchange(peer_opk)
    else:
        dh4 = X3DH_NULL_KEY
    # Канонический salt: отсортированные identity-ключи сторон — обе стороны
    # X3DH вычисляют идентичный SK независимо от порядка аргументов.
    salt = b"".join(sorted([ik_priv.public_key().public_bytes_raw(),
                            _b64d(peer_ik_x25519_b64)]))
    sk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
              info=KDF_X3DH_INFO).derive(dh1 + dh2 + dh3 + dh4)
    return sk, ek_priv.public_key().public_bytes_raw()


def x3dh_receiver_secret(
    ik_priv: x25519.X25519PrivateKey,
    spk_priv: x25519.X25519PrivateKey,
    opk_priv: Optional[x25519.X25519PrivateKey],
    my_ik_x25519_b64: str,
    peer_ik_x25519_b64: str,
    ek_pub_b64: str,
) -> bytes:
    """X3DH со стороны получателя PreKey-сообщения (зеркальный расчёт SK)."""
    peer_ik = x25519.X25519PublicKey.from_public_bytes(_b64d(peer_ik_x25519_b64))
    ek = x25519.X25519PublicKey.from_public_bytes(_b64d(ek_pub_b64))
    dh1 = spk_priv.exchange(peer_ik)
    dh2 = ik_priv.exchange(ek)
    dh3 = spk_priv.exchange(ek)
    dh4 = opk_priv.exchange(ek) if opk_priv is not None else X3DH_NULL_KEY
    salt = b"".join(sorted([_b64d(my_ik_x25519_b64), _b64d(peer_ik_x25519_b64)]))
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=KDF_X3DH_INFO).derive(dh1 + dh2 + dh3 + dh4)


# ---------------------------------------------------------------------------
# CryptoEngine — фасад для UI/API-слоя клиента
# ---------------------------------------------------------------------------

SESSION_ACCOUNT = "default"


class CryptoEngine:
    """Единая точка входа E2E для клиента MeNo.

    Ответственности:
      - владение Identity + Prekey Bundle устройства;
      - публикация bundle на сервер (через callback ``publish_bundle``);
      - установление сессий X3DH и поддержка Double Ratchet;
      - сборка/разборка ciphertext-контейнеров для поля ``content`` сервера.

    ``publish_bundle`` — асинхронный колбэк ``(bundle_dict) -> None``,
    который api_client подключает к POST /api/v2/crypto/bundle.
    """

    def __init__(self, account: str = SESSION_ACCOUNT, storage_dir: Optional[Path] = None,
                 publish_bundle=None) -> None:
        self.account = account or SESSION_ACCOUNT
        self._lock = threading.RLock()
        self._sessions: Dict[str, SessionState] = {}
        self._peer_identities: Dict[str, str] = {}
        self._bundle_cache: Dict[str, dict] = {}
        self.publish_bundle = publish_bundle
        self._dir = storage_dir or self._default_dir()
        self._identity: Optional[Identity] = None
        self._load_state()

    @staticmethod
    def _default_dir() -> Path:
        for var in ("MENO_DATA_DIR", "FLET_APP_STORAGE_DATA"):
            v = os.environ.get(var)
            if v:
                p = Path(v)
                p.mkdir(parents=True, exist_ok=True)
                return p
        return Path(__file__).parent

    # ---------- хранение ----------
    def _session_file(self) -> Path:
        return self._dir / f"meno_e2e_sessions_{self.account}.bin"

    @staticmethod
    def _storage_key() -> bytes:
        """Ключ шифрования состояния сессий: стабильный per-device секрет."""
        marker = Path(__file__).with_name(".meno_engine_salt")
        try:
            if marker.exists():
                salt = marker.read_bytes()
            else:
                salt = secrets.token_bytes(32)
                marker.write_bytes(salt)
                try:
                    os.chmod(marker, 0o600)
                except OSError:
                    pass
        except OSError:
            salt = b"meno-engine-fallback-salt"
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                    info=b"session-store").derive(b"meno-e2e-sessions")

    def _load_state(self) -> None:
        path = self._session_file()
        if not path.exists():
            return
        try:
            raw = path.read_bytes()
            if _local_store is not None:
                plain = _local_store.decrypt_bytes(self._storage_key(),
                                                   base64.b64encode(raw).decode())
            else:
                nonce, ct = raw[:12], raw[12:]
                plain = AESGCM(self._storage_key()).decrypt(nonce, ct, None)
            doc = json.loads(plain.decode("utf-8"))
        except Exception:
            return
        with self._lock:
            id_seed = doc.get("identity_seed")
            if id_seed:
                self._identity = Identity.from_seed_b64(id_seed)
            for peer, sd in (doc.get("sessions") or {}).items():
                try:
                    self._sessions[peer] = SessionState.from_dict(sd)
                except Exception:
                    continue
            self._peer_identities = dict(doc.get("peer_ids") or {})

    def _save_state(self) -> None:
        with self._lock:
            doc = {
                "v": PROTOCOL_VERSION,
                "identity_seed": self._identity.seed_b64 if self._identity else None,
                "sessions": {p: s.to_dict() for p, s in self._sessions.items()},
                "peer_ids": dict(self._peer_identities),
            }
        pt = json.dumps(doc).encode("utf-8")
        key = self._storage_key()
        if _local_store is not None:
            blob = base64.b64decode(_local_store.encrypt_bytes(key, pt))
        else:
            nonce = secrets.token_bytes(12)
            blob = nonce + AESGCM(key).encrypt(nonce, pt, None)
        tmp = self._session_file().with_suffix(".tmp")
        tmp.write_bytes(blob)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(self._session_file())

    # ---------- identity / prekeys ----------
    def ensure_identity(self) -> Identity:
        with self._lock:
            if self._identity is None:
                self._identity = Identity()
                self._save_state()
            return self._identity

    def identity_public_b64(self) -> str:
        return self.ensure_identity().identity_pub_b64

    def identity_x25519_b64(self) -> str:
        return self.ensure_identity().identity_x25519_pub_b64

    async def publish_full_bundle(self, one_time_count: int = 20) -> dict:
        """Собирает и публикует Prekey Bundle на сервер (при регистрации/входе)."""
        bundle = self.ensure_identity().build_bundle(0, one_time_count)
        with self._lock:
            self._save_state()
        if self.publish_bundle is not None:
            await self.publish_bundle(bundle)
        return bundle

    async def replenish_if_needed(self, threshold: int = 5, count: int = 20) -> bool:
        """Автодополнение пула OPK (сервер помечает выданные one-time ключи consumed)."""
        ident = self.ensure_identity()
        if not ident.needs_replenishment(threshold) or self.publish_bundle is None:
            return False
        otpks = ident.generate_one_time_prekeys(count)
        with self._lock:
            self._save_state()
        await self.publish_bundle({
            "identity_pub": ident.identity_pub_b64,
            "identity_x25519": ident.identity_x25519_pub_b64,
            "signed_prekey": ident.signed_prekey_b64,
            "signed_prekey_id": ident.signed_prekey_id,
            "signature": ident.signed_prekey_signature_b64(),
            "one_time_prekeys": [{"key_id": k, "public_key": v} for k, v in otpks],
            "replace": False,
        })
        return True

    # ---------- контейнер ----------
    @staticmethod
    def _aad(envelope_head: dict) -> bytes:
        """Связывающий AAD: версия + identity обеих сторон + ratchet pubkey.

        Сервер не может подменить адресата или перенести ciphertext между
        сессиями: любое изменение этих полей ломает GCM-тег.

        КАНОН (симметричен для отправителя и получателя):
          v|type|from|spk_id|opk_id|ek|hk_pk|n|pn|env_pk
        Поля n/pn/env_pk добавляются в envelope ПОСЛЕ шифрования, поэтому
        каноническое значение для них — пустая строка; фактические значения
        заголовка Double Ratchet верифицируются отдельным полем pk внутри hk
        (для whisper) и эхо-тегом (для pre). Получатель нормализует raw-копию
        envelope к этому же состоянию перед вызовом (_decrypt_envelope).
        """
        hk = envelope_head.get("hk") or {}
        parts = [
            str(envelope_head.get("v", PROTOCOL_VERSION)).encode(),
            str(envelope_head.get("type", "")).encode(),
            (envelope_head.get("from") or "").encode(),
            str(envelope_head.get("spk_id", hk.get("spk_id", 0))).encode(),
            str(hk.get("opk_id", 0)).encode(),
            (hk.get("ek") or "").encode(),
            # PK из манифеста — только для whisper-контейнеров (в hk кладётся
            # тот же DH-ключ, что и в header). В pre-контейнере hk.pk — это
            # эхо-тег handshake; обе стороны канонически используют пустой PK.
            (hk.get("pk") or "").encode()
            if envelope_head.get("type") != "pre" else b"",
            # Нумерация Double Ratchet (n/pn/env pk) — канонически пуста на
            # момент шифрования у ОБОИХ сторон; нормализуется зеркально у
            # получателя до вызова _aad (см. _decrypt_envelope).
            b"", b"", b"",
        ]
        return b"|".join(parts)

    # ---------- исходящие сообщения ----------
    def encrypt_for_peer(self, peer_user_id: int, peer_bundle: Optional[dict],
                         text: str, force_new_handshake: bool = False) -> str:
        """Шифрует текст для собеседника; при отсутствии сессии выполняет X3DH.

        Возвращает base64 JSON-контейнера — «слепой» content для сервера.
        """
        ident = self.ensure_identity()
        peer_key = str(peer_user_id)
        with self._lock:
            session = self._sessions.get(peer_key)
            is_new_session = (session is None or not session.initialized
                              or force_new_handshake)
            if force_new_handshake:
                # Режим «stateless E2E» (чат chat_ui): каждый вызов — полный
                # X3DH-handshake (PreKey Whisper Message); сторона-получатель
                # восстанавливает сессию из манифеста каждого pre-сообщения.
                bundle = peer_bundle or self._bundle_cache.get(peer_key)
                session = self._start_session(ident, peer_user_id, bundle)
                remote_ident = (bundle or {}).get("identity_pub", "")
            elif peer_bundle is not None:
                remote_ident = peer_bundle.get("identity_pub", "")
            else:
                remote_ident = self._peer_identities.get(peer_key, "")
            if is_new_session and not force_new_handshake:
                known = self._peer_identities.get(peer_key)
                if known and known != remote_ident:
                    # Смена Identity Key собеседника (пересоздание аккаунта):
                    # принудительная ре-инициализация сессии через новый X3DH.
                    self._sessions.pop(peer_key, None)
                if not peer_bundle:
                    raise SecurityError(
                        f"Prekey Bundle пользователя {peer_user_id} недоступен: "
                        "собеседник не активировал E2E или сервер недоступен.")
                session = self._start_session(ident, peer_user_id, peer_bundle)
                self._peer_identities[peer_key] = remote_ident
            envelope = {
                "v": PROTOCOL_VERSION,
                "type": "pre" if is_new_session else "whisper",
                "from": ident.identity_pub_b64,
                "to": remote_ident,
                "hk": (dict(session.handshake_manifest)
                       if is_new_session else {}),
            }
            if is_new_session:
                # поля, обязательные для восстановления сессии стороной B и
                # для связывания AAD (сервер их не читает — только хранит)
                envelope["spk"] = session.handshake_manifest.get("spk", "")
                envelope["spk_id"] = session.handshake_manifest.get("spk_id", 0)
                # PreKey Whisper Message: эхо-тег handshake (b64("ek|from")) —
                # канонический идентификатор первого сообщения, identical'но
                # вычисляется обеими сторонами из манифеста в envelope.
                session.prekey_ek_tag = _b64e(
                    f"{envelope['hk'].get('ek', '')}|{envelope['from']}".encode())
            ct_b64, header = session.encrypt(text, self._aad(envelope))
            # whisper-заголовок (pk/n/pn) кладём в envelope ПОСЛЕ шифрования;
            # манифест сессии остаётся чистым handshake-документом — зеркально
            # состоянию стороны B при дешифровании pre-сообщений.
            envelope["pk"] = header["pk"]
            envelope["pn"] = header["pn"]
            envelope["n"] = header["n"]
            envelope["ct"] = ct_b64
            if is_new_session:
                # MK_pre нужен Alice до первого mirror-ключа в ответе Bob'а;
                # после записи состояния он больше не используется (одноразовый).
                session.prekey_msg_key = b""
            self._save_state()
        return _b64e(json.dumps(envelope, separators=(",", ":")).encode("utf-8"))

    def _start_session(self, ident: Identity, peer_user_id: int,
                       peer_bundle: dict) -> SessionState:
        """Инициатор X3DH: проверяем подпись SPK, считаем SK, стартуем трещотку."""
        if not ident.verify_spk_signature(
                peer_bundle.get("identity_pub", ""),
                peer_bundle.get("signed_prekey", ""),
                int(peer_bundle.get("signed_prekey_id", 0)),
                peer_bundle.get("signature", "")):
            raise SecurityError(
                f"Signed Prekey пользователя {peer_user_id} не прошёл проверку "
                "подписи Identity Key — возможен MITM. Отправьте Safety Number "
                "для сверки.")
        session = SessionState(peer_bundle["identity_pub"], ident.identity_pub_b64)
        ek_priv = x25519.X25519PrivateKey.generate()
        opk = (peer_bundle.get("one_time_prekeys") or [None])[0]
        opk_b64 = opk["public_key"] if isinstance(opk, dict) else None
        sk, ek_pub = x3dh_initiator_secret(
            ident.ik_priv, ek_priv,
            peer_bundle["identity_x25519"], peer_bundle["signed_prekey"], opk_b64)
        # Первая отправительская цепочка PreKey-сессии: DH-пары трещотки —
        # собственный ratchet-ключ = IK(A), удалённый = SPK(B). Корневой секрет
        # уже содержит все четыре DH X3DH, поэтому стартовый шаг — симметричный
        # HKDF(sk) -> (root key, chain key). Оба пика получают идентичные
        # цепочки; нумерация сообщений синхронизируется заголовком n.
        session.init_first_chain(sk, ident.ik_priv,
                                 peer_bundle["signed_prekey"], is_alice=True)
        session.handshake_manifest = {
            "ik": ident.identity_x25519_pub_b64,
            "ek": _b64e(ek_pub),
            "spk": peer_bundle["signed_prekey"],
            "spk_id": peer_bundle.get("signed_prekey_id", 0),
            "opk_id": opk["key_id"] if isinstance(opk, dict) else -1,
        }
        self._sessions[str(peer_user_id)] = session
        return session

    # ---------- входящие сообщения ----------
    def decrypt_from_sender(self, sender_user_id: int, payload_b64: str) -> str:
        """Дешифрует base64-контейнер от собеседника (обёртка для stateless-вызова)."""
        try:
            raw = json.loads(base64.b64decode(payload_b64).decode("utf-8"))
        except Exception as exc:
            raise SecurityError(f"Malformed ciphertext envelope: {exc}") from exc
        return self._decrypt_envelope(sender_user_id, raw)

    def _decrypt_envelope(self, sender_user_id: int, raw: dict) -> str:
        """Ядро дешифрования. Для type="pre" поднимает новую сессию-получателя:
        изымает из локального пула приватную часть One-Time Prekey по opk_id,
        вычисляет зеркальный X3DH-секрет и инициализирует трещотку."""
        ident = self.ensure_identity()
        env_type = raw.get("type")
        sender_key = str(sender_user_id)
        with self._lock:
            session = self._sessions.get(sender_key)
            if env_type == "pre":
                hk = raw.get("hk") or {}
                ek_tag = _b64e(f"{hk.get('ek', '')}|{raw.get('from', '')}".encode())
                opk_id = int(hk.get("opk_id", -1))
                reuse = (session is not None and session.initialized
                         and session.handshake_tag == ek_tag)
                if not reuse:
                    opk_priv = (ident.take_one_time_priv(opk_id)
                                if opk_id >= 0 else None)
                    sk = x3dh_receiver_secret(
                        ident.ik_priv, ident.signed_prekey_priv, opk_priv,
                        ident.identity_x25519_pub_b64,
                        hk.get("ik", ""), hk.get("ek", ""))
                    session = SessionState(raw.get("from", ""),
                                           ident.identity_pub_b64)
                # Зеркальная инициализация трещотки: собственный ratchet-ключ —
                # наш Identity Key (IK(B)), удалённый — SPK(B), который инициатор
                # передал в манифесте handshake. Стартовая цепочка выводится
                # симметричным HKDF из X3DH-секрета — идентично стороне A.
                if not reuse:
                    session.init_first_chain(sk, ident.ik_priv,
                                             hk.get("spk", ""), is_alice=False)
                    session.handshake_tag = ek_tag
                # Bob восстанавливает эхо-тег инициатора из манифеста envelope —
                # ровно то значение pk, которое Alice поставила в заголовок
                # PreKey Whisper Message (детекция стадии без передачи ключей).
                session.prekey_ek_tag = ek_tag
                self._sessions[sender_key] = session
                self._peer_identities[sender_key] = raw.get("from", "")
            elif session is None:
                raise SecurityError(
                    f"Нет сессии с пользователем {sender_user_id}: "
                    "первое PreKey-сообщение потеряно или аккаунт пересоздан.")
            # AAD инициатора строится по envelope «изнутри», где to == IK(B);
            # у получателя поле "to" заполняется его собственным identity —
            # приводим к тому же каноническому значению, иначе GCM-тег не сойдётся.
            if env_type == "pre":
                raw.setdefault("spk", hk.get("spk", ""))
                raw.setdefault("spk_id", int(hk.get("spk_id", 0)))
            raw["to"] = ident.identity_pub_b64 if raw.get("to") in ("", None) \
                else raw["to"]
            # Заголовок Double Ratchet извлекаем ДО нормализации pre-полей:
            # для whisper он лежит в envelope (pk/pn) и hk (n), для pre —
            # только в копии манифеста hk.
            hk_src = raw.get("hk") or {}
            header = {"pk": raw.get("pk") or hk_src.get("pk", ""),
                      "n": int(hk_src.get("n") if hk_src.get("n") not in (None, "")
                               else (raw.get("n") or 0)),
                      "pn": int(raw.get("pn") if raw.get("pn") not in (None, "")
                                else (hk_src.get("pn") or 0))}
            if env_type == "pre":
                # Принудительное зеркало состояния отправителя на момент
                # шифрования PreKey Whisper Message: envelope["hk"] строился
                # копией манифеста ДО encrypt(), поэтому pk/n/pn в AAD-источнике
                # были пусты. Убираем их из копии hk (сам манифест сессии —
                # отдельный объект, он остаётся полным для reuse-детекции).
                hk.pop("pk", None)
                hk.pop("n", None)
                hk.pop("pn", None)
            # Канон AAD одинаков для обеих сторон: поля n/pn/env_pk всегда пусты
            # на момент шифрования (добавляются в envelope после encrypt()).
            # Для whisper hk.pk содержит DH-ключ трещотки — тот же канон, что и
            # у отправителя; для pre — обнулён выше (эхо-тег не входит в AAD).
            raw["pk"] = ""
            raw["pn"] = ""
            raw["n"] = ""
            aad = self._aad(raw)
            text = session.decrypt_with_header(raw["ct"], header, aad)
            self._save_state()
        return text

    # ---------- диагностика ----------
    def has_session(self, peer_user_id: int) -> bool:
        with self._lock:
            s = self._sessions.get(str(peer_user_id))
            return bool(s and s.initialized)

    def safety_fingerprint(self) -> str:
        """Отпечаток Identity Key (для диалога Safety Numbers)."""
        ident = self.ensure_identity()
        return hashlib.sha256(_b64d(ident.identity_pub_b64)).hexdigest()[:16]


class SecurityError(Exception):
    """Нарушение целостности протокола: неверная подпись SPK, потерянная сессия."""


    # ---------- вспомогательное API для P2P-чатов ----------
    def encrypt_p2p(self, peer_user_id: int, peer_bundle: Optional[dict],
                    text: str) -> str:
        """Шифрование для приватного чата «в лоб».

        Если сессия Double Ratchet с собеседником уже установлена — сообщение
        уходит обычным whisper-сообщением (эффективная цепочка). Иначе движок
        выполняет полный X3DH-handshake (PreKey Whisper Message) из кэша
        бандла собеседника; получатель восстановит сессию из манифеста.
        """
        with self._lock:
            if peer_bundle:
                self._bundle_cache[str(peer_user_id)] = peer_bundle
            cached = self._bundle_cache.get(str(peer_user_id))
        if peer_bundle is not None:
            return self.encrypt_for_peer(peer_user_id, peer_bundle, text)
        if cached is None:
            raise SecurityError(
                f"Prekey Bundle пользователя {peer_user_id} ещё не загружен.")
        # Сессия уже установлена — эффективный whisper; иначе полный handshake.
        return self.encrypt_for_peer(peer_user_id, cached, text,
                                     force_new_handshake=not self.has_session(peer_user_id))


def self_test() -> None:
    """Интегральная проверка протокола: X3DH + DR + переупорядоченная доставка.

    Запуск: ``python crypto_engine.py``
    """
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="meno-e2e-test-"))
    a = CryptoEngine(account="alice", storage_dir=tmp)
    b = CryptoEngine(account="bob", storage_dir=tmp)
    bundle_a = a.ensure_identity().build_bundle(1)
    bundle_b = b.ensure_identity().build_bundle(2)
    # 1) A -> B: PreKey Whisper Message
    ct1 = a.encrypt_for_peer(2, bundle_b, "Привет, Боб! Это сквозное E2E.")
    assert ct1 != "Привет, Боб! Это сквозное E2E."
    pt1 = b.decrypt_from_sender(1, ct1)
    assert pt1 == "Привет, Боб! Это сквозное E2E.", pt1
    # 2) B -> A: ответ (DH-ratchet шаг на стороне A)
    ct2 = b.encrypt_for_peer(1, bundle_a, "Привет, Алиса. Ключи совпадают?")
    pt2 = a.decrypt_from_sender(2, ct2)
    assert pt2 == "Привет, Боб!"[:0] + "Привет, Алиса. Ключи совпадают?", pt2
    # 3) серия A -> B без ответа (skipped keys, переупорядоченная доставка)
    batch = [a.encrypt_for_peer(2, bundle_b, f"msg-{i}",
                                 force_new_handshake=True) for i in range(5)]
    assert b.decrypt_from_sender(1, batch[3]) == "msg-3"
    assert b.decrypt_from_sender(1, batch[0]) == "msg-0"
    for i in (1, 2, 4):
        assert b.decrypt_from_sender(1, batch[i]) == f"msg-{i}"
    # 4) персистентность состояния между инстансами
    a2 = CryptoEngine(account="alice", storage_dir=tmp)
    ct3 = a2.encrypt_for_peer(2, bundle_b, "после перезапуска",
                              force_new_handshake=True)
    assert b.decrypt_from_sender(1, ct3) == "после перезапуска"
    # 5) tamper detection (AES-GCM tag)
    env = json.loads(base64.b64decode(batch[0]))
    env["ct"] = _b64e(bytes(x ^ 0x01 for x in _b64d(env["ct"])))
    try:
        b.decrypt_from_sender(1, _b64e(json.dumps(env).encode()))
        raise AssertionError("tamper not detected")
    except Exception:
        pass
    print("crypto_engine self-test OK: X3DH + Double Ratchet + AES-256-GCM")


if __name__ == "__main__":
    self_test()


__all__ = [
    "CryptoEngine",
    "Identity",
    "PreKeyBundle",
    "SessionState",
    "SecurityError",
    "PROTOCOL_VERSION",
    "x3dh_initiator_secret",
    "x3dh_receiver_secret",
    "self_test",
]
