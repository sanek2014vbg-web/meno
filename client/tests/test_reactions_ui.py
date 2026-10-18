"""Логические UI-тесты реакций (Микро-спринт 3, Часть 2 / Шаг 3.7).

Без GUI-рантайма Flet (в CI нет экрана): тестируем чистую бизнес-логику
модулей ui.message_model и контроллера ChatScreen из ui.message_area.

Покрываемые критические точки:
A. Roundtrip E2EE-реакций: encrypt_reaction_payload -> ванильный AES-GCM
   blob с префиксом ``rx1:``, decrypt_reaction_blob восстанавливает эмодзи;
   битый/чужой blob деградирует молча (None), а не роняет UI.
B. Дедупликация свайпа: повторный свайп по тому же сообщению внутри окна
   SWIPE_DEDUPE_SECONDS (0.8 c) не уходит в сеть — строго 1 POST.

Сетевые вызовы изолированы recording-стабом FakeApi (подмена _api_react);
crypto-хранилище настроек не читаем (build() не вызываем).
"""

from __future__ import annotations

import asyncio
import base64
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

# Клиентский пакет лежит в client/ — добавляем его в sys.path точечно,
# чтобы тесты работали и из корня репозитория, и из CI (паттерн
# test_auth_storage.py / test_client_ui_logic.py).
CLIENT_DIR = Path(__file__).resolve().parents[1]
if str(CLIENT_DIR) not in sys.path:
    sys.path.insert(0, str(CLIENT_DIR))

from ui import message_area  # noqa: E402
from ui.message_area import ChatScreen  # noqa: E402
from ui.message_model import (  # noqa: E402
    QUICK_REACTIONS,
    REACTION_BLOB_PREFIX,
    Message,
    MessageStatus,
    apply_reaction_summary,
    decrypt_reaction_blob,
    encrypt_reaction_payload,
)

MY_ID = 1
PEER_ID = 2
CHAT_KEY = b"\x11" * 32  # детерминированный 256-битный ключ чата для тестов


class DragEvent:
    """Минимальный дабл ft.DragEndEvent: нужен только local_x."""

    def __init__(self, local_x: float) -> None:
        self.local_x = local_x


class FakeApi:
    """Recording-стаб ApiClient: пишет каждый toggle-POST в .react_calls."""

    def __init__(self) -> None:
        self.react_calls: list[tuple[int, str]] = []

    async def toggle_reaction(self, message_id: int, payload: str) -> dict:
        self.react_calls.append((message_id, payload))
        return {"ok": True, "reactions": {}}


def make_screen() -> ChatScreen:
    """ChatScreen вне дерева страницы: page=None, api=FakeApi.

    build() не вызываем — свайп-логика работает только с моделями,
    e2e_key и _last_swipe_at; рантайм Flet не нужен.
    """
    app = SimpleNamespace(page=None, api=FakeApi(), me={"id": MY_ID}, chat={"id": 7})
    sc = ChatScreen(
        app,
        {
            "id": 7,
            "title": "Тест",
            "type": "private",
            "members": [{"id": MY_ID}, {"id": PEER_ID}],
        },
    )
    sc.e2e_key = CHAT_KEY
    return sc


def add_message(sc: ChatScreen, msg_id: int) -> Message:
    m = Message(
        id=msg_id,
        chat_id=7,
        sender_id=PEER_ID,
        text=f"m{msg_id}",
        status=MessageStatus.DELIVERED,
    )
    sc.messages.append(m)
    sc.index_by_id[m.id] = m
    return m


def swipe(
    sc: ChatScreen, m: Message, start_x: float = 10.0, end_x: float = 90.0
) -> None:
    """Имитирует полный жест drag_start -> drag_end со смещением > порога."""
    sc._begin_swipe(m, DragEvent(start_x))
    sc._end_swipe(m, DragEvent(end_x))


async def flush_tasks() -> None:
    """Даёт шанс ensure_future-задачам дойти до записи в FakeApi."""
    for _ in range(5):
        await asyncio.sleep(0)


# ---------------------------------------------------------------------------
# Сценарий A: roundtrip шифрования реакций (AES-GCM, префикс rx1:)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("emoji", QUICK_REACTIONS)
def test_reaction_payload_roundtrip(emoji: str) -> None:
    """Каждый эмодзи радар-меню проходит seal -> open без потерь."""
    blob = encrypt_reaction_payload(CHAT_KEY, emoji)
    assert blob.startswith(REACTION_BLOB_PREFIX)
    assert decrypt_reaction_blob(CHAT_KEY, blob) == emoji


def test_reaction_blob_is_opaque_to_server() -> None:
    """В тело blob'а не утекает ни сам эмодзи, ни его UTF-8 байты."""
    blob = encrypt_reaction_payload(CHAT_KEY, "👍")
    body = blob[len(REACTION_BLOB_PREFIX) :]
    decoded = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    assert "👍".encode() not in decoded
    assert "👍" not in decoded.decode(errors="replace")


def test_decrypt_requires_matching_key_and_prefix() -> None:
    """Чужой ключ, отсутствие ключа и мусор -> None (UI не падает)."""
    blob = encrypt_reaction_payload(CHAT_KEY, "❤️")
    assert decrypt_reaction_blob(b"\x22" * 32, blob) is None
    assert decrypt_reaction_blob(None, blob) is None
    assert decrypt_reaction_blob(CHAT_KEY, "не-наш-формат") is None
    assert decrypt_reaction_blob(CHAT_KEY, REACTION_BLOB_PREFIX + "%%%") is None


def test_apply_reaction_summary_decodes_blobs() -> None:
    """Серверный summary {blob: [users]} -> человекочитаемые реакции."""
    blob_a = encrypt_reaction_payload(CHAT_KEY, "😂")
    blob_junk = "rx1:" + base64.urlsafe_b64encode(b"broken").decode().rstrip("=")
    m = Message(id=1, chat_id=7, sender_id=PEER_ID, text="t", status=MessageStatus.READ)
    changed = apply_reaction_summary(
        m, {blob_a: [PEER_ID], blob_junk: [MY_ID]}, CHAT_KEY
    )
    assert changed is True
    assert m.reactions == {"😂": {PEER_ID}}  # битый blob проигнорирован
    # Повторное применение идемпотентно: изменений нет, перерисовка не нужна.
    assert apply_reaction_summary(m, {blob_a: [PEER_ID]}, CHAT_KEY) is False


# ---------------------------------------------------------------------------
# Сценарий B: дедупликация свайпа (анти-дребезг жеста, окно 0.8 c)
# ---------------------------------------------------------------------------


async def test_swipe_sends_exactly_one_post_within_dedupe_window() -> None:
    """Два быстрых свайпа подряд => ровно 1 POST за окно SWIPE_DEDUPE_SECONDS."""
    sc = make_screen()
    m = add_message(sc, 101)
    assert sc.SWIPE_DEDUPE_SECONDS == 0.8  # контракт из ТЗ

    swipe(sc, m)
    await flush_tasks()
    swipe(sc, m)  # мгновенный повтор — должен проглотить анти-дребезг
    await flush_tasks()

    calls = sc.app.api.react_calls
    assert len(calls) == 1
    msg_id, payload = calls[0]
    assert msg_id == 101
    assert decrypt_reaction_blob(CHAT_KEY, payload) == QUICK_REACTIONS[0]


async def test_swipe_allowed_again_after_dedupe_window(monkeypatch) -> None:
    """После истечения окна свайп снова работает (toggle-UX сохранён)."""
    sc = make_screen()
    m = add_message(sc, 102)

    swipe(sc, m)
    await flush_tasks()
    # Сдвигаем метку времени жеста за пределы окна, не дожидаясь реальных
    # 0.8 c: time.monotonic — единственные часы анти-дребезга в контроллере.
    real_now = message_area.time.monotonic()
    monkeypatch.setattr(message_area.time, "monotonic", lambda: real_now + 1_000.0)

    swipe(sc, m)
    await flush_tasks()
    assert len(sc.app.api.react_calls) == 2


async def test_micro_drag_is_not_a_gesture() -> None:
    """Смещение < SWIPE_MIN_DELTA_PX — случайный сдвиг пальца, не POST."""
    sc = make_screen()
    m = add_message(sc, 103)
    swipe(sc, m, start_x=10.0, end_x=10.0 + sc.SWIPE_MIN_DELTA_PX - 1)
    await flush_tasks()
    assert sc.app.api.react_calls == []


async def test_swipe_without_e2e_key_never_leaks_emoji() -> None:
    """Приватность важнее фичи: без ключа чата свайп не уходит в сеть."""
    sc = make_screen()
    sc.e2e_key = None
    m = add_message(sc, 104)
    swipe(sc, m)
    await flush_tasks()
    assert sc.app.api.react_calls == []
