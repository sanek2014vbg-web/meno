"""Логические UI-тесты клиента MeNo (микро-спринт 2, финальный шаг).

Тестируем бизнес-логику интерфейса БЕЗ GUI-рантайма Flet: в CI нет экрана,
поэтому ни один тест не создаёт ft.Page и не трогает real-объекты.

Покрываемые критические точки Этапа 7.3 («Живая галочка» + Ghost Mode):
1. Маппинг статуса -> иконка/цвет (чистые функции ui.message_model);
2. Монотонный merge next_status (запоздалые WS-события не откатывают статус);
3. O(1)-индексация сообщений (hash-таблицы index_by_id / rows_by_id) и
   перехват WS-события STATUS_UPDATE без линейного скана списка;
4. ACK-логика: delivered при доставке, read при просмотре, ghost=True из
   настройки «ghost_mode», клиентская дедупликация повторных ACK.

Изоляция: все сетевые вызовы идут через _api_* контроллера ChatScreen —
в тестах они подменяются recording-стабом FakeApi; crypto.get_setting
monkeypatch'ится (реальное хранилище настроек не читаем).
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

import flet as ft
import pytest

# Клиентский пакет лежит в client/ — добавляем его в sys.path точечно,
# чтобы тесты работали и из корня репозитория, и из CI (тот же паттерн,
# что в test_auth_storage.py).
CLIENT_DIR = Path(__file__).resolve().parents[1]
if str(CLIENT_DIR) not in sys.path:
    sys.path.insert(0, str(CLIENT_DIR))

import crypto  # noqa: E402
from ui import message_area  # noqa: E402
from ui.message_area import ChatScreen, MessageRow  # noqa: E402
from ui.message_model import (  # noqa: E402
    Message,
    MessageStatus,
    next_status,
    status_icon,
    status_icon_color,
)

MY_ID = 1
PEER_ID = 2
SUB_COLOR = "#94a3b8"
READ_COLOR = ft.Colors.BLUE


# ---------------------------------------------------------------------------
# Двойники и фикстуры
# ---------------------------------------------------------------------------


class FakeApi:
    """Recording-стаб ApiClient: пишет каждый PATCH статуса в .calls."""

    def __init__(self) -> None:
        self.calls: list[tuple[int, str, bool]] = []

    async def update_message_status(
        self, message_id: int, status: str, ghost: bool = False
    ) -> dict:
        self.calls.append((message_id, status, ghost))
        return {"ok": True, "changed": True, "status": status}


def make_message(msg_id: int, sender_id: int, status: MessageStatus) -> Message:
    return Message(
        id=msg_id, chat_id=7, sender_id=sender_id, text=f"m{msg_id}", status=status
    )


@pytest.fixture()
def screen(monkeypatch) -> ChatScreen:
    """ChatScreen с фейковым app: page=None, api=FakeApi, me={id: MY_ID}.

    Метод build() не вызываем — логика статусов/ACK/роутера WS работает
    только с моделями, индексом и rows_by_id, рантайм Flet не нужен.
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
    # Тема: sub-цвет берём из реального палитры контроллера (page=None ->
    # дефолтная тёмная тема themes), чтобы ассерты цветов были честными.
    sc.sub_color = sc.c["sub"]
    # Настройки приложения — детерминированный dict вместо crypto-хранилища.
    settings: dict[str, object] = {"ghost_mode": False}
    monkeypatch.setattr(
        crypto, "get_setting", lambda key, default=None: settings.get(key, default)
    )
    sc.test_settings = settings  # доступ для тестов Ghost Mode
    return sc


def attach_outgoing_row(
    sc: ChatScreen, msg_id: int, status: MessageStatus = MessageStatus.SENT
) -> MessageRow:
    """Регистрирует исходящее сообщение в индексах + рисует MessageRow.

    Ряд существует вне дерева страницы (page=None) — это ожидаемо:
    update_status_ui ловит отвязку контрола и обновляет модель/иконку
    локально (деградация без падения, ровно как при закрытом экране чата).
    """
    m = make_message(msg_id, MY_ID, status)
    sc.messages.append(m)
    sc.index_by_id[m.id] = m
    row = sc._bubble(m)
    assert sc.rows_by_id[m.id] is row
    return row


# ---------------------------------------------------------------------------
# 1. Маппинг «Живой галочки»: статус -> имя иконки и цвет
# ---------------------------------------------------------------------------


def test_live_tick_icon_mapping():
    """sent -> CHECK (одна), delivered/read -> DONE_ALL (две)."""
    assert status_icon(MessageStatus.SENT) == ft.Icons.CHECK
    assert status_icon(MessageStatus.DELIVERED) == ft.Icons.DONE_ALL
    assert status_icon(MessageStatus.READ) == ft.Icons.DONE_ALL


def test_live_tick_read_color_is_blue_delivered_gray():
    """read — акцентный BLUE; sent/delivered — приглушённый sub-цвет."""
    assert (
        status_icon_color(MessageStatus.READ, SUB_COLOR, READ_COLOR) == ft.Colors.BLUE
    )
    assert (
        status_icon_color(MessageStatus.DELIVERED, SUB_COLOR, READ_COLOR) == SUB_COLOR
    )
    assert status_icon_color(MessageStatus.SENT, SUB_COLOR, READ_COLOR) == SUB_COLOR


def test_next_status_monotonic_merge():
    """Монотонность: read never откатывается запоздалым delivered."""
    assert (
        next_status(MessageStatus.SENT, MessageStatus.DELIVERED)
        is MessageStatus.DELIVERED
    )
    assert (
        next_status(MessageStatus.DELIVERED, MessageStatus.READ) is MessageStatus.READ
    )
    assert (
        next_status(MessageStatus.READ, MessageStatus.DELIVERED) is MessageStatus.READ
    )
    assert next_status(MessageStatus.SENT, MessageStatus.SENT) is MessageStatus.SENT


def test_status_icon_control_builds_expected_ft_icon():
    """Чистая сборка ft.Icon: DONE_ALL + синий для read, серая для delivered."""
    read_icon = message_area.status_icon_control(MessageStatus.READ, SUB_COLOR)
    assert isinstance(read_icon, ft.Icon)
    assert read_icon.icon == ft.Icons.DONE_ALL
    assert read_icon.color == ft.Colors.BLUE

    delivered_icon = message_area.status_icon_control(
        MessageStatus.DELIVERED, SUB_COLOR
    )
    assert delivered_icon.icon == ft.Icons.DONE_ALL
    assert delivered_icon.color == SUB_COLOR


async def test_message_row_update_status_ui_o1_and_no_downgrade(screen):
    """update_status_ui меняет иконку/цвет за O(1) и не откатывает статус."""
    row = attach_outgoing_row(screen, 101, MessageStatus.SENT)
    assert row._status_icon.icon == ft.Icons.CHECK

    changed = await row.update_status_ui(MessageStatus.DELIVERED)
    assert changed is True
    assert row._status_icon.icon == ft.Icons.DONE_ALL
    assert row._status_icon.color == screen.sub_color

    changed = await row.update_status_ui(MessageStatus.READ)
    assert changed is True
    assert row._status_icon.color == ft.Colors.BLUE
    assert row.message.status is MessageStatus.READ

    # Запоздалое delivered не перекрашивает синие галочки назад — no-op.
    assert await row.update_status_ui(MessageStatus.DELIVERED) is False
    assert row._status_icon.color == ft.Colors.BLUE
    assert row.message.status is MessageStatus.READ


# ---------------------------------------------------------------------------
# 2. O(1)-индексация + перехват WS-события STATUS_UPDATE
# ---------------------------------------------------------------------------


async def test_ws_status_update_resolves_via_hash_index(screen):
    """STATUS_UPDATE находит ряд по hash-таблице rows_by_id (не сканом)."""
    row = attach_outgoing_row(screen, 202, MessageStatus.SENT)

    # Детектор «нет линейного перебора»: любой проход по списку строк
    # (list_view.controls) уронил бы тест — роутер обязан идти через dict.
    class _NoScanList(list):
        def __iter__(self):
            raise AssertionError("O(1)-роутер не должен обходить controls линейно")

    screen.list_view = SimpleNamespace(controls=_NoScanList(), update=lambda: None)

    await screen._handle_status_update(
        {"type": "STATUS_UPDATE", "message_id": 202, "status": "delivered"}
    )
    await asyncio.sleep(0)  # дать ensure_future-задаче добежать до await

    assert row.message.status is MessageStatus.DELIVERED
    assert row._status_icon.icon == ft.Icons.DONE_ALL
    assert screen.index_by_id[202].status is MessageStatus.DELIVERED


async def test_ws_router_handles_alias_and_ignores_unknown_ids(screen):
    """Роутер WS принимает алиасы message_status/STATUS_UPDATE, id вне
    индекса — безопасный no-op (сообщение не из этого чата)."""
    row = attach_outgoing_row(screen, 303, MessageStatus.DELIVERED)

    screen.handle_event(
        {
            "type": "message_status",
            "message_id": 303,
            "status": "read",
            "reader_id": PEER_ID,
        }
    )
    await asyncio.sleep(0)
    assert row.message.status is MessageStatus.READ
    assert PEER_ID in row.message.read_by

    # Неизвестный id — тихо игнорируем, без KeyError и без падений.
    screen.handle_event({"type": "STATUS_UPDATE", "message_id": 999, "status": "read"})
    await asyncio.sleep(0)
    assert 999 not in screen.index_by_id


# ---------------------------------------------------------------------------
# 3. ACK-логика и Ghost Mode на клиенте
# ---------------------------------------------------------------------------


async def test_incoming_message_triggers_delivered_and_visible_read_acks(screen):
    """WS «message» входящего => ACK delivered; сообщение попало в видимый
    хвост открытого экрана (len <= VISIBLE_TAIL) => сразу и ACK read.

    Порядок статусов на проводе именно такой: delivered первым, read вторым —
    серверный условный UPDATE по рангам монотонен, поэтому порядок/повторы
    безопасны (идемпотентность гарантирует бэкенд).
    """
    payload = {
        "id": 404,
        "chat_id": 7,
        "sender_id": PEER_ID,
        "text": "привет",
        "created_at": "2026-10-18T10:00:00Z",
    }
    screen.list_view = SimpleNamespace(controls=[], update=lambda: None)

    screen.handle_event({"type": "message", "payload": payload})
    await asyncio.sleep(0)

    assert screen.app.api.calls == [(404, "delivered", False), (404, "read", False)]
    assert 404 in screen.index_by_id


async def test_ghost_mode_sends_read_with_ghost_flag_true(screen):
    """Ghost Mode включён => PATCH read уходит с ghost=True (флаг в теле)."""
    screen.test_settings["ghost_mode"] = True
    incoming = make_message(505, PEER_ID, MessageStatus.DELIVERED)
    screen.messages.append(incoming)
    screen.index_by_id[incoming.id] = incoming

    await screen._send_read(incoming)
    assert screen.app.api.calls == [(505, "read", True)]

    # Честная локальная симметрия: сервер вернул applied-status 'read' —
    # модель тоже становится read (собеседник же видит только delivered).
    assert incoming.status is MessageStatus.READ


async def test_ghost_mode_off_sends_plain_read_and_dedups_acks(screen):
    """Ghost выключен => ghost=False; повторный ACK не уходит в сеть."""
    incoming = make_message(606, PEER_ID, MessageStatus.DELIVERED)
    screen.messages.append(incoming)
    screen.index_by_id[incoming.id] = incoming

    await screen._send_read(incoming)
    await screen._send_read(incoming)  # дедупликация: второй раз — no-op

    assert screen.app.api.calls == [(606, "read", False)]
    assert incoming.status is MessageStatus.READ


async def test_server_ghost_downgrade_keeps_local_ui_at_delivered(screen):
    """Сервер при ghost тихо вернул status='delivered' => локальные галочки
    собственных реплик НЕ перепрыгивают в read (applied-status из ответа)."""
    row = attach_outgoing_row(screen, 707, MessageStatus.SENT)

    async def ghost_downgrade(message_id, status, ghost=False):
        screen.app.api.calls.append((message_id, status, ghost))
        return {"ok": True, "changed": True, "status": "delivered"}

    screen.app.api.update_message_status = ghost_downgrade
    screen.test_settings["ghost_mode"] = True

    await screen._send_read(row.message)

    assert screen.app.api.calls == [(707, "read", True)]
    assert row.message.status is MessageStatus.DELIVERED
    assert row._status_icon.color == screen.sub_color  # не стал синим
