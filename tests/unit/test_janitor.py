"""Тесты фонового дворника (server/services/janitor.py) — Блок C ТЗ.

Полностью изолированы: ни сети, ни реального Redis не требуется.
- cache/manager/chat_member_ids мокаются (unittest.mock.AsyncMock);
- БД — SQLite из корневого conftest (фикстура clean_db пересоздаёт схему).
"""
import asyncio
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import text as sqltext

from server import database
from server.services import janitor as janitor_mod
from server.services.janitor import (
    DELETE_EVENT_TYPE,
    JanitorService,
    janitor_service,
)
from server.utils import utc_now


async def _insert_message(db, **kw):
    """Вставляет сообщение; колонки соответствуют реальной схеме (content)."""
    defaults = dict(
        chat_id=1, sender_id=1, content="body", ttl_seconds=None,
        view_once=0, viewed=0, expires_at=None, type="text", e2e=0,
        client_id=f"c{utc_now().timestamp()}", media_path=None, duration=None,
    )
    defaults.update(kw)
    await db.execute(
        sqltext(
            "INSERT INTO messages (chat_id, sender_id, content, type, e2e,"
            " client_id, media_path, duration, ttl_seconds, view_once,"
            " viewed, expires_at, created_at)"
            " VALUES (:chat_id, :sender_id, :content, :type, :e2e,"
            " :client_id, :media_path, :duration, :ttl_seconds,"
            " :view_once, :viewed, :expires_at, :created_at)"
        ),
        {**defaults, "created_at": kw.get("created_at", utc_now())},
    )


async def _insert_refresh_token(db, user_id=1, token="h", family="f",
                               expires_at=None, revoked=0):
    await db.execute(
        sqltext(
            "INSERT INTO refresh_tokens (user_id, token, family, expires_at,"
            " revoked, created_at) VALUES (:u, :t, :f, :e, :r, :c)"
        ),
        {"u": user_id, "t": token, "f": family, "e": expires_at or utc_now(),
         "r": revoked, "c": utc_now()},
    )


@pytest.fixture()
def mocks():
    """Изоляция внешних сервисов дворника: Redis-кеш, WS-шина, состав чата."""
    with (
        patch.object(janitor_mod, "cache") as cache,
        patch.object(janitor_mod, "manager") as manager,
        patch.object(janitor_mod, "chat_member_ids",
                     new_callable=AsyncMock) as members,
    ):
        cache.delete = AsyncMock()
        manager.send_to_users = AsyncMock()
        members.return_value = [1, 2]
        yield MagicMock(cache=cache, manager=manager, members=members)



@pytest.mark.usefixtures("clean_db")
class TestJanitorRunOnce:
    async def test_no_expired_messages_is_noop(self, mocks):
        async with database.get_db() as db:
            await _insert_message(db, ttl_seconds=3600)  # живой TTL
            await db.commit()
        assert await JanitorService().run_once() == 0
        mocks.manager.send_to_users.assert_not_awaited()

    async def test_absolute_ttl_expired_erased_and_broadcast(self, mocks):
        async with database.get_db() as db:
            await _insert_message(db, chat_id=7,
                                  expires_at=utc_now() - timedelta(seconds=1))
            await _insert_message(db, chat_id=7,
                                  expires_at=utc_now() + timedelta(hours=1))
            await db.commit()

        assert await JanitorService().run_once() == 1

        # физическое стирание: строки больше нет в БД
        async with database.get_db() as db:
            rows = await database.aq(db, "SELECT id FROM messages")
            assert len(rows) == 1

        mocks.cache.delete.assert_any_await("chat_last:7")
        mocks.manager.send_to_users.assert_awaited_once()
        call = mocks.manager.send_to_users.await_args
        assert call.args[0] == [1, 2]
        assert call.args[1]["type"] == DELETE_EVENT_TYPE
        assert call.args[1]["chat_id"] == 7
        assert len(call.args[1]["message_ids"]) == 1

    async def test_legacy_relative_ttl_deadline(self, mocks):
        async with database.get_db() as db:
            await _insert_message(db, ttl_seconds=10,
                                  created_at=utc_now() - timedelta(seconds=30))
            await db.commit()
        assert await JanitorService().run_once() == 1

    async def test_view_once_erased_only_after_viewing(self, mocks):
        async with database.get_db() as db:
            await _insert_message(db, view_once=1, viewed=0)
            await db.commit()
        assert await JanitorService().run_once() == 0  # ещё не просмотрен

        async with database.get_db() as db:
            await db.execute(sqltext(
                "UPDATE messages SET viewed = 1"))
            await db.commit()
        assert await JanitorService().run_once() == 1

    async def test_refresh_tokens_hygiene(self, mocks):
        async with database.get_db() as db:
            await _insert_refresh_token(
                db, expires_at=utc_now() - timedelta(days=1))
            await db.commit()
        await JanitorService().run_once()
        async with database.get_db() as db:
            row = await database.aq1(db, "SELECT COUNT(*) AS n"
                                     " FROM refresh_tokens")
            assert row["n"] == 0

    async def test_grouping_by_chat_one_event_per_chat(self, mocks):
        async with database.get_db() as db:
            for chat in (1, 1, 2):
                await _insert_message(db, chat_id=chat,
                                      expires_at=utc_now()
                                      - timedelta(seconds=5))
            await db.commit()
        assert await JanitorService().run_once() == 3
        # send_to_users вызывается ОДИН раз на чат — группировка событий:
        # args = (member_ids, payload), где payload содержит chat_id/message_ids
        calls = mocks.manager.send_to_users.await_args_list
        assert len(calls) == 2
        by_chat = {c.args[1]["chat_id"]: c.args[1]["message_ids"] for c in calls}
        assert set(by_chat) == {1, 2}
        assert len(by_chat[1]) == 2 and len(by_chat[2]) == 1
        assert all(c.args[1]["type"] == DELETE_EVENT_TYPE for c in calls)

    async def test_empty_membership_skips_broadcast(self, mocks):
        mocks.members.return_value = []
        async with database.get_db() as db:
            await _insert_message(db, expires_at=utc_now()
                                  - timedelta(seconds=1))
            await db.commit()
        assert await JanitorService().run_once() == 1
        mocks.manager.send_to_users.assert_not_awaited()


@pytest.mark.usefixtures("clean_db")
class TestJanitorLifecycle:
    async def test_start_stop_idempotent(self):
        svc = JanitorService()
        with patch.object(svc, "run_once", new_callable=AsyncMock) as run:
            await svc.start(interval=0.01)
            await svc.start(interval=0.01)          # повторный start — no-op
            assert svc._task is not None
            task = svc._task
            await asyncio.sleep(0.05)
            assert run.await_count >= 1
            await svc.stop()
            assert svc._task is None and task.done()
            await svc.stop()                        # остановка без задачи

    async def test_loop_survives_tick_exception(self):
        svc = JanitorService()
        boom = AsyncMock(side_effect=[RuntimeError("db down"),
                                      AsyncMock(return_value=0)()])
        with patch.object(svc, "run_once", new=boom):
            await svc.start(interval=0.01)
            await asyncio.sleep(0.08)
            assert boom.await_count >= 2            # цикл НЕ упал на ошибке
            assert not svc._task.done()
            await svc.stop()

    def test_singleton_exported(self):
        assert isinstance(janitor_service, JanitorService)
