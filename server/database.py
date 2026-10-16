"""MeNo — модуль базы данных (SQLite, боевой режим).

Боевая отказоустойчивость под высокую нагрузку:
- WAL (Write-Ahead Logging): параллельное чтение во время записи,
  устойчивость к обрывам процесса, отсутствие «database is locked»
  при одновременной записи логов и E2E-сообщений;
- пул соединений с таймаутом ожидания блокировок (busy_timeout),
  чтобы конкурентные запросы не падали с ошибкой блокировки файла;
- synchronous=NORMAL — оптимальный баланс скорости и надёжности в WAL.
"""
import os
import queue
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Tuple

DB_PATH = os.path.join(os.path.dirname(__file__), "meno.db")

# Параметры пула соединений (высоконагруженный режим)
POOL_SIZE = 8            # максимум одновременно открытых соединений
BUSY_TIMEOUT_MS = 5000   # ждать снятия блокировки до 5 секунд (вместо мгновенной ошибки)
CONNECT_TIMEOUT_S = 30   # сколько ждать свободное соединение из пула

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    phone         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name  TEXT DEFAULT '',
    role          TEXT DEFAULT 'user',
    totp_secret   TEXT,
    twofa_enabled INTEGER DEFAULT 0,
    avatar_path   TEXT,
    e2e_pub       TEXT,
    created_at    TEXT DEFAULT (datetime('now')),
    last_seen     TEXT
);

CREATE TABLE IF NOT EXISTS verify_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    phone      TEXT NOT NULL,
    code       TEXT NOT NULL,
    purpose    TEXT DEFAULT 'register',
    expires_at TEXT NOT NULL,
    used       INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS chats (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    type       TEXT NOT NULL,
    title      TEXT DEFAULT '',
    created_by INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS chat_members (
    chat_id   INTEGER NOT NULL,
    user_id   INTEGER NOT NULL,
    role      TEXT DEFAULT 'member',
    joined_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (chat_id, user_id)
);

CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id     INTEGER NOT NULL,
    sender_id   INTEGER NOT NULL,
    type        TEXT DEFAULT 'text',
    content     TEXT DEFAULT '',
    media_path  TEXT,
    ttl_seconds INTEGER,
    view_once   INTEGER DEFAULT 0,
    viewed      INTEGER DEFAULT 0,
    e2e         INTEGER DEFAULT 0,
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id     INTEGER NOT NULL,
    message_id  INTEGER NOT NULL,
    reporter_id INTEGER NOT NULL,
    reason      TEXT DEFAULT '',
    status      TEXT DEFAULT 'open',
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS push_tokens (
    user_id    INTEGER NOT NULL,
    token      TEXT PRIMARY KEY,
    platform   TEXT DEFAULT 'android',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages (chat_id, id);
CREATE INDEX IF NOT EXISTS idx_chat_members_user ON chat_members (user_id);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports (status);
CREATE INDEX IF NOT EXISTS idx_push_tokens_user ON push_tokens (user_id);
"""


class _ConnPool:
    """Пул потокобезопасных соединений SQLite.

    Соединение возвращается в пул после каждой операции; если пул полон,
    поток ожидает освобождения до CONNECT_TIMEOUT_S. Все соединения
    открываются с WAL, busy_timeout и foreign_keys — это исключает
    «database is locked» при конкурентной записи.
    """

    def __init__(self, size: int = POOL_SIZE) -> None:
        self._pool: "queue.Queue[sqlite3.Connection]" = queue.Queue(maxsize=size)
        self._size = size
        self._lock = threading.Lock()
        self._created = 0

    @staticmethod
    def _new() -> sqlite3.Connection:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=CONNECT_TIMEOUT_S)
        conn.row_factory = sqlite3.Row
        # WAL: параллельные читатели + один писатель, без «lock» при обрыве
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=%d" % BUSY_TIMEOUT_MS)
        conn.execute("PRAGMA foreign_keys=ON")
        # synchronous=NORMAL: fsync только на чекпоинтах WAL (скорость+надёжность)
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def acquire(self) -> sqlite3.Connection:
        try:
            return self._pool.get_nowait()
        except queue.Empty:
            pass
        # Создаём новое соединение, пока не упёрлись в максимум пула
        with self._lock:
            if self._created < self._size:
                self._created += 1
                return self._new()
        # Пул исчерпан — ждём освобождения соединения
        return self._pool.get(timeout=CONNECT_TIMEOUT_S)

    def release(self, conn: sqlite3.Connection) -> None:
        try:
            self._pool.put_nowait(conn)
        except queue.Full:
            try:
                conn.close()
            except Exception:
                pass

    def close_all(self) -> None:
        """Закрывает все соединения (при остановке сервера)."""
        while True:
            try:
                conn = self._pool.get_nowait()
                conn.close()
            except queue.Empty:
                break


_pool = _ConnPool()


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Возвращает соединение из пула. Каждая операция коммитится по выходу."""
    conn = _pool.acquire()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _pool.release(conn)


def init_db() -> None:
    """Создаёт таблицы при первом запуске + миграции для существующих БД."""
    with get_db() as db:
        db.executescript(SCHEMA)
        _migrate(db)


def close_pool() -> None:
    """Закрывает пул соединений (вызывается при остановке приложения)."""
    _pool.close_all()


def _migrate(db: sqlite3.Connection) -> None:
    """Добавляет новые колонки в уже созданные таблицы (безопасно, идемпотентно)."""
    user_cols = {r["name"] for r in db.execute("PRAGMA table_info(users)")}
    if "e2e_pub" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN e2e_pub TEXT")

    msg_cols = {r["name"] for r in db.execute("PRAGMA table_info(messages)")}
    if "e2e" not in msg_cols:
        db.execute("ALTER TABLE messages ADD COLUMN e2e INTEGER DEFAULT 0")

    # Таблица push-токенов (добавлена в 1.1.0)
    db.execute(
        "CREATE TABLE IF NOT EXISTS push_tokens ("
        " user_id INTEGER NOT NULL,"
        " token TEXT PRIMARY KEY,"
        " platform TEXT DEFAULT 'android',"
        " created_at TEXT DEFAULT (datetime('now'))"
        ")"
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_push_tokens_user ON push_tokens (user_id)")


def q(db: sqlite3.Connection, sql: str, params: Tuple[Any, ...] = ()) -> List[Dict[str, Any]]:
    """Выполняет SELECT и возвращает список словарей."""
    rows = db.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def q1(db: sqlite3.Connection, sql: str, params: Tuple[Any, ...] = ()) -> Optional[Dict[str, Any]]:
    """Выполняет SELECT и возвращает одну строку (или None)."""
    row = db.execute(sql, params).fetchone()
    return dict(row) if row else None