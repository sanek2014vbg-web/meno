"""MeNo Admin Center & Monitor — нативное Windows-приложение (PyQt6 + qasync).

Тотальный админ-мониторинг экосистемы MeNo Messenger:
  * Live-лента всех событий тапа (сообщения, сессии, janitor) в реальном времени;
  * таблица пользователей с онлайн-статусом, kill sessions и сменой роли на лету;
  * перехват чатов (курсорная лента всех сообщений);
  * визуализация TTL-джоб janitor_jobs;
  * системный трей (QSystemTrayIcon) + native Toast-уведомления Windows
    (win1toast -> winotify -> fallback balloon тррея).

Архитектура:
  network.MonitorClient — чистый asyncio-слой (HTTP+WS), без Qt;
  main.py               — GUI-адаптер: mpsc-очередь asyncio.Queue ->
                         QAbstractTableModel через dataChanged/beginReset (batch).

Запуск:
  python -m admin_monitor.main            # или
  python admin_monitor/main.py
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import os
import sys
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PyQt6.QtCore import (  # noqa: E402
    QAbstractTableModel,
    QLockFile,
    QModelIndex,
    Qt,
    QTimer,
)
from PyQt6.QtGui import QAction, QColor, QIcon, QPainter, QPixmap  # noqa: E402
from PyQt6.QtWidgets import (  # noqa: E402
    QApplication,
    QDialog,
    QDockWidget,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSystemTrayIcon,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

try:
    import qasync
except ImportError as exc:  # pragma: no cover - окружение без qasync
    print("qasync required: pip install qasync", file=sys.stderr)
    raise SystemExit(1) from exc

from admin_monitor.i18n import t  # noqa: E402
from admin_monitor.network import ApiError, AuthError, MonitorClient  # noqa: E402

log = logging.getLogger("meno.monitor")

RING_ROWS = 5000  # ёмкость живой ленты (O(1) ring-сдвиг строками таблицы)
BATCH_FLUSH_MS = 100  # QTimer-период: пачка событий за один layout-redraw
MAX_BATCH_PER_FLUSH = 200  # потолок строк за перерисовку: UI не замирает при шторме
EVENT_QUEUE_MAX = 10000  # asyncio.Queue буфер net->UI (drop-oldest при переполнении)
CHAT_INTERCEPT_ROWS = 2000  # жёсткий потолок перехвата чатов (память O(N) ограничена)
COMPLIANCE_ROWS = 2000  # кольцевой буфер DLP-журнала: жёсткий потолок памяти

# --force-platform — тестовый хедлес-режим (CI без Windows): пропустить
# single-instance мьютекс и трей. Никогда не использовать в проде.
FORCE_PLATFORM = os.environ.get("MENO_MONITOR_FORCE_PLATFORM", "")

EVENT_HEADERS = ("seq", "time", "scope", "kind", "payload")
USER_HEADERS = ("id", "username", "display_name", "role", "online", "last_seen")
CHAT_HEADERS = ("id", "chat_title", "sender_name", "content", "created_at")
JOB_HEADERS = ("job", "table_name", "interval_seconds", "last_status",
               "last_rows_deleted", "next_run_at", "consecutive_failures")
COMPLIANCE_HEADERS = ("id", "message_id", "chat_title", "author_name", "body", "logged_at")


def _app_icon() -> QIcon:
    """Программная иконка (зелёный щит с точкой мониторинга) — без внешних файлов."""
    pm = QPixmap(64, 64)
    pm.fill(QColor(0, 0, 0, 0))
    painter = QPainter(pm)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QColor(37, 135, 74))
    painter.setPen(QColor(20, 90, 50))
    painter.drawRoundedRect(6, 6, 52, 52, 14, 14)
    painter.setBrush(QColor(255, 80, 80))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(24, 24, 16, 16)
    painter.end()
    return QIcon(pm)


# --------------------------------------------------------------------------- #
# Native Windows toast (best-effort, деградирует до balloon трея)
# --------------------------------------------------------------------------- #

class WinToaster:
    def __init__(self) -> None:
        self._mode = "balloon"
        if sys.platform == "win32":
            try:
                from win1toast import toast  # type: ignore

                self._fn = toast
                self._mode = "win1toast"
            except ImportError:
                try:
                    from winotify import Notification, audio  # type: ignore

                    self._fn = functools.partial(self._winotify_send)
                    self._audio = audio
                    self._mode = "winotify"
                except ImportError:
                    pass

    def _winotify_send(self, title: str, body: str) -> None:
        from winotify import Notification, audio  # local import: только на win

        n = Notification(
            app_id="MeNo Admin Monitor",
            title=title,
            msg=body,
            duration="short",
        )
        n.add_audio(self._audio.Reminder)
        n.show()

    @property
    def mode(self) -> str:
        return self._mode

    def show(self, title: str, body: str) -> bool:
        """True — native toast показан; False — нужен fallback (balloon трея)."""
        if self._mode == "balloon":
            return False
        try:
            self._fn(title, body)
        except Exception as exc:
            log.warning("toast failed (%s)", exc.__class__.__name__)
            return False
        return True


# --------------------------------------------------------------------------- #
# Модели таблиц (Qt Model — данные вне виджетов, O(1) инкрементальная вставка)
# --------------------------------------------------------------------------- #

class RingTableModel(QAbstractTableModel):
    """Живая кольцевая лента событий: append() не сбрасывает представление."""

    def __init__(self, headers: List[str], capacity: int) -> None:
        super().__init__()
        self._headers = list(headers)
        self._capacity = capacity
        self._rows: List[List[str]] = []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return len(self._headers)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole or not index.isValid():
            return None
        return self._rows[index.row()][index.column()]

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):  # noqa: N802
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self._headers[section]
        return None

    def append(self, row: List[str]) -> None:
        """O(1) амортизированно: beginInsertRows(0) + trim хвоста."""
        self.beginInsertRows(QModelIndex(), 0, 0)
        self._rows.insert(0, row)
        overflow = len(self._rows) - self._capacity
        if overflow > 0:
            # Атомарное удаление самых старых строк одним removeRows (один
            # layout-сигнал вместо N сдвигов) — жёсткий потолок памяти O(capacity).
            first = self._capacity
            last = len(self._rows) - 1
            self.beginRemoveRows(QModelIndex(), first, last)
            del self._rows[first:]
            self.endRemoveRows()
        self.endInsertRows()

    def append_many(self, rows: List[List[str]]) -> None:
        """Пакетная вставка за один layout-redraw.

        Batch-операция для GUI-таймера: K событий рисуются как одна перерисовка
        (begin/endInsertRows однократно), newest-first; хвост сверх capacity
        срезается одним удалением. Суммарно O(K + C) вместо O(K*C) поштучной
        вставки — лента не деградирует при highload.
        """
        if not rows:
            return
        n = len(rows)
        self.beginInsertRows(QModelIndex(), 0, n - 1)
        self._rows[:0] = reversed(rows)
        overflow = len(self._rows) - self._capacity
        if overflow > 0:
            first = self._capacity
            last = len(self._rows) - 1
            self.beginRemoveRows(QModelIndex(), first, last)
            del self._rows[first:]
            self.endRemoveRows()
        self.endInsertRows()

    def reset_rows(self, rows: List[List[str]]) -> None:
        self.beginResetModel()
        self._rows = rows[: self._capacity]
        self.endResetModel()

    def row_at(self, r: int) -> List[str]:
        return self._rows[r]


# --------------------------------------------------------------------------- #
# Диалог авторизации
# --------------------------------------------------------------------------- #

class AuthDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(t("dialog.auth_title"))
        form = QFormLayout(self)
        self.url = QLineEdit("http://127.0.0.1:8000")
        self.username = QLineEdit("owner")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow(t("dialog.server_url"), self.url)
        form.addRow(t("dialog.username"), self.username)
        form.addRow(t("dialog.password"), self.password)
        buttons = QHBoxLayout()
        ok = QPushButton(t("btn.connect"))
        cancel = QPushButton(t("tray.quit"))
        ok.clicked.connect(self.accept)
        cancel.clicked.connect(self.reject)
        buttons.addWidget(ok)
        buttons.addWidget(cancel)
        form.addRow(buttons)


# --------------------------------------------------------------------------- #
# Главное окно
# --------------------------------------------------------------------------- #

class MainWindow(QMainWindow):
    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__()
        self._loop = loop
        self.setWindowTitle(t("app.title"))
        self.setWindowIcon(_app_icon())
        self.resize(1280, 800)
        self.client: Optional[MonitorClient] = None
        self.toaster = WinToaster()
        self._event_counter = 0
        self._batch: List[List[str]] = []
        self._selected_user_id: Optional[int] = None
        self._selected_username: str = ""
        self._frozen = False
        # Явная инициализация сетевых задач: атрибуты существуют с момента
        # создания окна (до run_connection_pump), shutdown-логика читает их
        # безопасно даже при отказе подключения на раннем этапе.
        self._pump_task = None
        self._state_task = None

        self.events_model = RingTableModel(list(EVENT_HEADERS), RING_ROWS)
        self.users_model = RingTableModel(list(USER_HEADERS), 5000)
        self.chat_model = RingTableModel(list(CHAT_HEADERS), CHAT_INTERCEPT_ROWS)
        self.jobs_model = RingTableModel(list(JOB_HEADERS), 200)
        self.compliance_model = RingTableModel(list(COMPLIANCE_HEADERS), COMPLIANCE_ROWS)
        self._compliance_batch: List[List[str]] = []
        self._compliance_cursor: Optional[str] = None

        tabs = QTabWidget()
        self.tbl_events = self._make_table(self.events_model)
        self.tbl_users = self._make_table(self.users_model)
        self.tbl_chat = self._make_table(self.chat_model)
        self.tbl_jobs = self._make_table(self.jobs_model)
        self.tbl_compliance = self._make_table(self.compliance_model)
        tabs.addTab(self._wrap_with_toolbar(self.tbl_events, freeze=True), t("tab.live"))
        tabs.addTab(self._wrap_with_toolbar(self.tbl_users, users=True), t("tab.users"))
        tabs.addTab(self._wrap_with_toolbar(self.tbl_chat), t("tab.chat"))
        tabs.addTab(self._wrap_with_toolbar(self.tbl_jobs), t("tab.janitor"))
        tabs.addTab(
            self._wrap_with_toolbar(self.tbl_compliance, compliance=True),
            t("tab.compliance"),
        )
        self.tabs = tabs
        self.setCentralWidget(tabs)

        self.status = QLabel(t("status.disconnected"))
        self.statusBar().addPermanentWidget(self.status)

        dock = QDockWidget(t("tray.tooltip"), self)
        dock.setObjectName("monitorLogDock")
        self.audit_label = QLabel("—")
        self.audit_label.setWordWrap(True)
        dock.setWidget(self.audit_label)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, dock)

        self._build_tray()

        # Батчер ленты: просыпается каждые 100 мс и рисует накопленную пачку
        # за ОДИН layout-redraw (append_many). Шторм 10k EPS -> 10 перерисовок/сек
        # по <=200 строк; память ограничена capacity (O(1) на событие).
        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(BATCH_FLUSH_MS)
        self._flush_timer.timeout.connect(self._flush_batch)
        self._flush_timer.timeout.connect(self._flush_compliance_batch)
        self._flush_timer.start()

    def _build_tray(self) -> None:
        if FORCE_PLATFORM == "off":
            # Хедлес-режим CI/Linux: без системного трея.
            self.tray = None
            return
        self.tray = QSystemTrayIcon(_app_icon(), self)
        self.tray.setToolTip(t("tray.tooltip"))
        menu = QMenu()
        show = QAction(t("tray.show"), self)
        show.triggered.connect(lambda: (self.show(), self.raise_()))
        quit_a = QAction(t("tray.quit"), self)
        quit_a.triggered.connect(QApplication.instance().quit)
        menu.addAction(show)
        menu.addSeparator()
        menu.addAction(quit_a)
        self.tray.setContextMenu(menu)
        self.tray.show()

    def _notify(self, title: str, body: str) -> None:
        if self.toaster.show(title, body):
            return
        if self.tray is not None:
            self.tray.showMessage(title, body, self.windowIcon(), 4000)

    # ---------------- table & toolbar builders ---------------- #

    @staticmethod
    def _make_table(model: RingTableModel) -> QTableView:
        view = QTableView()
        view.setModel(model)
        view.setSortingEnabled(False)
        view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        view.verticalHeader().setVisible(False)
        view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        return view

    def _wrap_with_toolbar(
        self,
        table: QTableView,
        freeze: bool = False,
        users: bool = False,
        compliance: bool = False,
    ) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        bar = QHBoxLayout()
        if compliance:
            refresh_c = QPushButton(t("btn.refresh_compliance"))
            refresh_c.clicked.connect(lambda: self._spawn(self._load_compliance_logs()))
            bar.addWidget(refresh_c)
            more_c = QPushButton(t("btn.load_more_compliance"))
            more_c.clicked.connect(lambda: self._spawn(self._load_compliance_page()))
            bar.addWidget(more_c)
        if users:
            refresh = QPushButton(t("btn.refresh_users"))
            refresh.clicked.connect(lambda: self._spawn(self._load_users()))
            bar.addWidget(refresh)
            kill = QPushButton(t("btn.kill_sessions"))
            kill.clicked.connect(lambda: self._spawn(self._kill_selected()))
            bar.addWidget(kill)
            promote = QPushButton(t("btn.promote_admin"))
            promote.clicked.connect(lambda: self._spawn(self._set_role("admin")))
            bar.addWidget(promote)
            demote = QPushButton(t("btn.demote_user"))
            demote.clicked.connect(lambda: self._spawn(self._set_role("user")))
            bar.addWidget(demote)
        if freeze:
            freeze_btn = QPushButton(t("btn.freeze_feed"))
            freeze_btn.setCheckable(True)
            freeze_btn.toggled.connect(lambda v: setattr(self, "_frozen", v))
            bar.addWidget(freeze_btn)
        bar.addStretch(1)
        lay.addLayout(bar)
        lay.addWidget(table)
        if users:
            table.selectionModel().selectionChanged.connect(self._on_user_selected)
        return w

    def _on_user_selected(self) -> None:
        view = self.tbl_users
        rows = view.selectionModel().selectedRows()
        if not rows:
            self._selected_user_id = None
            return
        row = self.users_model.row_at(rows[0].row())
        self._selected_user_id = int(row[0])
        self._selected_username = row[1]

    # ---------------- async glue ---------------- #

    def _spawn(self, coro) -> None:
        asyncio.ensure_future(coro, loop=self._loop)

    def run_connection_pump(self) -> None:
        """Единственный long-running consumer asyncio.Queue -> Qt model."""
        self._pump_task = asyncio.ensure_future(self._pump(), loop=self._loop)
        self._state_task = asyncio.ensure_future(self._state_pump(), loop=self._loop)

    async def _pump(self) -> None:
        while True:
            if not self.client:
                await asyncio.sleep(0.2)
                continue
            try:
                env = await self.client.events.get()
            except asyncio.CancelledError:
                return
            if env.get("type") != "tap_event":
                continue
            if self._frozen:
                continue
            event = env.get("event", {})
            payload = json.dumps(event, ensure_ascii=False, default=str)[:400]
            row = [
                str(env.get("seq", "")),
                str(env.get("ts", ""))[11:19],
                str(event.get("scope", "")),
                str(event.get("kind", "")),
                payload,
            ]
            self._batch.append(row)
            self._event_counter += 1
            kind = event.get("kind")
            if kind == "new_message":
                chat_id = event.get("chat_id", "?")
                self._notify(t("toast.new_message", chat_id=chat_id), payload[:120])
            elif kind in ("sessions_killed", "role_changed"):
                self._notify("MeNo Monitor", payload[:160])

    async def _state_pump(self) -> None:
        while True:
            if not self.client:
                await asyncio.sleep(0.2)
                continue
            try:
                state = await self.client.state_changed.get()
            except asyncio.CancelledError:
                return
            if state == "connected":
                self.status.setText(t("status.connected", url=self.client.base_url))
                self._notify(t("tray.notify.connected"), self.client.base_url)
            elif state == "connecting":
                self.status.setText(t("status.connecting"))
            elif state == "disconnected":
                self.status.setText(t("tray.notify.reconnecting"))
                self._notify(t("tray.notify.disconnected"), "")

    def _flush_batch(self) -> None:
        if not self._batch:
            return
        rows, self._batch = self._batch, []
        # Пакетная вставка за ОДИН layout-redraw (append_many): newest-first
        # обеспечивается самой моделью — строки подаются в хронологическом
        # порядке пачки и вставляются блоком в начало ленты.
        self.events_model.append_many(rows)
        self.status.setText(
            t(
                "status.events",
                n=self._event_counter,
                b=len(rows),
                sps=f"{len(rows) * 1000 // max(BATCH_FLUSH_MS, 1)}",
            )
        )

    def _flush_compliance_batch(self) -> None:
        """DLP-журнал: пачка за один layout-redraw (тот же QTimer 100 мс)."""
        if not self._compliance_batch:
            return
        rows, self._compliance_batch = self._compliance_batch, []
        self.compliance_model.append_many(rows)

    # ---------------- actions ---------------- #

    async def connect_to(self, url: str, username: str, password: str) -> None:
        self.client = MonitorClient(url)
        try:
            await self.client.login(username, password)
            # tap-token (legacy-путь) больше не запрашивается: WS-авторизация —
            # one-time билеты, которые client получает на каждый handshake.
            await self.client.connect_tap()
        except AuthError as exc:
            QMessageBox.critical(self, t("confirm.title"), str(exc))
            await self.client.close()
            self.client = None
            return
        self.run_connection_pump()
        await self._load_users()
        await self._load_chat_history()
        await self._load_jobs()
        await self._load_compliance_logs()

    async def _load_users(self) -> None:
        if not self.client:
            return
        try:
            users = await self.client.get_users()
        except (ApiError, AuthError) as exc:
            self.audit_label.setText(t("error.network", exc=str(exc)))
            return
        rows = [
            [
                str(u["id"]),
                u.get("username", ""),
                u.get("display_name") or "",
                u.get("role", ""),
                "●" if u.get("online") else "○",
                str(u.get("last_seen") or ""),
            ]
            for u in users
        ]
        self.users_model.reset_rows(rows)

    async def _load_chat_history(self) -> None:
        if not self.client:
            return
        try:
            msgs = await self.client.recent_messages(200)
        except (ApiError, AuthError):
            return
        rows = [
            [
                str(m["id"]),
                m.get("chat_title") or f"#{m.get('chat_id')}",
                m.get("sender_name") or str(m.get("sender_id")),
                (m.get("content") or "")[:200],
                str(m.get("created_at") or ""),
            ]
            for m in msgs
        ]
        self.chat_model.reset_rows(rows)

    async def _load_jobs(self) -> None:
        if not self.client:
            return
        try:
            jobs = await self.client.janitor_jobs()
        except (ApiError, AuthError):
            return
        rows = [
            [
                j.get("job", ""),
                j.get("table_name", ""),
                str(j.get("interval_seconds", "")),
                j.get("last_status") or "",
                str(j.get("last_rows_deleted", 0)),
                str(j.get("next_run_at") or ""),
                str(j.get("consecutive_failures", 0)),
            ]
            for j in jobs
        ]
        self.jobs_model.reset_rows(rows)

    @staticmethod
    def _compliance_row(item: dict) -> List[str]:
        """ORM-строка ComplianceAuditLog (API items[]) -> плоская строка таблицы.

        body усекается до 200 символов для рендера: полный текст остаётся в
        БД и отдаётся API без усечения — усечение только визуальное (защита
        ширины столбца при длинных логах).
        """
        return [
            str(item.get("id", "")),
            str(item.get("message_id", "")),
            item.get("chat_title") or f"#{item.get('chat_id')}",
            item.get("author_name") or str(item.get("author_id")),
            (item.get("body") or "")[:200],
            str(item.get("logged_at") or ""),
        ]

    async def _load_compliance_logs(self) -> None:
        """Свежая страница newest-first через ticket-flow (X-Meno-Ticket)."""
        if not self.client:
            return
        try:
            page = await self.client.fetch_compliance_logs(limit=200)
        except (ApiError, AuthError) as exc:
            self.audit_label.setText(t("error.network", exc=str(exc)))
            return
        items = page["items"]
        rows = [self._compliance_row(i) for i in items]
        self.compliance_model.reset_rows(rows)
        self._compliance_cursor = page["next_cursor"]
        self.status.setText(t("status.compliance", n=len(rows), b=0))

    async def _load_compliance_page(self) -> None:
        """Курсорная догрузка страниц назад (before=last logged_at) батчем."""
        if not self.client or not self._compliance_cursor:
            return
        try:
            page = await self.client.fetch_compliance_logs(
                before=self._compliance_cursor, limit=200
            )
        except (ApiError, AuthError) as exc:
            self.audit_label.setText(t("error.network", exc=str(exc)))
            return
        items = page["items"]
        # Хронологический порядок пачки -> append_many сам поставит старшие
        # строки под текущими (newest-first внутри блока вставки).
        self._compliance_batch.extend(self._compliance_row(i) for i in reversed(items))
        self._compliance_cursor = page["next_cursor"] or self._compliance_cursor

    async def _kill_selected(self) -> None:
        if self._selected_user_id is None or not self.client:
            QMessageBox.information(self, t("confirm.title"), t("error.no_selection"))
            return
        answer = QMessageBox.question(
            self,
            t("confirm.title"),
            t("confirm.kill_sessions", username=self._selected_username),
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            res = await self.client.kill_sessions(self._selected_user_id)
            self.audit_label.setText(
                f"kill_sessions user={self._selected_user_id} revoked={res['revoked']}"
            )
        except (ApiError, AuthError) as exc:
            QMessageBox.critical(self, t("confirm.title"), str(exc))

    async def _set_role(self, role: str) -> None:
        if self._selected_user_id is None or not self.client:
            QMessageBox.information(self, t("confirm.title"), t("error.no_selection"))
            return
        try:
            await self.client.set_role(self._selected_user_id, role)
            await self._load_users()
        except (ApiError, AuthError) as exc:
            QMessageBox.critical(self, t("confirm.title"), str(exc))

    def closeEvent(self, event) -> None:  # noqa: N802
        # В headless-режиме (трея нет) или при уже скрытом окне — выходим сразу;
        # иначе сворачиваем в трей и игнорируем закрытие.
        if self.tray is not None and self.isVisible() and not self.isHidden():
            self.hide()
            self.tray.showMessage(
                t("app.title"), t("tray.tooltip"), self.windowIcon(), 3000
            )
            event.ignore()
            return
        if self.client:
            asyncio.ensure_future(self.client.close(), loop=self._loop)
        event.accept()


# --------------------------------------------------------------------------- #
# Точка входа
# --------------------------------------------------------------------------- #

def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    app = QApplication(sys.argv)

    # Windows hardening: single-instance через QLockFile (кроссплатформенный
    # аналог named mutex; на Windows используется LockFileEx). Билет-файл
    # автоматически снимается при падении процесса (ОС закрывает handle).
    lock_path = Path(app.applicationDirPath()) / "meno_admin_monitor.lock"
    lock = QLockFile(str(lock_path))
    lock.setStaleLockTime(0)
    if FORCE_PLATFORM != "off" and not lock.tryLock(100):
        QMessageBox.warning(None, t("app.title"), t("error.already_running"))
        return 1

    app.setQuitOnLastWindowClosed(False)
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    win = MainWindow(loop)
    win.show()

    dlg = AuthDialog(win)
    if dlg.exec() != QDialog.DialogCode.Accepted:
        return 0

    with loop:
        loop.run_until_complete(
            win.connect_to(dlg.url.text().strip(), dlg.username.text().strip(),
                           dlg.password.text())
        )
        loop.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
