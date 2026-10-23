"""MeNo Admin Center & Monitor — i18n-словарь десктопного монитора.

Все UI-тексты вынесены сюда (требование локализации); язык переключается
через set_language(). KeyError при неизвестном ключе — защита от опечаток.
"""

from __future__ import annotations

from typing import Dict

_RU: Dict[str, str] = {
    "app.title": "MeNo Admin Center & Monitor",
    "tray.tooltip": "MeNo Monitor — тотальный мониторинг",
    "tray.show": "Показать окно",
    "tray.quit": "Выход",
    "tray.notify.connected": "Подключение установлено",
    "tray.notify.disconnected": "Соединение с сервером потеряно",
    "tray.notify.reconnecting": "Переподключение...",
    "toast.new_message": "Новое сообщение в чате #{chat_id}",
    "toast.session_killed": "Сессии пользователя {username} разорваны",
    "toast.role_changed": "Роль пользователя {username} изменена на {role}",
    "tab.live": "Live-события",
    "tab.users": "Пользователи",
    "tab.chat": "Перехват чатов",
    "tab.janitor": "Janitor / TTL",
    "col.seq": "Seq",
    "col.time": "Время",
    "col.scope": "Область",
    "col.kind": "Событие",
    "col.payload": "Данные",
    "col.id": "ID",
    "col.username": "Логин",
    "col.display_name": "Имя",
    "col.role": "Роль",
    "col.online": "Онлайн",
    "col.last_seen": "Активность",
    "col.sender": "Отправитель",
    "col.chat": "Чат",
    "col.content": "Содержимое",
    "col.job": "Задача",
    "col.table": "Таблица",
    "col.deleted": "Удалено",
    "col.status": "Статус",
    "col.next_run": "След. запуск",
    "btn.connect": "Подключить",
    "btn.disconnect": "Отключить",
    "btn.refresh_users": "Обновить",
    "btn.kill_sessions": "Разорвать сессии",
    "btn.promote_admin": "Сделать админом",
    "btn.demote_user": "Понизить до user",
    "btn.freeze_feed": "Заморозить ленту",
    "status.disconnected": "Не подключено",
    "status.connecting": "Подключение...",
    "status.connected": "В сети: {url}",
    "status.events": "Событий: {n} | Буфер: {b} | SPS: {sps}",
    "dialog.auth_title": "Авторизация SuperAdmin",
    "dialog.server_url": "URL сервера:",
    "dialog.username": "Логин владельца:",
    "dialog.password": "Пароль:",
    "error.no_selection": "Сначала выберите пользователя в таблице",
    "error.http_generic": "Ошибка сервера: {code}",
    "error.network": "Сетевая ошибка: {exc}",
    "error.already_running": "Приложение уже запущено.",
    "tab.compliance": "Журнал комплаенса и DLP-аудита",
    "col.logged_at": "Зафиксировано",
    "col.author": "Автор",
    "col.message_id": "ID сообщения",
    "btn.refresh_compliance": "Обновить журнал",
    "btn.load_more_compliance": "Страница назад",
    "status.compliance": "DLP-журнал: строк {n} | Добавлено пачкой {b}",
    "compliance.empty_hint": "Журнал пуст: исчезающих сообщений (ttl_seconds) ещё не зафиксировано",
    "confirm.kill_sessions": "Разорвать ВСЕ сессии пользователя {username}?",
    "confirm.title": "Подтверждение",
}

_EN: Dict[str, str] = {
    "app.title": "MeNo Admin Center & Monitor",
    "tray.tooltip": "MeNo Monitor — total ecosystem monitoring",
    "tray.show": "Show window",
    "tray.quit": "Quit",
    "tray.notify.connected": "Connected to server",
    "tray.notify.disconnected": "Connection to server lost",
    "tray.notify.reconnecting": "Reconnecting...",
    "toast.new_message": "New message in chat #{chat_id}",
    "toast.session_killed": "Sessions of {username} were revoked",
    "toast.role_changed": "Role of {username} changed to {role}",
    "tab.live": "Live events",
    "tab.users": "Users",
    "tab.chat": "Chat tap",
    "tab.janitor": "Janitor / TTL",
    "col.seq": "Seq",
    "col.time": "Time",
    "col.scope": "Scope",
    "col.kind": "Event",
    "col.payload": "Payload",
    "col.id": "ID",
    "col.username": "Username",
    "col.display_name": "Display name",
    "col.role": "Role",
    "col.online": "Online",
    "col.last_seen": "Last seen",
    "col.sender": "Sender",
    "col.chat": "Chat",
    "col.content": "Content",
    "col.job": "Job",
    "col.table": "Table",
    "col.deleted": "Deleted",
    "col.status": "Status",
    "col.next_run": "Next run",
    "btn.connect": "Connect",
    "btn.disconnect": "Disconnect",
    "btn.refresh_users": "Refresh",
    "btn.kill_sessions": "Kill sessions",
    "btn.promote_admin": "Promote to admin",
    "btn.demote_user": "Demote to user",
    "btn.freeze_feed": "Freeze feed",
    "status.disconnected": "Disconnected",
    "status.connecting": "Connecting...",
    "status.connected": "Online: {url}",
    "status.events": "Events: {n} | Buffer: {b} | EPS: {sps}",
    "dialog.auth_title": "SuperAdmin authorization",
    "dialog.server_url": "Server URL:",
    "dialog.username": "Owner username:",
    "dialog.password": "Password:",
    "error.no_selection": "Select a user in the table first",
    "error.http_generic": "Server error: {code}",
    "error.network": "Network error: {exc}",
    "error.already_running": "Application is already running.",
    "tab.compliance": "Compliance & DLP Audit Log",
    "col.logged_at": "Logged at",
    "col.author": "Author",
    "col.message_id": "Message ID",
    "btn.refresh_compliance": "Refresh log",
    "btn.load_more_compliance": "Older page",
    "status.compliance": "DLP log: rows {n} | Batched {b}",
    "compliance.empty_hint": "Log is empty: no ephemeral (ttl_seconds) messages captured yet",
    "confirm.kill_sessions": "Revoke ALL sessions of {username}?",
    "confirm.title": "Confirm",
}

_TABLES: Dict[str, Dict[str, str]] = {"ru": _RU, "en": _EN}
_current = "ru"


def set_language(code: str) -> None:
    global _current
    code = code.lower().split("-")[0]
    if code not in _TABLES:
        raise KeyError(f"Unknown language: {code!r}")
    _current = code


def t(key: str, **fmt) -> str:
    """Перевод по ключу; EN-fallback; KeyError на неизвестный ключ."""
    table = _TABLES[_current]
    text = table.get(key) or _TABLES["en"][key]
    return text.format(**fmt) if fmt else text
