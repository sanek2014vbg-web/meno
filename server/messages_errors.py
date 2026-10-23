"""MeNo — единый словарь текстов ошибок домена сообщений (i18n-слой).

Правила рефакторинга (архитектурный аудит, Пункт 1):
- маршруты и сервисы НЕ содержат литералов пользовательских ошибок —
  все строки берутся отсюда, ключи каноничны;
- язык выбирается один раз при импорте (MENO_LANGUAGE), переключение на
  лету не требуется: текст ошибки фиксируется в HTTP-ответе;
- неизвестный ключ падает KeyError сразу при вызове — опечатка не может
  «утечь» в прод как пустая строка.

Английский — fallback: если перевод ключа для выбранного языка отсутствует,
возвращается EN-версия, а не KeyError.
"""

from server import config

MSG_NOT_FOUND = "msg.not_found"
NOT_CHAT_MEMBER = "msg.not_chat_member"
NO_ACCESS = "msg.no_access"
EMPTY_MESSAGE = "msg.empty"
SPAM_LIMIT = "msg.spam_limit"
DELETE_FOREIGN = "msg.delete_foreign"
REPORT_SELF = "msg.report_self"
REPORT_DUPLICATE = "msg.report_duplicate"
REPORT_SENT = "msg.report_sent"

# Заголовки push для нетекстовых типов (не ошибка, но тоже UI-текст).
PUSH_E2E = "push.e2e"
PUSH_IMAGE = "push.image"
PUSH_FILE = "push.file"
PUSH_VOICE = "push.voice"

# Тексты админского контура безопасности (SuperAdmin tap / WS-билеты).
ADMIN_ONLY = "admin.only"
ADMIN_ROLE_REVOKED = "admin.role_revoked"
ADMIN_REPORT_NOT_FOUND = "admin.report_not_found"
ADMIN_MSG_NOT_FOUND = "admin.msg_not_found"
ADMIN_USER_NOT_FOUND = "admin.user_not_found"
ADMIN_SELF_ROLE = "admin.self_role"
ADMIN_ROLE_RACE = "admin.role_race"
ADMIN_TICKET_REQUIRED = "admin.ticket_required"
ADMIN_TICKET_INVALID = "admin.ticket_invalid"
TAP_REDIS_UNAVAILABLE = "tap.redis_unavailable"
COMPLIANCE_TABLE_MISSING = "compliance.table_missing"

_EN: dict[str, str] = {
    MSG_NOT_FOUND: "Message not found",
    NOT_CHAT_MEMBER: "You are not a member of this chat",
    NO_ACCESS: "Access denied",
    EMPTY_MESSAGE: "Empty message",
    SPAM_LIMIT: "You are sending messages too often",
    DELETE_FOREIGN: "You can delete only your own messages",
    REPORT_SELF: "You cannot report your own message",
    REPORT_DUPLICATE: "You have already reported this message",
    REPORT_SENT: "Report sent to moderator",
    PUSH_E2E: "\U0001f512 Encrypted message",
    PUSH_IMAGE: "\U0001f4f7 Photo",
    PUSH_FILE: "\U0001f4ce File",
    PUSH_VOICE: "\U0001f399️ Voice message",
    ADMIN_ONLY: "Access restricted to owner (DevMode)",
    ADMIN_ROLE_REVOKED: "Administrator role has been revoked",
    ADMIN_REPORT_NOT_FOUND: "Report not found",
    ADMIN_MSG_NOT_FOUND: "Message not found",
    ADMIN_USER_NOT_FOUND: "User not found",
    ADMIN_SELF_ROLE: "You cannot change your own role",
    ADMIN_ROLE_RACE: "Role changed by a concurrent operation, retry",
    ADMIN_TICKET_REQUIRED: "One-time WebSocket ticket required",
    ADMIN_TICKET_INVALID: "Ticket invalid, expired or already used",
    TAP_REDIS_UNAVAILABLE: "Session store temporarily unavailable",
    COMPLIANCE_TABLE_MISSING: "Compliance audit log table not provisioned (run migrations)",
}

_RU: dict[str, str] = {
    MSG_NOT_FOUND: "Сообщение не найдено",
    NOT_CHAT_MEMBER: "Вы не участник этого чата",
    NO_ACCESS: "Нет доступа",
    EMPTY_MESSAGE: "Пустое сообщение",
    SPAM_LIMIT: "Слишком часто отправляете сообщения",
    DELETE_FOREIGN: "Удалять можно только свои сообщения",
    REPORT_SELF: "Нельзя пожаловаться на своё сообщение",
    REPORT_DUPLICATE: "Вы уже пожаловались на это сообщение",
    REPORT_SENT: "Жалоба отправлена модератору",
    PUSH_E2E: "🔒 Зашифрованное сообщение",
    PUSH_IMAGE: "📷 Фотография",
    PUSH_FILE: "📎 Файл",
    PUSH_VOICE: "🎙️ Голосовое сообщение",
    ADMIN_ONLY: "Доступ только для владельца (DevMode)",
    ADMIN_ROLE_REVOKED: "Роль администратора отозвана",
    ADMIN_REPORT_NOT_FOUND: "Жалоба не найдена",
    ADMIN_MSG_NOT_FOUND: "Сообщение не найдено",
    ADMIN_USER_NOT_FOUND: "Пользователь не найден",
    ADMIN_SELF_ROLE: "Нельзя изменить собственную роль",
    ADMIN_ROLE_RACE: "Роль изменена параллельной операцией, повторите",
    ADMIN_TICKET_REQUIRED: "Требуется одноразовый билет WebSocket",
    ADMIN_TICKET_INVALID: "Билет недействителен, истёк или уже использован",
    TAP_REDIS_UNAVAILABLE: "Хранилище сессий временно недоступно",
    COMPLIANCE_TABLE_MISSING: "Журнал комплаенса не создан (примените миграции)",
}

_TABLES: dict[str, dict[str, str]] = {"ru": _RU, "en": _EN}


def t(key: str) -> str:
    """Текст по ключу на активном языке (fallback — английский)."""
    lang = (getattr(config, "MENO_LANGUAGE", "ru") or "ru").lower()[:2]
    table = _TABLES.get(lang, _EN)
    if key in table:
        return table[key]
    if key in _EN:
        return _EN[key]
    raise KeyError(f"Unknown i18n message key: {key!r}")
