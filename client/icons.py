"""MeNo — иконки (совместимость с flet 0.85, где иконки в ft.icons.Icons).

Каждое имя подбирается с запасным вариантом, чтобы интерфейс не падал
при изменении названий в будущих версиях Flet.
"""
import flet as ft

_I = ft.icons.Icons  # атрибутный доступ (модуль ft.icons импортировать нельзя)


def _pick(*names):
    for n in names:
        if hasattr(_I, n):
            return getattr(_I, n)
    return _I.INFO


LOCK = _pick("LOCK_OUTLINE", "LOCK")
LOCK_OPEN = _pick("LOCK_OPEN")
DNS = _pick("DNS")
PHONE = _pick("PHONE_ANDROID", "PHONE", "CALL")
PIN = _pick("PIN")
BADGE = _pick("BADGE")
VERIFIED = _pick("VERIFIED_USER_OUTLINED", "VERIFIED_USER", "VERIFIED")
GPP = _pick("GPP_GOOD", "SECURITY")
CHAT = _pick("CHAT_BUBBLE_OUTLINE", "CHAT_BUBBLE")
CHAT_FILLED = _pick("CHAT_BUBBLE")
SETTINGS = _pick("SETTINGS_OUTLINED", "SETTINGS")
SETTINGS_FILLED = _pick("SETTINGS")
ADMIN = _pick("ADMIN_PANEL_SETTINGS_OUTLINED", "ADMIN_PANEL_SETTINGS")
ADMIN_FILLED = _pick("ADMIN_PANEL_SETTINGS")
MORE_VERT = _pick("MORE_VERT")
MORE_HORIZ = _pick("MORE_HORIZ")
ARROW_BACK = _pick("ARROW_BACK")
SEND = _pick("SEND")
ATTACH = _pick("ATTACH_FILE")
EMOJI = _pick("SENTIMENT_SATISFIED_OUTLINED", "EMOJI_EMOTIONS_OUTLINED", "EMOJI_EMOTIONS")
TIMER = _pick("TIMER_OUTLINED", "TIMER")
VISIBILITY_OFF = _pick("VISIBILITY_OFF_OUTLINED", "VISIBILITY_OFF")
VISIBILITY_OFF_FILLED = _pick("VISIBILITY_OFF")
REFRESH = _pick("REFRESH")
ADD = _pick("ADD")
LOGOUT = _pick("LOGOUT")
DELETE = _pick("DELETE_FOREVER", "DELETE")