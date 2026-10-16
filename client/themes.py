"""MeNo — темы оформления: светлая и тёмная, акцентный цвет."""
import flet as ft

APP_NAME = "MeNo"
ACCENT = "#00E5FF"

# Палитры для тёмной и светлой тем
PALETTES = {
    "dark": {
        "bg": "#0B0E14",
        "card": "#131A24",
        "text": "#E6EDF3",
        "sub": "#8B98A5",
        "field": "#1A2330",
        "bubble_me": "#0F3A44",
        "bubble_other": "#1A2330",
    },
    "light": {
        "bg": "#F6F8FB",
        "card": "#FFFFFF",
        "text": "#0B0E14",
        "sub": "#5B6B78",
        "field": "#EAF0F6",
        "bubble_me": "#CCF0F7",
        "bubble_other": "#FFFFFF",
    },
}


def _resolved_mode(page: ft.Page, mode: str) -> str:
    """Определяет фактическую палитру для режима темы.

    Для 'system' используем яркость платформы (page.platform_brightness),
    чтобы палитра совпадала с системной темой устройства/браузера.
    """
    if mode != "system":
        return mode
    try:
        if getattr(page, "platform_brightness", None) == ft.Brightness.LIGHT:
            return "light"
    except Exception:
        pass
    return "dark"  # по умолчанию — мягкая тёмная


def apply_theme(page: ft.Page, mode: str) -> None:
    """Применяет тему: 'dark' | 'light' | 'system'."""
    page.theme_mode = {
        "dark": ft.ThemeMode.DARK,
        "light": ft.ThemeMode.LIGHT,
        "system": ft.ThemeMode.SYSTEM,
    }[mode]
    page.theme = ft.Theme(color_scheme_seed=ACCENT)
    resolved = _resolved_mode(page, mode)
    c = PALETTES[resolved]
    page.bgcolor = c["bg"]
    page.update()


def colors(page: ft.Page) -> dict:
    """Палитра с учётом текущей темы страницы."""
    mode: str = "dark"
    try:
        tm = page.theme_mode
        if tm == ft.ThemeMode.LIGHT:
            mode = "light"
        elif tm == ft.ThemeMode.SYSTEM:
            mode = _resolved_mode(page, "system")
    except Exception:
        pass
    return PALETTES[mode]