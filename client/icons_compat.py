"""MeNo — слой совместимости с flet 0.85+.

В flet 0.80+ многие старые API переехали:
- ft.icons.NAME  ->  перечисление ft.icons.Icons (модуль-атрибут ft.icons)
- ft.alignment.center -> ft.Alignment.CENTER
- ft.padding.symmetric/all -> конструктор Padding
- ft.ImageFit -> ft.BoxFit

Этот модуль восстанавливает старый стиль, чтобы весь остальной код
оставался читаемым. Импортировать ПЕРВЫМ в main.py.
"""
import flet as ft


# ---------- Иконки: ft.icons.NAME ----------
_Icons = ft.icons.Icons
if not hasattr(ft.icons, "DNS"):  # патчим один раз
    for _name in dir(_Icons):
        if not _name.startswith("_"):
            try:
                setattr(ft.icons, _name, getattr(_Icons, _name))
            except Exception:
                pass

# ---------- Выравнивание: ft.alignment.center и т.п. ----------
if not hasattr(ft.alignment, "center"):
    for _name in dir(ft.Alignment):
        if not _name.startswith("_") and not _name.islower():
            try:
                setattr(ft.alignment, _name.lower(), getattr(ft.Alignment, _name))
            except Exception:
                pass

# ---------- Отступы: ft.padding.symmetric / ft.padding.all ----------
from flet.controls.padding import Padding as _Padding


def _padding_symmetric(*args, **kwargs):
    if args:
        v = args[0]
        h = args[1] if len(args) > 1 else v
    else:
        v = kwargs.get("vertical", 0)
        h = kwargs.get("horizontal", 0)
    return _Padding(left=h, top=v, right=h, bottom=v)


def _padding_all(*args):
    if len(args) == 1:
        return _Padding(left=args[0], top=args[0], right=args[0], bottom=args[0])
    if len(args) == 2:
        v, h = args
        return _Padding(left=h, top=v, right=h, bottom=v)
    l, t, r, b = args
    return _Padding(left=l, top=t, right=r, bottom=b)


def _padding_only(**kwargs):
    return _Padding(
        left=kwargs.get("left", 0), top=kwargs.get("top", 0),
        right=kwargs.get("right", 0), bottom=kwargs.get("bottom", 0),
    )


if not hasattr(ft.padding, "symmetric"):
    ft.padding.symmetric = _padding_symmetric
    ft.padding.all = _padding_all
    ft.padding.only = _padding_only

# ---------- Изображения: ft.ImageFit -> ft.BoxFit ----------
if not hasattr(ft, "ImageFit") and hasattr(ft, "BoxFit"):
    ft.ImageFit = ft.BoxFit