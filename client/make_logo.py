"""MeNo — генератор логотипа (SVG + PNG).

Концепция: сияющая сфера с расходящимися волнами-сигналами.
- Тёмная версия: светящаяся циановая сфера на тёмном фоне
- Светлая версия: тёмно-циановый контур на светлом фоне

Запуск:  python make_logo.py   (создаёт файлы в client/assets/)
"""
import math
import os
from pathlib import Path

from PIL import Image, ImageDraw

ASSETS = Path(__file__).parent / "assets"
ACCENT = (0, 229, 255)        # #00E5FF
DARK_BG = (11, 14, 20)        # #0B0E14
LIGHT_BG = (246, 248, 251)    # #F6F8FB
DARK_FG = (8, 26, 33)         # тёмный циан для светлой темы

SIZE = 512
CX, CY = SIZE // 2, SIZE // 2


def _lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def draw_logo(bg_color: tuple, fg_color: tuple, glow: bool) -> Image.Image:
    """Рисует логотип: сфера + три дуги-волны."""
    img = Image.new("RGBA", (SIZE, SIZE), bg_color + (255,))
    d = ImageDraw.Draw(img)

    # --- Сияние вокруг сферы (несколько полупрозрачных кругов) ---
    if glow:
        for i in range(10, 0, -1):
            r = 58 + i * 9
            alpha = int(38 * (1 - i / 11))
            d.ellipse(
                [CX - r, CY - r, CX + r, CY + r],
                outline=fg_color + (alpha,),
                width=3,
            )

    # --- Сфера ---
    r_sphere = 54
    d.ellipse(
        [CX - r_sphere, CY - r_sphere, CX + r_sphere, CY + r_sphere],
        fill=fg_color + (255,),
        outline=_lerp(fg_color, (255, 255, 255), 0.35) + (255,),
        width=4,
    )
    # Блик
    d.ellipse([CX - 24, CY - 30, CX + 6, CY - 4], fill=(255, 255, 255, 150))

    # --- Волны-сигналы (три дуги справа сверху) ---
    for k, w in enumerate((22, 38, 54)):
        bbox = [CX - w, CY - w, CX + w, CY + w]
        start, end = 300, 60  # по часовой стрелке от -60° до 60°
        d.arc(bbox, start=start, end=end, fill=fg_color + (235,), width=9 - k * 2)

    return img


def make_svg(bg: str, fg: str, glow: bool) -> str:
    """Возвращает SVG-код логотипа."""
    glow_def = ""
    if glow:
        glow_def = (
            '  <filter id="g"><feGaussianBlur stdDeviation="6"/></filter>\n'
            '  <circle cx="256" cy="256" r="120" fill="none" stroke="%s" stroke-width="2" opacity="0.25" filter="url(#g)"/>\n'
            % fg
        )
    arcs = "".join(
        f'  <path d="M {256 - w},{256} A {w},{w} 0 0 1 {256},{256 - w}" '
        f'fill="none" stroke="{fg}" stroke-width="{7 - k}" stroke-linecap="round" opacity="0.9"/>\n'
        for k, w in enumerate((60, 80, 100))
    )
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">
  <rect width="512" height="512" fill="{bg}"/>
{glow_def}{arcs}  <circle cx="256" cy="256" r="54" fill="{fg}" stroke="#ffffff" stroke-width="4"/>
  <ellipse cx="236" cy="230" rx="16" ry="13" fill="#ffffff" opacity="0.55"/>
</svg>
"""


def main():
    os.makedirs(ASSETS, exist_ok=True)

    # Тёмная тема (иконка приложения)
    dark = draw_logo(DARK_BG, ACCENT, glow=True)
    dark.save(ASSETS / "logo_dark.png")

    # Светлая тема
    light = draw_logo(LIGHT_BG, DARK_FG, glow=False)
    light.save(ASSETS / "logo_light.png")

    # Иконка приложения (квадрат с заливкой под тёмный фон)
    icon = Image.new("RGBA", (SIZE, SIZE), DARK_BG + (255,))
    icon.alpha_composite(dark)
    icon.save(ASSETS / "icon.png")

    # SVG-версии
    (ASSETS / "logo_dark.svg").write_text(make_svg("#0B0E14", "#00E5FF", glow=True), encoding="utf-8")
    (ASSETS / "logo_light.svg").write_text(make_svg("#F6F8FB", "#081A21", glow=False), encoding="utf-8")

    print("Логотип MeNo создан в", ASSETS)


if __name__ == "__main__":
    main()