"""MeNo — проверка загрузки и отправки медиа (этап 2, FilePicker-цепочка).

Через API повторяем путь, который выполняет FilePicker в UI:
загрузка файла -> сообщение типа image/file -> скачивание по ссылке.
"""
import struct
import zlib
from pathlib import Path

import httpx

BASE = "http://127.0.0.1:8000"


def make_png(path: Path):
    """Генерирует минимальный валидный PNG 4x4 (циановый квадрат)."""
    w = h = 4
    raw = b"".join(b"\x00" + bytes([0, 229, 255]) * w for _ in range(h))

    def chunk(tag: bytes, data: bytes) -> bytes:
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c))

    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )
    path.write_bytes(png)


def main():
    c = httpx.Client(timeout=15)
    r = c.post(f"{BASE}/api/login", json={"phone": "79990000001", "password": "1234"})
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    h = {"Authorization": f"Bearer {token}"}

    photo = Path(__file__).parent / "_test_photo.png"
    make_png(photo)

    # 1. Загрузка файла на сервер (как это делает FilePicker -> api.upload)
    with photo.open("rb") as f:
        r = c.post(f"{BASE}/api/upload", headers=h,
                   files={"file": (photo.name, f, "image/png")})
    print("Upload:", r.status_code, r.json())
    assert r.status_code == 200
    media_path = r.json()["path"]

    # 2. Отправка сообщения типа image (как в chat_view._on_pick)
    r = c.post(f"{BASE}/api/chats/1/messages", headers=h,
               json={"type": "image", "content": photo.name, "media_path": media_path})
    print("Send image:", r.status_code, r.json().get("id"), r.json().get("type"))
    assert r.status_code == 200 and r.json()["type"] == "image"

    # 3. Скачивание файла по ссылке file_url (как рендерит ft.Image)
    url = f"{BASE}{media_path}?token={token}"
    dl = c.get(url)
    print("Download:", dl.status_code, len(dl.content), "bytes")
    assert dl.status_code == 200 and len(dl.content) > 40  # PNG минимальный ~70 байт

    # 4. Отправка обычного файла (тип file)
    txt = Path(__file__).parent / "_test_note.txt"
    txt.write_text("MeNo test file", encoding="utf-8")
    with txt.open("rb") as f:
        r = c.post(f"{BASE}/api/upload", headers=h, files={"file": (txt.name, f)})
    print("Upload txt:", r.status_code)
    r = c.post(f"{BASE}/api/chats/1/messages", headers=h,
               json={"type": "file", "content": txt.name, "media_path": r.json()["path"]})
    print("Send file:", r.status_code, r.json().get("type"))
    assert r.status_code == 200 and r.json()["type"] == "file"

    print("\nМедиа: ✅ все шаги успешны")


if __name__ == "__main__":
    main()