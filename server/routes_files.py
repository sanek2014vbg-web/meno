"""MeNo — загрузка и раздача медиафайлов."""
import os
import uuid

import config
import auth
from deps import get_current_user
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse

from rate_limit import limiter, user_key

router = APIRouter(tags=["files"])

ALLOWED_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp3", ".ogg", ".m4a", ".wav", ".txt", ".pdf", ".zip", ".mp4"}


@router.post("/api/upload")
async def upload(
    file: UploadFile = File(...),
    request: Request = None,
    user: dict = Depends(get_current_user),
):
    """Сохраняет файл в папку uploads, возвращает путь для использования в сообщениях.

    Rate limit по связке IP+user_id защищает от переполнения диска.
    """
    if not limiter.allow(
        user_key("upload", request, user["id"]),
        config.RL_UPLOAD_LIMIT,
        config.RL_UPLOAD_WINDOW,
    ):
        raise HTTPException(429, "Слишком много загрузок — попробуйте позже")
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(400, f"Недопустимый тип файла: {ext or 'без расширения'}")

    os.makedirs(config.UPLOAD_DIR, exist_ok=True)
    name = f"{uuid.uuid4().hex}{ext}"
    dest = os.path.join(config.UPLOAD_DIR, name)

    size = 0
    with open(dest, "wb") as out:
        while chunk := await file.read(1024 * 256):
            size += len(chunk)
            if size > config.MAX_UPLOAD_MB * 1024 * 1024:
                out.close()
                os.remove(dest)
                raise HTTPException(413, f"Файл больше {config.MAX_UPLOAD_MB} МБ")
            out.write(chunk)

    return {"path": f"/files/{name}", "size": size}


@router.get("/files/{filename}")
def get_file(filename: str, token: str = ""):
    """Раздача файла. Доступ по валидному JWT-токену (в query-параметре)."""
    if not auth.decode_token(token):
        raise HTTPException(401, "Требуется авторизация")
    if "/" in filename or "\\" in filename:
        raise HTTPException(400, "Недопустимое имя файла")
    path = os.path.join(config.UPLOAD_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(404, "Файл не найден")
    return FileResponse(path)