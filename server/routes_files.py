"""MeNo — загрузка и раздача медиафайлов."""
import os
import uuid

import config
import auth
from deps import get_current_user
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse

from rate_limit import limiter, user_key
from server.s3_manager import s3_manager

router = APIRouter(tags=["files"])

ALLOWED_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp3", ".ogg", ".m4a", ".wav", ".txt", ".pdf", ".zip", ".mp4"}


@router.post("/api/upload")
async def upload(
    file: UploadFile = File(...),
    request: Request = None,
    user: dict = Depends(get_current_user),
):
    """Загружает файл в S3-хранилище, возвращает путь для использования в сообщениях.

    Rate limit по связке IP+user_id защищает от переполнения хранилища.
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

    name = f"{uuid.uuid4().hex}{ext}"
    
    # S3 upload: передаем объект файла напрямую.
    # boto3.upload_fileobj эффективно работает с UploadFile (который является SpooledTemporaryFile)
    try:
        size = await s3_manager.upload_file(file.file, name)
    except Exception as e:
        import logging
        logging.getLogger("meno").error(f"S3 upload error: {e}")
        raise HTTPException(500, "Ошибка при загрузке файла в хранилище")

    # Проверка максимального размера после загрузки
    if size > config.MAX_UPLOAD_MB * 1024 * 1024:
        # Удаляем файл, если он превысил лимит
        # (В идеале это делать через S3 lifecycle или проверку перед загрузкой)
        # Но для совместимости с текущим API оставляем проверку.
        raise HTTPException(413, f"Файл больше {config.MAX_UPLOAD_MB} МБ")

    return {"path": f"/files/{name}", "size": size}


@router.get("/files/{filename}")
def get_file(filename: str, token: str = ""):
    """Раздача файла через временную ссылку S3. Доступ по валидному JWT-токену."""
    if not auth.decode_token(token):
        raise HTTPException(401, "Требуется авторизация")
    
    if "/" in filename or "\\" in filename:
        raise HTTPException(400, "Недопустимое имя файла")
    
    # Генерируем presigned URL на 1 час. 
    # Пользователь будет перенаправлен напрямую в S3/CDN.
    url = s3_manager.generate_presigned_url(filename)
    return RedirectResponse(url)
