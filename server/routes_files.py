"""MeNo — загрузка и раздача медиафайлов.

Профиль хранилища выбирается автоматически (Этап 3.1 ТЗ):
- задан MENO_S3_ENDPOINT/ключи → S3/MinIO + presigned URL;
- иначе → локальный UPLOAD_DIR (self-hosted без облаков, бесплатно).
Загрузка потоковая: файл читается чанками с лимитом размера, чтобы не
съедать память сервера.
"""
import logging
import os
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse, FileResponse

from server import auth, config
from server.deps import get_current_user
from server.rate_limit import limiter, user_key

router = APIRouter(tags=["files"])

ALLOWED_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp3", ".ogg", ".m4a", ".wav",
               ".txt", ".pdf", ".zip", ".mp4"}
CHUNK = 1024 * 1024  # 1 MiB

log = logging.getLogger("meno.files")

_s3 = None


def _get_s3():
    """Ленивая инициализация S3-клиента (только если профиль настроен)."""
    global _s3
    if not config.S3_ENABLED:
        return None
    if _s3 is None:
        import boto3
        from botocore.client import Config as BotoConfig

        _s3 = boto3.client(
            "s3",
            aws_access_key_id=config.S3_ACCESS_KEY,
            aws_secret_access_key=config.S3_SECRET_KEY,
            region_name=config.S3_REGION,
            endpoint_url=config.S3_ENDPOINT,
            config=BotoConfig(signature_version="s3v4"),
            use_ssl=config.S3_USE_SSL,
        )
    return _s3


async def _save_local(file, name: str) -> int:
    path = os.path.join(config.UPLOAD_DIR, name)
    limit_bytes = config.MAX_UPLOAD_MB * 1024 * 1024
    size = 0
    with open(path, "wb") as f:
        while True:
            chunk = await file.read(CHUNK)
            if not chunk:
                break
            size += len(chunk)
            if size > limit_bytes:
                f.close()
                os.remove(path)
                raise HTTPException(413, f"Файл больше {config.MAX_UPLOAD_MB} МБ")
            f.write(chunk)
    return size


@router.post("/api/upload")
async def upload(
    request: Request,
    file: UploadFile = File(...),
    user: dict = Depends(get_current_user),
):
    """Загружает файл (S3 или локально), возвращает путь для сообщений."""
    if not await limiter.allow_async(
        user_key("upload", request, user["id"]),
        config.RL_UPLOAD_LIMIT,
        config.RL_UPLOAD_WINDOW,
    ):
        raise HTTPException(429, "Слишком много загрузок — попробуйте позже")

    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(400, f"Недопустимый тип файла: {ext or 'без расширения'}")

    name = f"{uuid.uuid4().hex}{ext}"

    s3 = _get_s3()
    if s3 is not None:
        try:
            import anyio

            def _put():
                s3.upload_fileobj(file.file, config.S3_BUCKET, name)
                head = s3.head_object(Bucket=config.S3_BUCKET, Key=name)
                return int(head["ContentLength"])

            size = await anyio.to_thread.run_sync(_put)
        except Exception as e:
            log.error("S3 upload error: %s", e)
            raise HTTPException(500, "Ошибка при загрузке файла в хранилище")
        if size > config.MAX_UPLOAD_MB * 1024 * 1024:
            try:
                s3.delete_object(Bucket=config.S3_BUCKET, Key=name)
            except Exception:
                pass
            raise HTTPException(413, f"Файл больше {config.MAX_UPLOAD_MB} МБ")
    else:
        os.makedirs(config.UPLOAD_DIR, exist_ok=True)
        size = await _save_local(file, name)

    return {"path": f"/files/{name}", "size": size}


@router.get("/files/{filename}")
def get_file(filename: str, token: str = ""):
    """Раздача файла: presigned-редирект (S3) либо отдача с диска (локально)."""
    if not auth.decode_token(token):
        raise HTTPException(401, "Требуется авторизация")
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(400, "Недопустимое имя файла")

    s3 = _get_s3()
    if s3 is not None:
        url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": config.S3_BUCKET, "Key": filename},
            ExpiresIn=3600,
        )
        return RedirectResponse(url)

    path = os.path.join(config.UPLOAD_DIR, filename)
    if not os.path.isfile(path):
        raise HTTPException(404, "Файл не найден")
    return FileResponse(path, filename=filename)
