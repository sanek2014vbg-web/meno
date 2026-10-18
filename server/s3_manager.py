"""MeNo — менеджер работы с S3-хранилищем (AWS S3, MinIO и др.).

Реализация-прокси: единая точка создания boto3-клиента lives in
``server.routes_files._get_s3`` (ленивая инициализация + profile-check);
этот модуль переиспользует её, чтобы не дублировать конфигурацию.
Раньше модуль был мёртвым кодом с битым импортом ``import config``
таинь-модуля и синглтоном, падающим при старте без S3 — исправлено (Фаза 3).
"""
from __future__ import annotations

from typing import Optional

from server import config
from server.routes_files import _get_s3


class S3Manager:
    """Тонкая обёртка над общим ленивым boto3-клиентом приложения."""

    @property
    def enabled(self) -> bool:
        return config.S3_ENABLED

    @property
    def bucket(self) -> str:
        return config.S3_BUCKET

    def client(self):
        """Boto3-клиент S3 или None, если профиль хранилища не настроен."""
        return _get_s3()

    async def upload_fileobj(self, file_obj, key: str) -> int:
        """Загружает файл в S3 и возвращает его размер в байтах."""
        s3 = self.client()
        if s3 is None:
            raise RuntimeError("S3 профиль не настроен (MENO_S3_ENDPOINT)")
        # boto3 синхронный; для тяжёлых загрузок вызывающий код оборачивает
        # в asyncio.to_thread (см. routes_files.upload).
        s3.upload_fileobj(file_obj, self.bucket, key)
        response = s3.head_object(Bucket=self.bucket, Key=key)
        return int(response["ContentLength"])

    def generate_presigned_url(self, key: str, expires_in: int = 3600) -> Optional[str]:
        """Временная ссылка на файл (None, если S3 выключен)."""
        s3 = self.client()
        if s3 is None:
            return None
        return s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.bucket, "Key": key},
            ExpiresIn=expires_in,
        )


s3_manager = S3Manager()

__all__ = ["S3Manager", "s3_manager"]
