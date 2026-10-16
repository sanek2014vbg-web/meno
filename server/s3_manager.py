"""MeNo — менеджер работы с S3-хранилищем (AWS S3, MinIO и др.).

Позволяет загружать файлы и генерировать временные ссылки для доступа, 
что снимает нагрузку с основного API-сервера.
"""
import boto3
from botocore.client import Config
from datetime import timedelta
import config

class S3Manager:
    def __init__(self):
        self.bucket = config.S3_BUCKET
        self.s3 = boto3.client(
            "s3",
            aws_access_key_id=config.S3_ACCESS_KEY,
            aws_secret_access_key=config.S3_SECRET_KEY,
            region_name=config.S3_REGION,
            endpoint_url=config.S3_ENDPOINT,
            config=Config(signature_version="s3v4"),
            use_ssl=config.S3_USE_SSL
        )

    async def upload_file(self, file_obj, filename: str) -> int:
        """Загружает файл в S3 и возвращает его размер в байтах."""
        # boto3 upload_fileobj работает синхронно, но эффективно для потоков
        # Для полноценного async используется aioboto3, но boto3 достаточно для большинства задач
        size = 0
        #- Мы используем upload_fileobj, так как он работает с объектами, имеющими метод read()
        # file_obj (UploadFile) поддерживает это.
        self.s3.upload_fileobj(file_obj, self.bucket, filename)
        
        # Получаем размер загруженного объекта
        response = self.s3.head_object(Bucket=self.bucket, Key=filename)
        size = response["ContentLength"]
        return size

    def generate_presigned_url(self, filename: str, expires_in: int = 3600) -> str:
        """Создает временную ссылку на файл (по умолчанию на 1 час)."""
        return self.s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.bucket, "Key": filename},
            ExpiresIn=expires_in
        )

# Синглтон для использования в приложении
s3_manager = S3Manager()
