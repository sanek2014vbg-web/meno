"""Тесты S3-менеджера (server/s3_manager.py) — Блок C ТЗ.

Полностью изолированы от сети: boto3-клиент подменяется MagicMock'ом,
ни одного реального HTTP-запроса к S3/MinIO не выполняется.
"""

from unittest.mock import MagicMock, patch

import pytest

from server import config
from server.s3_manager import S3Manager, s3_manager


@pytest.fixture()
def fake_s3():
    """Mock boto3-клиента вместо routes_files._get_s3 (общая точка создания)."""
    client = MagicMock(name="FakeS3Client")
    with patch("server.s3_manager._get_s3", return_value=client):
        yield client


class TestS3ManagerIsolation:
    def test_singleton_is_manager_instance(self):
        assert isinstance(s3_manager, S3Manager)

    def test_client_reuses_shared_lazy_factory(self, fake_s3):
        assert s3_manager.client() is fake_s3

    def test_enabled_and_bucket_follow_config(self):
        with (
            patch.object(config, "S3_ENABLED", True),
            patch.object(config, "S3_BUCKET", "my-bucket"),
        ):
            m = S3Manager()
            assert m.enabled is True
            assert m.bucket == "my-bucket"

    def test_disabled_profile_returns_no_client(self):
        with patch("server.s3_manager._get_s3", return_value=None):
            assert S3Manager().client() is None


class TestUpload:
    async def test_upload_returns_size_from_head_object(self, fake_s3):
        fake_s3.head_object.return_value = {"ContentLength": 4096}
        file_obj = MagicMock(name="UploadFile")
        size = await S3Manager().upload_fileobj(file_obj, "u/1/photo.png")
        assert size == 4096
        fake_s3.upload_fileobj.assert_called_once_with(
            file_obj, config.S3_BUCKET, "u/1/photo.png"
        )
        fake_s3.head_object.assert_called_once_with(
            Bucket=config.S3_BUCKET, Key="u/1/photo.png"
        )

    async def test_upload_without_profile_raises(self):
        with patch("server.s3_manager._get_s3", return_value=None):
            with pytest.raises(RuntimeError):
                await S3Manager().upload_fileobj(MagicMock(), "k")


class TestPresignedUrl:
    def test_presigned_url_params(self, fake_s3):
        fake_s3.generate_presigned_url.return_value = "https://s3/signed?X"
        url = S3Manager().generate_presigned_url("u/1/file.pdf", expires_in=60)
        assert url == "https://s3/signed?X"
        args, kwargs = fake_s3.generate_presigned_url.call_args
        assert args[0] == "get_object"
        assert kwargs["Params"] == {"Bucket": config.S3_BUCKET, "Key": "u/1/file.pdf"}
        assert kwargs["ExpiresIn"] == 60

    def test_default_expiry_one_hour(self, fake_s3):
        S3Manager().generate_presigned_url("k")
        assert fake_s3.generate_presigned_url.call_args.kwargs["ExpiresIn"] == 3600

    def test_presigned_url_none_when_storage_local(self):
        # локальный профиль (без S3) — тихий None, а не исключение:
        # вызывающий код фолбэкится на FileResponse из UPLOAD_DIR
        with patch("server.s3_manager._get_s3", return_value=None):
            assert S3Manager().generate_presigned_url("k") is None
