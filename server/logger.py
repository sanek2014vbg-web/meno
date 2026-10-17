"""MeNo — централизованная система логирования и мониторинга.

Loguru для структурированного вывода; Sentry — полностью опционален
(Этап 3.4 ТЗ): если MENO_SENTRY_DSN не задан, мониторинг ошибок просто
не инициализируется, сервер работает автономно.
"""
import os
import sys

from loguru import logger

from server.config import SENTRY_DSN


def setup_logging() -> None:
    """Настройка логирования всего приложения."""
    logger.remove()

    # 1. Консоль (читаемый формат для разработки)
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level="INFO",
    )

    # 2. Файл с ротацией (собирается в /app/data или рядом с кодом)
    log_dir = os.environ.get("MENO_LOG_DIR") or os.path.dirname(__file__)
    logger.add(
        os.path.join(log_dir, "server.log"),
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}",
        rotation="10 MB",
        retention="7 days",
        compression="zip",
        level="DEBUG",
    )


def setup_sentry() -> bool:
    """Инициализация Sentry для мониторинга ошибок. Возвращает True, если включён."""
    if not SENTRY_DSN:
        logger.info("SENTRY_DSN is not configured — Sentry monitoring disabled (self-hosted mode).")
        return False

    import sentry_sdk
    from sentry_sdk.integrations.fastapi import FastApiIntegration

    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[FastApiIntegration()],
        traces_sample_rate=float(os.environ.get("MENO_SENTRY_TRACES_RATE", "0.1")),
    )
    logger.info("Sentry monitoring initialized.")
    return True


# Экспортируем настроенный логгер
log = logger
