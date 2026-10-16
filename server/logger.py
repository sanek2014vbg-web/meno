"""MeNo — централизованная система логирования и мониторинга.

Использует Loguru для структурированного вывода и Sentry для отслеживания критических ошибок.
"""
import sys
import os
from loguru import logger
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from server.config import SENTRY_DSN

def setup_logging():
    """Настройка логирования всего приложения."""
    # Очищаем стандартные обработчики loguru
    logger.remove()

    # 1. Настройка вывода в консоль (красивый формат для разработки)
    logger.add(
        sys.stderr, 
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level="INFO"
    )

    # 2. Настройка записи в файл (формат для сбора логов)
    log_file = os.path.join(os.path.dirname(__file__), "server.log")
    logger.add(
        log_file,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}",
        rotation="10 MB",
        retention="7 days",
        compression="zip",
        level="DEBUG"
    )

def setup_sentry():
    """Инициализация Sentry для мониторинга ошибок."""
    if not SENTRY_DSN:
        logger.warning("SENTRY_DSN is not configured. Sentry monitoring is disabled.")
        return

    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[FastApiIntegration()],
        traces_sample_rate=1.0,
        profiles_sample_rate=1.0,
    )
    logger.info("Sentry monitoring initialized.")

# Экспортируем настроенный логгер
log = logger
