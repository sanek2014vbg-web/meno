#!/bin/sh
# MeNo entrypoint (Этап 1.6): alembic upgrade head перед стартом сервера.
set -e

echo "[entrypoint] применяем миграции БД: alembic upgrade head"
if ! alembic upgrade head; then
    echo "[entrypoint] ОШИБКА: миграции не применены — сервер не запускается." >&2
    exit 1
fi
echo "[entrypoint] миграции применены, запускаем приложение"
exec "$@"
