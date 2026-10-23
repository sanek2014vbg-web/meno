# MeNo Messenger — production-образ сервера (Этап 1.6 ТЗ; hardening v2.0).
#
# Multi-stage:
#   stage 1 (builder)  — сборка wheel'ов зависимостей; слой кешируется по
#                        content-hash requirements.txt (BuildKit cache mount),
#                        поэтому пересборка pip происходит ТОЛЬКО при смене
#                        зависимостей, а не при каждом изменении кода;
#   stage 2 (runtime)  — минимальный образ: только установленные пакеты,
#                        код server/, alembic.ini и migrations/.
#
# Безопасность (OWASP / CIS Docker Benchmark):
#   - фиксированный базовый тег python:3.11-slim (воспроизводимость);
#   - non-root пользователь meno (uid/gid 10001) c nologin-шеллом;
#   - pip install --no-cache-dir: в image layers не попадает кеш сборки;
#   - HEALTHCHECK через /health без внешних утилит (curl не устанавливается);
#   - в контекст сборки не попадают секреты (.env), тесты и каталоги CI —
#     см. корневой .dockerignore.
#
# Сборка (контекст = корень репозитория, как в docker-compose.yml):
#   docker build -f server/Dockerfile -t meno-server .

# syntax=docker/dockerfile:1

# ---------- Stage 1: build ----------
FROM python:3.11-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Сначала — только requirements.txt: COPY-слой инвалидируется лишь при
# изменении самого файла; cache mount сохраняет http-кеш pip между
# сборками, поэтому неизменившиеся wheel'ы не скачиваются повторно.
COPY server/requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --prefix=/install --no-cache-dir -r requirements.txt

# ---------- Stage 2: runtime ----------
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# non-root пользователь: контейнер не работает от root (требование безопасности).
# Фиксированные uid/gid 10001 — стабильные права на volume uploads_data.
RUN groupadd --system --gid 10001 meno \
    && useradd --system --uid 10001 --gid meno --home-dir /app --shell /usr/sbin/nologin meno

WORKDIR /app

# Установленные зависимости из build-слоя
COPY --from=builder /install /usr/local

# Код приложения: server/ целиком — включая новые сервисные слои
# (server/services/message_history.py, message_send.py, message_view.py,
#  message_moderation.py, ttl_registry.py), примитивы конкурентности
# (server/db/concurrency.py) и i18n-словарь (server/messages_errors.py):
# всё это части пакета server/, рекурсивный COPY гарантированно их включает.
COPY server/ ./server/
COPY alembic.ini /app/alembic.ini
COPY migrations /app/migrations

# Каталоги данных принадлежат пользователю meno (запись без root);
# uploads создаётся здесь, чтобы volume наследовал правильных владельца.
# Entrypoint копируется с явными правами 0755 — запускать скрипт от meno
# можно без stage-менеджмента привилегированных операций.
RUN mkdir -p /app/server/uploads && chown -R meno:meno /app
COPY --chmod=755 --chown=meno:meno server/entrypoint.sh /usr/local/bin/entrypoint.sh

USER meno

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; \
r=urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4); \
sys.exit(0 if r.status==200 else 1)" || exit 1

# Entrypoint: применяет миграции (alembic upgrade head), затем стартует uvicorn.
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]
