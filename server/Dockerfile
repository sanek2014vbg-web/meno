# MeNo Messenger — production-образ сервера (Этап 1.6 ТЗ).
# Multi-stage: зависимости собираются в build-слое, в финальный образ
# попадают только установленные пакеты и код приложения.

# ---------- Stage 1: build ----------
FROM python:3.11-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=0 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Сначала — только requirements.txt: слой кэшируется и пересобирается
# лишь при изменении зависимостей.
COPY requirements.txt .
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt

# ---------- Stage 2: runtime ----------
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# non-root пользователь: контейнер не работает от root (требование безопасности)
RUN groupadd --system meno && useradd --system --gid meno --home-dir /app --shell /usr/sbin/nologin meno

WORKDIR /app

# Установленные зависимости из build-слоя
COPY --from=builder /install /usr/local

# Код приложения (сервер + миграции alembic в корне репозитория)
COPY . ./server
COPY alembic.ini /app/alembic.ini
COPY migrations /app/migrations

# Каталог загрузок принадлежит пользователю meno (права на запись без root)
RUN mkdir -p /app/server/uploads && chown -R meno:meno /app

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
