"""MeNo — общие утилиты (время, сериализация)."""
from datetime import datetime, timezone


def utc_now() -> datetime:
    """Текущее время в UTC с таймзоной (замена deprecated datetime.utcnow())."""
    return datetime.now(timezone.utc)


def as_utc(dt) -> datetime | None:
    """Приводит значение времени из БД/Redis к tz-aware UTC.

    Дефект-фикс №3 (Этап 2.5): драйверы и сторонние хранилища (Redis строки,
    legacy-колонки TEXT в SQLite) могут вернуть ISO-строку вместо datetime —
    парсим её, включая суффикс 'Z'. Naive-значения трактуются как UTC."""
    if dt is None:
        return None
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(dt, datetime):
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
