"""MeNo — общие утилиты (время, сериализация)."""
from datetime import datetime, timezone


def utc_now() -> datetime:
    """Текущее время в UTC с таймзоной (замена deprecated datetime.utcnow())."""
    return datetime.now(timezone.utc)


def as_utc(dt: datetime | None) -> datetime | None:
    """Приводит naive-datetime из БД (хранится в UTC) к tz-aware значению."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
