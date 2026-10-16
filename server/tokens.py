"""MeNo — дополнение к схеме БД для управления сессиями."""

# Таблица для хранения Refresh-токенов
# Позволяет инвалидировать сессии (например, при смене пароля или выходе из всех устройств)
REFRESH_TOKEN_TABLE = """
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens (user_id);
"""
