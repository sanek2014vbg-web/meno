import asyncio
import logging
import sys
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from server.database import Base, init_db

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mock_test_db")

# Используем SQLite в памяти для мок-теста. 
# SQLAlchemy позволяет использовать те же модели, что и для Postgres.
MOCK_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

async def run_mock_tests():
    logger.info("--- Starting Mock Database Tests (SQLite in-memory) ---")
    
    # Создаем временный движок для тестов
    engine = create_async_engine(MOCK_DATABASE_URL, echo=False)
    AsyncSessionLocal = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    try:
        # 1. Создание схемы
        logger.info("Creating tables in memory...")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Schema created successfully.")

        # 2. Тест записи и чтения (на модели Setting)
        async with AsyncSessionLocal() as session:
            logger.info("Testing data insertion (Settings)...")
            
            # Используем сырой SQL через session.execute, как в наших функциях aq/aq1
            await session.execute(
                text("INSERT INTO settings (key, value) VALUES (:k, :v)"),
                {"k": "test_key", "v": "test_value"}
            )
            await session.commit()

            # Проверка чтения
            result = await session.execute(
                text("SELECT value FROM settings WHERE key = :k"), 
                {"k": "test_key"}
            )
            val = result.scalar()
            logger.info(f"Read back value: {val}")
            
            if val == "test_value":
                logger.info("✅ Settings test PASSED!")
            else:
                logger.error("❌ Settings test FAILED!")

        # 3. Тест связей (User -> ChatMember -> Chat)
        async with AsyncSessionLocal() as session:
            logger.info("Testing User and Chat relationships...")
            
            # Создаем пользователя
            await session.execute(
                text("INSERT INTO users (phone, password_hash) VALUES (:p, :h)"),
                {"p": "79990000000", "h": "hashed_pw"}
            )
            # Создаем чат
            await session.execute(
                text("INSERT INTO chats (type, title) VALUES (:t, :title)"),
                {"t": "group", "title": "Test Group"}
            )
            await session.commit()
            
            # Получаем ID
            user_id = (await session.execute(text("SELECT id FROM users LIMIT 1"))).scalar()
            chat_id = (await session.execute(text("SELECT id FROM chats LIMIT 1"))).scalar()
            
            # Добавляем пользователя в чат
            await session.execute(
                text("INSERT INTO chat_members (chat_id, user_id, role) VALUES (:c, :u, :r)"),
                {"c": chat_id, "u": user_id, "r": "admin"}
            )
            await session.commit()
            
            # Проверяем членство
            member = (await session.execute(
                text("SELECT role FROM chat_members WHERE chat_id = :c AND user_id = :u"),
                {"c": chat_id, "u": user_id}
            )).scalar()
            
            if member == "admin":
                logger.info("✅ Relationships test PASSED!")
            else:
                logger.error(f"❌ Relationships test FAILED: Got role {member}")

        logger.info("--- All Mock Tests Completed Successfully! ---")

    except Exception as e:
        logger.exception(f"❌ Mock test encountered an error: {e}")
        sys.exit(1)
    finally:
        await engine.dispose()

if __name__ == "__main__":
    # Для работы aiosqlite в памяти нам нужно установить его
    # так как SQLAlchemy использует его для асинхронного SQLite
    try:
        asyncio.run(run_mock_tests())
    except KeyboardInterrupt:
        pass
