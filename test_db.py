import asyncio
import logging
import sys
from sqlalchemy import text
from server.database import engine, init_db, get_db

# Настройка логирования, чтобы видеть всё, что происходит
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_db")

async def test_connection():
    logger.info("--- Starting Database Test ---")
    
    try:
        # 1. Инициализация схемы (создание таблиц)
        logger.info("Initializing database schema...")
        await init_db()
        logger.info("Schema initialized successfully.")

        # 2. Проверка подключения и список таблиц
        async with get_db() as session:
            logger.info("Connected to database. Fetching table list...")
            
            # Запрос для PostgreSQL, чтобы получить список всех таблиц в схеме public
            query = text("""
                SELECT tablename 
                FROM pg_catalog.pg_tables 
                WHERE schemaname = 'public';
            """)
            
            result = await session.execute(query)
            tables = result.scalars().all()
            
            if tables:
                logger.info(f"Found {len(tables)} tables in database: {', '.join(tables)}")
            else:
                logger.warning("Database is connected, but no tables were found!")

            # 3. Тестовая запись (Insert)
            logger.info("Testing data insertion...")
            await session.execute(
                text("INSERT INTO settings (key, value) VALUES (:k, :v) ON CONFLICT (key) DO UPDATE SET value = :v"),
                {"k": "test_connection", "v": "success"}
            )
            
            # 4. Тестовое чтение (Select)
            res = await session.execute(
                text("SELECT value FROM settings WHERE key = :k"), 
                {"k": "test_connection"}
            )
            val = res.scalar()
            logger.info(f"Read back value from settings: {val}")
            
            if val == "success":
                logger.info("✅ Database test PASSED!")
            else:
                logger.error("❌ Database test FAILED: Unexpected value read back.")

    except Exception as e:
        logger.exception(f"❌ Database test encountered an error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(test_connection())
    except KeyboardInterrupt:
        pass
