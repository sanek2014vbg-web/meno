import pytest
import asyncio
from httpx import AsyncClient
from server.main import app
from server.database import Base, engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

# --- Config ---
TEST_DATABASE_URL = "postgresql+asyncpg://postgres:postgres@localhost:5432/meno_test"

# Create a separate session maker for testing
async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
async def client():
    """Async client for FastAPI tests."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

@pytest.fixture(autouse=True)
async def setup_db():
    """Setup and teardown of the test database."""
    # In a real scenario, we would switch to TEST_DATABASE_URL
    # For now, we use the existing engine for structural validation
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    # Cleanup can be added here
