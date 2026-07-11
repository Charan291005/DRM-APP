"""
database.py — Async SQLAlchemy engine + session factory.

Uses SQLite (via aiosqlite) for development by default.
Switch to PostgreSQL for production by changing DATABASE_URL in .env.
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from config import get_settings

settings = get_settings()

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,           # Set True for SQL debug logging
    future=True,
    # SQLite-specific: enable WAL mode for better concurrent reads
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {},
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass


async def get_db() -> AsyncSession:
    """FastAPI dependency that yields a DB session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Create all tables on startup (development only).
    For production, use Alembic migrations instead.
    """
    async with engine.begin() as conn:
        from models import Base as ModelBase  # noqa: F401 — ensures models are registered
        await conn.run_sync(ModelBase.metadata.create_all)
