"""
Database configuration and connection management for FastAPI backend
Simplified for production: embedded SQLite with proper path handling
"""

import os
from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
import structlog

logger = structlog.get_logger()

# Determine database location based on environment
def get_database_path() -> Path:
    """Get the database file path based on OS and environment"""
    
    # Check for explicit override
    if db_path := os.getenv("DATABASE_FILE"):
        return Path(db_path).resolve()
    
    # Development: use project data directory
    if os.getenv("ENVIRONMENT") == "development":
        project_root = Path(__file__).resolve().parent.parent
        db_dir = project_root / "data"
        db_dir.mkdir(parents=True, exist_ok=True)
        return db_dir / "ai_bug_bounty_scanner.db"
    
    # Production: use OS-appropriate user data directory
    if os.name == "nt":  # Windows
        app_data = Path(os.getenv("LOCALAPPDATA", "~")).expanduser()
        db_dir = app_data / "AIBugBountyScanner"
    else:  # Linux/Mac
        home = Path.home()
        db_dir = home / ".local" / "share" / "ai-bug-bounty-scanner"
    
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / "scanner.db"

# Get database path and create directory
DATABASE_FILE = get_database_path()
DATABASE_URL = f"sqlite+aiosqlite:///{DATABASE_FILE.as_posix()}"

logger.info(
    "Database configured",
    path=str(DATABASE_FILE),
    url=DATABASE_URL,
    exists=DATABASE_FILE.exists()
)

# Create async engine
engine = create_async_engine(
    DATABASE_URL,
    echo=False,  # Set to True for SQL query logging in development
    future=True,
    connect_args={"check_same_thread": False},
)

# Create async session factory
async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# Export for compatibility
AsyncSessionLocal = async_session_maker

def get_async_engine():
    """Get the async engine instance"""
    return engine

class Base(DeclarativeBase):
    """Base class for all database models"""
    pass

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency to get database session"""
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()

async def init_db():
    """Initialize database and create tables"""
    try:
        # Ensure database file can be created
        DATABASE_FILE.parent.mkdir(parents=True, exist_ok=True)
        
        # Import all models to ensure they are registered
        from .models import Scan, Vulnerability, Report, Tool, ReconPlan
        
        # Create all tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        logger.info(
            "Database initialized successfully",
            tables=list(Base.metadata.tables.keys())
        )
        
    except Exception as e:
        logger.error("Failed to initialize database", error=str(e), exc_info=True)
        raise

async def close_db():
    """Close database connections"""
    await engine.dispose()
    logger.info("Database connections closed")