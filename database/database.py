# database/database.py - Database Connection and Session Management
"""
Database connection and session management for PostgreSQL
Provides thread-safe database operations and connection pooling
"""

import os
import logging
from contextlib import contextmanager
from sqlalchemy import create_engine, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import QueuePool

# Setup logging
logger = logging.getLogger(__name__)

# Base class for SQLAlchemy models
Base = declarative_base()

# Global variables for database connection
engine = None
SessionLocal = None
db_session = None


def init_database(database_url=None, echo=False):
    """
    Initialize database connection and session factory
    
    Args:
        database_url: Database connection URL
        echo: Whether to echo SQL statements (for debugging)
    """
    global engine, SessionLocal, db_session
    
    if not database_url:
        from core.config import get_config
        config = get_config()
        database_url = config.SQLALCHEMY_DATABASE_URI
    
    logger.info(f"Initializing database connection: {database_url}")
    
    # Create engine with connection pooling
    if database_url.startswith('postgresql'):
        engine = create_engine(
            database_url,
            echo=echo,
            poolclass=QueuePool,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,  # Validate connections
            pool_recycle=3600,   # Recycle connections every hour
            connect_args={
                "connect_timeout": 30,
                "options": "-c timezone=utc"
            }
        )
    else:
        # SQLite configuration
        engine = create_engine(
            database_url,
            echo=echo,
            connect_args={
                "check_same_thread": False  # Allow SQLite to be used across threads
            }
        )
    
    # Create session factory
    SessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine
    )
    
    # Create scoped session for thread safety
    db_session = scoped_session(SessionLocal)
    
    # Set up event listeners
    if database_url.startswith('postgresql'):
        @event.listens_for(engine, "connect")
        def set_postgresql_settings(dbapi_connection, connection_record):
            # PostgreSQL-specific optimizations can go here
            pass
    elif database_url.startswith('sqlite'):
        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            # Enable foreign key constraints for SQLite
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    
    logger.info("Database initialization completed")


def create_tables():
    """Create all database tables"""
    global engine
    
    if not engine:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    
    logger.info("Creating database tables...")
    
    # Import models to ensure they're registered
    from .models import (
        User, Scan, Vulnerability, Agent, Report, 
        ScanProgress, APIKey, UserSession
    )
    
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully")


def drop_tables():
    """Drop all database tables (use with caution)"""
    global engine
    
    if not engine:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    
    logger.warning("Dropping all database tables...")
    Base.metadata.drop_all(bind=engine)
    logger.warning("All database tables dropped")


@contextmanager
def get_db_session():
    """
    Get a database session with automatic cleanup
    
    Usage:
        with get_db_session() as session:
            # Use session here
            session.add(obj)
            session.commit()
    """
    global db_session
    
    if not db_session:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    
    session = db_session()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Database session error: {str(e)}")
        raise
    finally:
        session.close()


def get_session():
    """Get a new database session (manual cleanup required)"""
    global SessionLocal
    
    if not SessionLocal:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    
    return SessionLocal()


def close_database():
    """Close database connections"""
    global engine, db_session
    
    if db_session:
        db_session.remove()
    
    if engine:
        engine.dispose()
        logger.info("Database connections closed")


class DatabaseManager:
    """Database manager class for application integration"""
    
    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize database with Flask app"""
        self.app = app
        
        # Get database URL from app config
        database_url = app.config.get('SQLALCHEMY_DATABASE_URI')
        echo = app.config.get('SQLALCHEMY_ECHO', False)
        
        # Initialize database
        init_database(database_url, echo)
        
        # Create tables
        with app.app_context():
            create_tables()
        
        # Register teardown handler
        app.teardown_appcontext(self.close_db)
    
    @staticmethod
    def close_db(error):
        """Close database session on request teardown"""
        if db_session:
            db_session.remove()


# Health check functions
def check_database_health():
    """Check database connection health"""
    try:
        with get_db_session() as session:
            # Simple query to check connection
            session.execute("SELECT 1")
            return True
    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")
        return False


def get_database_info():
    """Get database connection information"""
    global engine
    
    if not engine:
        return {"status": "not_initialized"}
    
    try:
        with get_db_session() as session:
            # Get database version and info
            if engine.dialect.name == 'postgresql':
                result = session.execute("SELECT version()").fetchone()
                version = result[0] if result else "Unknown"
            else:
                version = "SQLite"
            
            return {
                "status": "connected",
                "dialect": engine.dialect.name,
                "version": version,
                "pool_size": engine.pool.size(),
                "checked_in": engine.pool.checkedin(),
                "checked_out": engine.pool.checkedout()
            }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


# Migration support
def run_migrations():
    """Run database migrations (placeholder for Alembic)"""
    logger.info("Database migrations placeholder - implement with Alembic")
    # In a real application, this would run Alembic migrations
    pass
