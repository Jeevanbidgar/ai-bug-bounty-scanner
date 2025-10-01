"""
Database initialization and migration system

Handles database setup, migrations, and initial data seeding.
"""

import asyncio
import os
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from alembic import command
from alembic.config import Config
import structlog

logger = structlog.get_logger()

def get_alembic_config() -> Config:
    """Get Alembic configuration"""
    current_dir = Path(__file__).parent
    alembic_cfg = Config(str(current_dir / "alembic.ini"))

    # Set script location
    alembic_cfg.set_main_option("script_location", str(current_dir / "migrations"))

    return alembic_cfg

async def init_database():
    """Initialize database with tables and seed data"""
    try:
        from backend.database import get_database_path

        # Get database path
        db_file_path = get_database_path()
        
        # Create database directory if it doesn't exist
        db_file_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"[DATABASE] Using: {db_file_path}")

        # Import models to register them
        from backend.models import Base

        # Use async engine to create tables
        from backend.database import get_async_engine
        engine = get_async_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        logger.info("Database tables created successfully")

        # For testing, skip seeding for now
        # asyncio.run(seed_initial_data())

        logger.info("Database initialization completed")

    except Exception as e:
        logger.error("Failed to initialize database", error=str(e))
        raise

def seed_initial_data():
    """Seed database with initial data"""
    from backend.database import _ensure_session_maker
    from backend.models import Tool, ReconPlan
    from backend.tool_discovery import tool_discovery_service
    from backend.services.recon_service import ReconService

    async def _seed():
        session_maker = _ensure_session_maker()
        async with session_maker() as session:
            # Check if tools already exist
            from sqlalchemy import select
            result = await session.execute(select(Tool).limit(1))
            existing_tools = result.scalars().all()

            if existing_tools:
                logger.info("Tools already seeded")
                return

            # Seed tools from discovery service
            await tool_discovery_service.ensure_ready()
            discovered_tools = await tool_discovery_service.list_tools()

            for tool_record in discovered_tools:
                tool = Tool(
                    name=tool_record.name,
                    description=tool_record.description,
                    category=tool_record.category,
                    command_template=" ".join(tool_record.command_template),
                    available=tool_record.installed,
                    installed=tool_record.installed,
                    version=tool_record.version,
                    last_check=datetime.fromisoformat(tool_record.last_checked) if tool_record.last_checked else None
                )
                session.add(tool)

            await session.commit()
            logger.info(f"Seeded {len(discovered_tools)} tools from discovery service")

            # Seed reconnaissance plans
            result = await session.execute(select(ReconPlan).limit(1))
            existing_plans = result.scalars().all()

            if not existing_plans:
                recon_service = ReconService()
                templates = recon_service.builtin_templates

                for name, template in templates.items():
                    plan = ReconPlan(
                        name=template.name,
                        description=template.description,
                        target_type=template.target_type,
                        phases=template.phases,
                        tools=[tool.tools for tool in template.phases]
                    )
                    session.add(plan)

                await session.commit()
                logger.info(f"Seeded {len(templates)} reconnaissance plans")

    return _seed()

def run_migrations():
    """Run database migrations"""
    try:
        alembic_cfg = get_alembic_config()

        # Stamp current revision (create alembic_version table)
        command.stamp(alembic_cfg, "head")

        # Upgrade to latest
        command.upgrade(alembic_cfg, "head")

        logger.info("Database migrations completed")

    except Exception as e:
        logger.error("Failed to run migrations", error=str(e))
        raise

def create_migration(message: str = "Auto migration"):
    """Create a new database migration"""
    try:
        alembic_cfg = get_alembic_config()
        command.revision(alembic_cfg, message=message, autogenerate=True)

        logger.info(f"Created migration: {message}")

    except Exception as e:
        logger.error("Failed to create migration", error=str(e))
        raise

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Database management")
    parser.add_argument("action", choices=["init", "migrate", "seed", "create-migration"])
    parser.add_argument("--message", default="Auto migration")

    args = parser.parse_args()

    if args.action == "init":
        init_database()
    elif args.action == "migrate":
        run_migrations()
    elif args.action == "seed":
        asyncio.run(seed_initial_data())
    elif args.action == "create-migration":
        create_migration(args.message)
