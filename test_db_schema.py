#!/usr/bin/env python3
"""
Test database schema and table structure
"""
import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def test_db_schema():
    print("Testing database schema...")

    try:
        from backend.database import AsyncSessionLocal
        from sqlalchemy import text

        async with AsyncSessionLocal() as session:
            # Check all tables
            result = await session.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
            tables = result.fetchall()
            print(f"Found {len(tables)} tables:")
            for table in tables:
                print(f"  - {table[0]}")

            # Check scans table structure
            if any(t[0] == 'scans' for t in tables):
                result = await session.execute(text("PRAGMA table_info(scans)"))
                columns = result.fetchall()
                print(f"\nscans table has {len(columns)} columns:")
                for col in columns:
                    print(f"  - {col[1]} ({col[2]})")

                # Check if there are any existing scans
                result = await session.execute(text("SELECT COUNT(*) FROM scans"))
                count = result.scalar()
                print(f"\nExisting scans count: {count}")

        return True

    except Exception as e:
        print(f"[FAIL] Database schema test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    result = asyncio.run(test_db_schema())
    if result:
        print("Database schema test PASSED")
    else:
        print("Database schema test FAILED")

