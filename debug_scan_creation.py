#!/usr/bin/env python3
"""
Debug script to test scan creation step by step
"""
import sys
import os
import asyncio
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def debug_scan_creation():
    print("[DEBUG] Debugging scan creation...")

    try:
        # Test database initialization
        print("1. Testing database initialization...")
        from backend.database import init_db
        await init_db()
        print("   [OK] Database initialized")

        # Test database connection
        print("2. Testing database connection...")
        from backend.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            from sqlalchemy import text
            result = await session.execute(text("SELECT 1"))
            print(f"   [OK] Database connection works: {result.scalar()}")

        # Test scan creation
        print("3. Testing scan creation...")
        from backend.api.scans import create_scan
        from backend.models import ScanCreate, ScanType

        scan_data = ScanCreate(
            target="example.com",
            scan_type=ScanType.QUICK
        )

        print(f"   Creating scan for target: {scan_data.target}")
        print(f"   Scan type: {scan_data.scan_type}")

        # This will fail but we'll see the exact error
        try:
            # We can't call the FastAPI endpoint directly, but we can test the database operations
            from sqlalchemy.ext.asyncio import AsyncSession
            from backend.database import AsyncSessionLocal
            from backend.models import Scan, ScanStatus

            async with AsyncSessionLocal() as session:
                scan = Scan(
                    target="example.com",
                    scan_type="quick",
                    status=ScanStatus.PENDING.value
                )
                session.add(scan)
                await session.commit()
                await session.refresh(scan)
                print(f"   [OK] Scan created in database: {scan.id}")

        except Exception as e:
            print(f"   [FAIL] Database scan creation failed: {e}")
            import traceback
            traceback.print_exc()

    except Exception as e:
        print(f"[FAIL] Debug failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(debug_scan_creation())
