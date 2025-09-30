#!/usr/bin/env python3
"""
Dramatiq worker process launcher

This script starts the Dramatiq worker processes for handling
background tasks in the AI Bug Bounty Scanner.
"""

import os
import sys
import logging
import argparse
from pathlib import Path

# Add backend to path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def main():
    """Main worker launcher"""
    parser = argparse.ArgumentParser(description='AI Bug Bounty Scanner Worker')
    parser.add_argument('--queues', nargs='+', default=['scans', 'tools', 'recon', 'reports', 'cleanup'],
                        help='Queues to process')
    parser.add_argument('--workers', type=int, default=2,
                        help='Number of worker processes')
    parser.add_argument('--redis-url', default=os.getenv('REDIS_URL', 'redis://localhost:6379'),
                        help='Redis broker URL')

    args = parser.parse_args()

    logger.info("Starting AI Bug Bounty Scanner workers")
    logger.info(f"Queues: {args.queues}")
    logger.info(f"Workers per queue: {args.workers}")
    logger.info(f"Redis URL: {args.redis_url}")

    try:
        # Import dramatiq and start workers
        import dramatiq
        from dramatiq.brokers.redis import RedisBroker

        # Set up Redis broker
        broker = RedisBroker(url=args.redis_url)
        dramatiq.set_broker(broker)

        # Start worker processes
        from dramatiq.cli import main as dramatiq_main

        # Build command line arguments for dramatiq
        cmd_args = [
            'dramatiq',
            '--processes', str(args.workers),
            '--threads', '1',
            '--path', str(backend_dir),
            '--module', 'workers.tasks'
        ]

        # Add queues
        for queue in args.queues:
            cmd_args.extend(['--queues', queue])

        logger.info(f"Starting workers with command: {' '.join(cmd_args)}")

        # Execute dramatiq worker
        sys.argv = cmd_args
        dramatiq_main()

    except KeyboardInterrupt:
        logger.info("Worker shutdown requested")
    except Exception as e:
        logger.error(f"Worker failed to start: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
