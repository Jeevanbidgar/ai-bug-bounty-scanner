# celery_app.py - Celery Application Factory
"""
Celery application factory and task definitions
Handles asynchronous vulnerability scanning tasks
"""

import os
import sys
from celery import Celery
from celery.signals import worker_init, worker_process_init
from kombu import Queue

# Add the project root to the path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)


def make_celery(app=None):
    """Create Celery application"""
    
    # Import here to avoid circular imports
    from core.config import get_config
    config = get_config()
    
    celery = Celery(
        'bug_bounty_scanner',
        broker=config.CELERY_BROKER_URL,
        backend=config.CELERY_RESULT_BACKEND,
        include=['tasks.scanning_tasks', 'tasks.report_tasks']
    )
    
    # Configure Celery
    celery.conf.update(
        task_serializer=config.CELERY_TASK_SERIALIZER,
        accept_content=config.CELERY_ACCEPT_CONTENT,
        result_serializer=config.CELERY_RESULT_SERIALIZER,
        timezone=config.CELERY_TIMEZONE,
        enable_utc=config.CELERY_ENABLE_UTC,
        task_track_started=True,
        task_time_limit=config.SCAN_TIMEOUT,
        task_soft_time_limit=config.SCAN_TIMEOUT - 60,
        worker_prefetch_multiplier=1,
        task_acks_late=True,
        worker_max_tasks_per_child=1000,
        task_routes={
            'tasks.scanning_tasks.run_full_scan': {'queue': 'scanning'},
            'tasks.scanning_tasks.run_agent_scan': {'queue': 'scanning'},
            'tasks.report_tasks.generate_report': {'queue': 'reports'},
            'tasks.report_tasks.export_report': {'queue': 'reports'},
        },
        task_default_queue='default',
        task_queues=(
            Queue('default', routing_key='default'),
            Queue('scanning', routing_key='scanning'),
            Queue('reports', routing_key='reports'),
        ),
    )
    
    # Update task base classes to include Flask app context
    if app:
        class ContextTask(celery.Task):
            """Make celery tasks work with Flask app context"""
            def __call__(self, *args, **kwargs):
                with app.app_context():
                    return self.run(*args, **kwargs)
        
        celery.Task = ContextTask
    
    return celery


# Create Celery instance for worker
celery_app = make_celery()


@worker_init.connect
def worker_init_handler(sender=None, conf=None, **kwargs):
    """Initialize worker with necessary setup"""
    print("Celery worker initializing...")


@worker_process_init.connect
def worker_process_init_handler(sender=None, **kwargs):
    """Initialize each worker process"""
    print(f"Worker process {os.getpid()} initialized")


if __name__ == '__main__':
    # Start Celery worker
    celery_app.start()
