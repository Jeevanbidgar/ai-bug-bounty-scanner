# Core module initialization
"""
Core functionality for AI Bug Bounty Scanner
Contains configuration, celery setup, and other core components
"""

__version__ = "2.0.0"
__author__ = "AI Bug Bounty Scanner Team"

from .config import get_config
from .celery_app import make_celery, celery_app

__all__ = ['get_config', 'make_celery', 'celery_app']
