# api/__init__.py
"""
API package for AI Bug Bounty Scanner v2.0
"""

from .auth_routes import auth_bp
from .scan_routes import scan_bp
from .report_routes import report_bp
from .user_routes import user_bp
from .admin_routes import admin_bp
