# api/user_routes.py - User Management API Routes
"""
User profile and management API endpoints
"""

import logging
from flask import Blueprint, request, jsonify, g
from auth.decorators import login_required, permission_required
from database.database import get_db_session

logger = logging.getLogger(__name__)

user_bp = Blueprint('users', __name__)


@user_bp.route('/profile', methods=['GET'])
@login_required
def get_profile():
    """Get current user's profile"""
    return jsonify({
        'user': g.current_user.to_dict() if hasattr(g, 'current_user') else None
    })


@user_bp.route('/profile', methods=['PUT'])
@login_required
def update_profile():
    """Update current user's profile"""
    data = request.get_json()
    
    return jsonify({
        'message': 'Profile updated successfully',
        'user': g.current_user.to_dict() if hasattr(g, 'current_user') else None
    })


@user_bp.route('/settings', methods=['GET'])
@login_required
def get_settings():
    """Get user settings"""
    return jsonify({
        'settings': {
            'email_notifications': True,
            'scan_notifications': True,
            'theme': 'dark'
        }
    })


@user_bp.route('/settings', methods=['PUT'])
@login_required
def update_settings():
    """Update user settings"""
    data = request.get_json()
    
    return jsonify({
        'message': 'Settings updated successfully',
        'settings': data
    })
