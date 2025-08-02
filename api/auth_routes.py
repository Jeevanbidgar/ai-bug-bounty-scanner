# api/auth_routes.py - Authentication API Routes
"""
Authentication and authorization API endpoints
Supports login, registration, token management, and API keys
"""

import logging
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, g
from auth.auth_manager import auth_manager
from auth.decorators import login_required, validate_json
from database.database import get_db_session
from database.models import User

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/register', methods=['POST'])
@validate_json(required_fields=['username', 'email', 'password'])
def register():
    """Register a new user account"""
    data = g.json_data
    
    try:
        success, message, user = auth_manager.create_user(
            username=data['username'],
            email=data['email'],
            password=data['password'],
            first_name=data.get('first_name'),
            last_name=data.get('last_name'),
            role=data.get('role', 'user')  # Default to user role
        )
        
        if success:
            logger.info(f"New user registered: {user.username}")
            return jsonify({
                'message': message,
                'user': user.to_dict()
            }), 201
        else:
            return jsonify({'error': message}), 400
            
    except Exception as e:
        logger.error(f"Registration failed: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500


@auth_bp.route('/login', methods=['POST'])
@validate_json(required_fields=['username', 'password'])
def login():
    """Authenticate user and return tokens"""
    data = g.json_data
    
    try:
        success, message, user = auth_manager.authenticate_user(
            data['username'], 
            data['password']
        )
        
        if success:
            # Generate tokens
            tokens = auth_manager.generate_tokens(user)
            
            # Create session
            session_success, session_message, session_id = auth_manager.create_session(
                user, 
                request.remote_addr, 
                request.headers.get('User-Agent')
            )
            
            logger.info(f"User logged in: {user.username}")
            
            response_data = {
                'message': 'Login successful',
                'user': user.to_dict(),
                'tokens': tokens
            }
            
            if session_success:
                response_data['session_id'] = session_id
            
            return jsonify(response_data)
        else:
            return jsonify({'error': message}), 401
            
    except Exception as e:
        logger.error(f"Login failed: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500


@auth_bp.route('/refresh', methods=['POST'])
@validate_json(required_fields=['refresh_token'])
def refresh():
    """Refresh access token using refresh token"""
    data = g.json_data
    
    try:
        success, message, tokens = auth_manager.refresh_access_token(
            data['refresh_token']
        )
        
        if success:
            return jsonify({
                'message': message,
                'tokens': tokens
            })
        else:
            return jsonify({'error': message}), 401
            
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}")
        return jsonify({'error': 'Token refresh failed'}), 500


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """Logout user and invalidate session"""
    try:
        # Get session ID from request
        session_id = request.json.get('session_id') if request.is_json else None
        
        if session_id:
            success, message = auth_manager.logout_session(session_id)
            if success:
                logger.info(f"User logged out: {g.current_user.username}")
                return jsonify({'message': 'Logout successful'})
            else:
                return jsonify({'error': message}), 400
        else:
            return jsonify({'message': 'Logout successful (no session)'})
            
    except Exception as e:
        logger.error(f"Logout failed: {str(e)}")
        return jsonify({'error': 'Logout failed'}), 500


@auth_bp.route('/profile', methods=['GET'])
@login_required
def get_profile():
    """Get current user profile"""
    return jsonify({
        'user': g.current_user.to_dict(include_sensitive=True)
    })


@auth_bp.route('/profile', methods=['PUT'])
@login_required
@validate_json()
def update_profile():
    """Update current user profile"""
    data = g.json_data
    
    try:
        with get_db_session() as session:
            user = session.query(User).get(g.current_user.id)
            
            # Update allowed fields
            if 'first_name' in data:
                user.first_name = data['first_name']
            if 'last_name' in data:
                user.last_name = data['last_name']
            if 'preferences' in data:
                user.preferences = data['preferences']
            
            user.updated_at = datetime.now(timezone.utc)
            session.commit()
            
            logger.info(f"Profile updated: {user.username}")
            
            return jsonify({
                'message': 'Profile updated successfully',
                'user': user.to_dict(include_sensitive=True)
            })
            
    except Exception as e:
        logger.error(f"Profile update failed: {str(e)}")
        return jsonify({'error': 'Profile update failed'}), 500


@auth_bp.route('/change-password', methods=['POST'])
@login_required
@validate_json(required_fields=['current_password', 'new_password'])
def change_password():
    """Change user password"""
    data = g.json_data
    
    try:
        with get_db_session() as session:
            user = session.query(User).get(g.current_user.id)
            
            # Verify current password
            if not user.check_password(data['current_password']):
                return jsonify({'error': 'Current password is incorrect'}), 400
            
            # Set new password
            user.set_password(data['new_password'])
            user.updated_at = datetime.now(timezone.utc)
            session.commit()
            
            logger.info(f"Password changed: {user.username}")
            
            return jsonify({'message': 'Password changed successfully'})
            
    except Exception as e:
        logger.error(f"Password change failed: {str(e)}")
        return jsonify({'error': 'Password change failed'}), 500


@auth_bp.route('/api-keys', methods=['GET'])
@login_required
def get_api_keys():
    """Get user's API keys"""
    try:
        with get_db_session() as session:
            from database.models import APIKey
            
            api_keys = session.query(APIKey).filter(
                APIKey.user_id == g.current_user.id
            ).all()
            
            return jsonify({
                'api_keys': [key.to_dict() for key in api_keys]
            })
            
    except Exception as e:
        logger.error(f"Failed to get API keys: {str(e)}")
        return jsonify({'error': 'Failed to retrieve API keys'}), 500


@auth_bp.route('/api-keys', methods=['POST'])
@login_required
@validate_json(required_fields=['name'])
def create_api_key():
    """Create new API key"""
    data = g.json_data
    
    try:
        success, message, api_key = auth_manager.create_api_key(
            g.current_user,
            data['name'],
            data.get('permissions', ['read']),
            data.get('expires_days')
        )
        
        if success:
            logger.info(f"API key created: {data['name']} for {g.current_user.username}")
            return jsonify({
                'message': message,
                'api_key': api_key  # Only returned once
            }), 201
        else:
            return jsonify({'error': message}), 400
            
    except Exception as e:
        logger.error(f"API key creation failed: {str(e)}")
        return jsonify({'error': 'API key creation failed'}), 500


@auth_bp.route('/api-keys/<int:key_id>', methods=['DELETE'])
@login_required
def delete_api_key(key_id):
    """Delete API key"""
    try:
        with get_db_session() as session:
            from database.models import APIKey
            
            api_key = session.query(APIKey).filter(
                APIKey.id == key_id,
                APIKey.user_id == g.current_user.id
            ).first()
            
            if not api_key:
                return jsonify({'error': 'API key not found'}), 404
            
            session.delete(api_key)
            session.commit()
            
            logger.info(f"API key deleted: {api_key.name} for {g.current_user.username}")
            
            return jsonify({'message': 'API key deleted successfully'})
            
    except Exception as e:
        logger.error(f"API key deletion failed: {str(e)}")
        return jsonify({'error': 'API key deletion failed'}), 500


@auth_bp.route('/verify', methods=['GET'])
@login_required
def verify_token():
    """Verify current authentication token"""
    return jsonify({
        'valid': True,
        'user': g.current_user.to_dict(),
        'authenticated_via': getattr(g, 'auth_method', 'unknown')
    })
