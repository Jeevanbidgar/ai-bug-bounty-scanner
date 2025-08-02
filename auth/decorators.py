# auth/decorators.py - Authentication and Authorization Decorators
"""
Decorators for protecting Flask routes with authentication and authorization
Supports JWT tokens, API keys, sessions, and role-based access control
"""

import functools
from flask import request, jsonify, g
from .auth_manager import auth_manager


def login_required(f):
    """
    Decorator to require authentication for a route
    Supports JWT tokens, API keys, and sessions
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # Get current user from request
        authenticated, message, user = auth_manager.get_current_user_from_request()
        
        if not authenticated:
            return jsonify({
                'error': 'Authentication required',
                'message': message
            }), 401
        
        # Store user in Flask's g object for use in the route
        g.current_user = user
        return f(*args, **kwargs)
    
    return decorated_function


def permission_required(permission):
    """
    Decorator to require specific permission for a route
    
    Args:
        permission: Required permission ('read', 'write', 'admin')
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Get current user from request
            authenticated, message, user = auth_manager.get_current_user_from_request()
            
            if not authenticated:
                return jsonify({
                    'error': 'Authentication required',
                    'message': message
                }), 401
            
            # Check if using API key authentication
            api_key_record = None
            api_key = request.headers.get('X-API-Key')
            if api_key:
                _, _, _, api_key_record = auth_manager.verify_api_key(api_key)
            
            # Check permission
            if not auth_manager.check_permission(user, permission, api_key_record):
                return jsonify({
                    'error': 'Insufficient permissions',
                    'message': f'Required permission: {permission}',
                    'user_role': user.role,
                    'user_permissions': api_key_record.permissions if api_key_record else None
                }), 403
            
            # Store user in Flask's g object
            g.current_user = user
            g.api_key_record = api_key_record
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def role_required(required_role):
    """
    Decorator to require specific user role
    
    Args:
        required_role: Required role ('admin', 'user', 'viewer')
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Get current user from request
            authenticated, message, user = auth_manager.get_current_user_from_request()
            
            if not authenticated:
                return jsonify({
                    'error': 'Authentication required',
                    'message': message
                }), 401
            
            # Check role
            role_hierarchy = {
                'admin': 3,
                'user': 2,
                'viewer': 1
            }
            
            user_level = role_hierarchy.get(user.role, 0)
            required_level = role_hierarchy.get(required_role, 0)
            
            if user_level < required_level:
                return jsonify({
                    'error': 'Insufficient role',
                    'message': f'Required role: {required_role}',
                    'user_role': user.role
                }), 403
            
            # Store user in Flask's g object
            g.current_user = user
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def admin_required(f):
    """Decorator to require admin role"""
    return role_required('admin')(f)


def api_key_required(permissions=None):
    """
    Decorator to require API key authentication with specific permissions
    
    Args:
        permissions: List of required permissions
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            api_key = request.headers.get('X-API-Key')
            
            if not api_key:
                return jsonify({
                    'error': 'API key required',
                    'message': 'Include X-API-Key header'
                }), 401
            
            # Verify API key
            valid, message, user, api_key_record = auth_manager.verify_api_key(api_key)
            
            if not valid:
                return jsonify({
                    'error': 'Invalid API key',
                    'message': message
                }), 401
            
            # Check permissions if specified
            if permissions:
                for permission in permissions:
                    if permission not in api_key_record.permissions:
                        return jsonify({
                            'error': 'Insufficient API key permissions',
                            'message': f'Required permissions: {permissions}',
                            'api_key_permissions': api_key_record.permissions
                        }), 403
            
            # Store user and API key in Flask's g object
            g.current_user = user
            g.api_key_record = api_key_record
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def owner_or_admin_required(user_id_param='user_id'):
    """
    Decorator to require user to be owner of resource or admin
    
    Args:
        user_id_param: Parameter name containing the user ID to check
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Get current user from request
            authenticated, message, user = auth_manager.get_current_user_from_request()
            
            if not authenticated:
                return jsonify({
                    'error': 'Authentication required',
                    'message': message
                }), 401
            
            # Admin users can access everything
            if user.role == 'admin':
                g.current_user = user
                return f(*args, **kwargs)
            
            # Get the user ID from request parameters
            target_user_id = kwargs.get(user_id_param) or request.view_args.get(user_id_param)
            
            if not target_user_id:
                return jsonify({
                    'error': 'User ID parameter missing',
                    'message': f'Required parameter: {user_id_param}'
                }), 400
            
            # Check if current user is the owner
            if str(user.id) != str(target_user_id):
                return jsonify({
                    'error': 'Access denied',
                    'message': 'You can only access your own resources'
                }), 403
            
            # Store user in Flask's g object
            g.current_user = user
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def rate_limit(max_requests=60, per_minutes=1):
    """
    Basic rate limiting decorator
    
    Args:
        max_requests: Maximum number of requests
        per_minutes: Time window in minutes
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # This is a basic implementation
            # In production, you'd want to use Redis or similar for rate limiting
            
            # For now, just proceed with the request
            # TODO: Implement proper rate limiting with Redis
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def validate_json(required_fields=None):
    """
    Decorator to validate JSON request body
    
    Args:
        required_fields: List of required field names
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({
                    'error': 'Invalid content type',
                    'message': 'Request must be JSON'
                }), 400
            
            data = request.get_json()
            if not data:
                return jsonify({
                    'error': 'Invalid JSON',
                    'message': 'Request body must contain valid JSON'
                }), 400
            
            # Check required fields
            if required_fields:
                missing_fields = []
                for field in required_fields:
                    if field not in data or data[field] is None:
                        missing_fields.append(field)
                
                if missing_fields:
                    return jsonify({
                        'error': 'Missing required fields',
                        'message': f'Required fields: {missing_fields}'
                    }), 400
            
            # Store validated data in Flask's g object
            g.json_data = data
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def cors_headers(f):
    """Decorator to add CORS headers to response"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        
        # Add CORS headers if response is a Flask response object
        if hasattr(response, 'headers'):
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-API-Key'
        
        return response
    
    return decorated_function
