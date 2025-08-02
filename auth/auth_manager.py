# auth/auth_manager.py - Authentication and Authorization Manager
"""
Comprehensive authentication and authorization system
Supports JWT tokens, API keys, session management, and role-based access
"""

import os
import jwt
import uuid
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Tuple
from functools import wraps
from flask import request, jsonify, current_app, session
from werkzeug.security import generate_password_hash, check_password_hash

from database.models import User, APIKey, UserSession
from database.database import get_db_session


class AuthenticationManager:
    """Main authentication manager class"""
    
    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize authentication with Flask app"""
        self.app = app
        
        # Set default config values
        app.config.setdefault('JWT_SECRET_KEY', app.config['SECRET_KEY'])
        app.config.setdefault('JWT_ACCESS_TOKEN_EXPIRES', timedelta(hours=1))
        app.config.setdefault('JWT_REFRESH_TOKEN_EXPIRES', timedelta(days=30))
        app.config.setdefault('SESSION_EXPIRE_DAYS', 7)
    
    def create_user(self, username: str, email: str, password: str, 
                   first_name: str = None, last_name: str = None, 
                   role: str = 'user') -> Tuple[bool, str, Optional[User]]:
        """
        Create a new user account
        
        Args:
            username: Unique username
            email: User email address
            password: Raw password (will be hashed)
            first_name: User's first name
            last_name: User's last name
            role: User role (admin, user, viewer)
            
        Returns:
            Tuple of (success, message, user_object)
        """
        try:
            with get_db_session() as session:
                # Check if username or email already exists
                existing_user = session.query(User).filter(
                    (User.username == username) | (User.email == email)
                ).first()
                
                if existing_user:
                    if existing_user.username == username:
                        return False, "Username already exists", None
                    else:
                        return False, "Email already exists", None
                
                # Create new user
                user = User(
                    username=username,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    role=role
                )
                user.set_password(password)
                
                session.add(user)
                session.commit()
                
                return True, "User created successfully", user
                
        except Exception as e:
            return False, f"Error creating user: {str(e)}", None
    
    def authenticate_user(self, username_or_email: str, password: str) -> Tuple[bool, str, Optional[User]]:
        """
        Authenticate user with username/email and password
        
        Args:
            username_or_email: Username or email address
            password: Raw password
            
        Returns:
            Tuple of (success, message, user_object)
        """
        try:
            with get_db_session() as session:
                # Find user by username or email
                user = session.query(User).filter(
                    (User.username == username_or_email) | (User.email == username_or_email)
                ).first()
                
                if not user:
                    return False, "User not found", None
                
                if not user.is_active:
                    return False, "Account is disabled", None
                
                if not user.check_password(password):
                    return False, "Invalid password", None
                
                # Update last login
                user.last_login = datetime.now(timezone.utc)
                session.commit()
                
                return True, "Authentication successful", user
                
        except Exception as e:
            return False, f"Authentication error: {str(e)}", None
    
    def generate_tokens(self, user: User) -> Dict[str, str]:
        """
        Generate JWT access and refresh tokens
        
        Args:
            user: User object
            
        Returns:
            Dictionary containing access_token and refresh_token
        """
        now = datetime.now(timezone.utc)
        
        # Access token payload
        access_payload = {
            'user_id': user.id,
            'username': user.username,
            'role': user.role,
            'iat': now,
            'exp': now + current_app.config['JWT_ACCESS_TOKEN_EXPIRES'],
            'type': 'access'
        }
        
        # Refresh token payload
        refresh_payload = {
            'user_id': user.id,
            'iat': now,
            'exp': now + current_app.config['JWT_REFRESH_TOKEN_EXPIRES'],
            'type': 'refresh'
        }
        
        # Generate tokens
        access_token = jwt.encode(
            access_payload,
            current_app.config['JWT_SECRET_KEY'],
            algorithm='HS256'
        )
        
        refresh_token = jwt.encode(
            refresh_payload,
            current_app.config['JWT_SECRET_KEY'],
            algorithm='HS256'
        )
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': int(current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds())
        }
    
    def verify_token(self, token: str, token_type: str = 'access') -> Tuple[bool, str, Optional[Dict]]:
        """
        Verify and decode JWT token
        
        Args:
            token: JWT token string
            token_type: Type of token (access or refresh)
            
        Returns:
            Tuple of (valid, message, payload)
        """
        try:
            payload = jwt.decode(
                token,
                current_app.config['JWT_SECRET_KEY'],
                algorithms=['HS256']
            )
            
            # Check token type
            if payload.get('type') != token_type:
                return False, f"Invalid token type, expected {token_type}", None
            
            # Check expiration
            exp = payload.get('exp')
            if exp and datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
                return False, "Token has expired", None
            
            return True, "Token is valid", payload
            
        except jwt.ExpiredSignatureError:
            return False, "Token has expired", None
        except jwt.InvalidTokenError:
            return False, "Invalid token", None
        except Exception as e:
            return False, f"Token verification error: {str(e)}", None
    
    def refresh_access_token(self, refresh_token: str) -> Tuple[bool, str, Optional[Dict[str, str]]]:
        """
        Generate new access token using refresh token
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            Tuple of (success, message, new_tokens)
        """
        # Verify refresh token
        valid, message, payload = self.verify_token(refresh_token, 'refresh')
        
        if not valid:
            return False, message, None
        
        try:
            with get_db_session() as session:
                # Get user
                user = session.query(User).get(payload['user_id'])
                if not user or not user.is_active:
                    return False, "User not found or inactive", None
                
                # Generate new tokens
                tokens = self.generate_tokens(user)
                return True, "Tokens refreshed successfully", tokens
                
        except Exception as e:
            return False, f"Token refresh error: {str(e)}", None
    
    def create_api_key(self, user: User, name: str, permissions: List[str] = None, 
                      expires_days: int = None) -> Tuple[bool, str, Optional[str]]:
        """
        Create API key for user
        
        Args:
            user: User object
            name: Descriptive name for the API key
            permissions: List of permissions (read, write, admin)
            expires_days: Number of days until expiration
            
        Returns:
            Tuple of (success, message, api_key)
        """
        try:
            with get_db_session() as session:
                # Generate API key
                api_key = str(uuid.uuid4())
                
                # Calculate expiration
                expires_at = None
                if expires_days:
                    expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)
                
                # Create API key record
                api_key_record = APIKey(
                    user_id=user.id,
                    name=name,
                    key_hash=generate_password_hash(api_key),
                    permissions=permissions or ['read'],
                    expires_at=expires_at
                )
                
                session.add(api_key_record)
                session.commit()
                
                return True, "API key created successfully", api_key
                
        except Exception as e:
            return False, f"Error creating API key: {str(e)}", None
    
    def verify_api_key(self, api_key: str) -> Tuple[bool, str, Optional[User], Optional[APIKey]]:
        """
        Verify API key and return associated user
        
        Args:
            api_key: API key string
            
        Returns:
            Tuple of (valid, message, user, api_key_record)
        """
        try:
            with get_db_session() as session:
                # Find API key by hash
                api_key_records = session.query(APIKey).filter(
                    APIKey.is_active == True
                ).all()
                
                for record in api_key_records:
                    if record.check_key(api_key) and record.is_valid():
                        # Update usage tracking
                        record.last_used = datetime.now(timezone.utc)
                        record.usage_count += 1
                        session.commit()
                        
                        # Get associated user
                        user = session.query(User).get(record.user_id)
                        if user and user.is_active:
                            return True, "API key is valid", user, record
                        else:
                            return False, "Associated user is inactive", None, None
                
                return False, "Invalid API key", None, None
                
        except Exception as e:
            return False, f"API key verification error: {str(e)}", None, None
    
    def create_session(self, user: User, ip_address: str = None, 
                      user_agent: str = None) -> Tuple[bool, str, Optional[str]]:
        """
        Create user session
        
        Args:
            user: User object
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            Tuple of (success, message, session_id)
        """
        try:
            with get_db_session() as db_session:
                # Generate session ID
                session_id = str(uuid.uuid4())
                
                # Calculate expiration
                expires_at = datetime.now(timezone.utc) + timedelta(
                    days=current_app.config.get('SESSION_EXPIRE_DAYS', 7)
                )
                
                # Create session record
                user_session = UserSession(
                    user_id=user.id,
                    session_id=session_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    expires_at=expires_at
                )
                
                db_session.add(user_session)
                db_session.commit()
                
                return True, "Session created successfully", session_id
                
        except Exception as e:
            return False, f"Error creating session: {str(e)}", None
    
    def verify_session(self, session_id: str) -> Tuple[bool, str, Optional[User]]:
        """
        Verify session and return associated user
        
        Args:
            session_id: Session ID string
            
        Returns:
            Tuple of (valid, message, user)
        """
        try:
            with get_db_session() as db_session:
                # Find session
                user_session = db_session.query(UserSession).filter(
                    UserSession.session_id == session_id
                ).first()
                
                if not user_session or not user_session.is_valid():
                    return False, "Invalid or expired session", None
                
                # Get associated user
                user = db_session.query(User).get(user_session.user_id)
                if not user or not user.is_active:
                    return False, "Associated user is inactive", None
                
                return True, "Session is valid", user
                
        except Exception as e:
            return False, f"Session verification error: {str(e)}", None
    
    def logout_session(self, session_id: str) -> Tuple[bool, str]:
        """
        Logout/invalidate session
        
        Args:
            session_id: Session ID to invalidate
            
        Returns:
            Tuple of (success, message)
        """
        try:
            with get_db_session() as db_session:
                user_session = db_session.query(UserSession).filter(
                    UserSession.session_id == session_id
                ).first()
                
                if user_session:
                    user_session.is_active = False
                    db_session.commit()
                    return True, "Session logged out successfully"
                else:
                    return False, "Session not found"
                    
        except Exception as e:
            return False, f"Logout error: {str(e)}"
    
    def get_current_user_from_request(self) -> Tuple[bool, str, Optional[User]]:
        """
        Extract and verify user from current request
        Supports JWT tokens, API keys, and sessions
        
        Returns:
            Tuple of (authenticated, message, user)
        """
        # Try JWT token first
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            valid, message, payload = self.verify_token(token)
            if valid:
                try:
                    with get_db_session() as session:
                        user = session.query(User).get(payload['user_id'])
                        if user and user.is_active:
                            return True, "JWT authentication successful", user
                except Exception:
                    pass
        
        # Try API key
        api_key = request.headers.get('X-API-Key')
        if api_key:
            valid, message, user, _ = self.verify_api_key(api_key)
            if valid:
                return True, "API key authentication successful", user
        
        # Try session
        session_id = session.get('session_id')
        if session_id:
            valid, message, user = self.verify_session(session_id)
            if valid:
                return True, "Session authentication successful", user
        
        return False, "No valid authentication found", None
    
    def check_permission(self, user: User, required_permission: str, 
                        api_key_record: APIKey = None) -> bool:
        """
        Check if user has required permission
        
        Args:
            user: User object
            required_permission: Permission to check (read, write, admin)
            api_key_record: API key record if using API key auth
            
        Returns:
            True if user has permission
        """
        # Admin users have all permissions
        if user.role == 'admin':
            return True
        
        # If using API key, check API key permissions
        if api_key_record:
            return required_permission in api_key_record.permissions
        
        # Check user role permissions
        role_permissions = {
            'admin': ['read', 'write', 'admin'],
            'user': ['read', 'write'],
            'viewer': ['read']
        }
        
        user_permissions = role_permissions.get(user.role, [])
        return required_permission in user_permissions


# Global authentication manager instance
auth_manager = AuthenticationManager()
