# database/models.py - Enhanced Database Models
"""
SQLAlchemy models for AI Bug Bounty Scanner
Enhanced with user authentication, progress tracking, and reporting
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, 
    Float, JSON, ForeignKey, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship, backref
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.hybrid import hybrid_property
from werkzeug.security import generate_password_hash, check_password_hash
from .database import Base


class User(Base):
    """User model for multi-user authentication"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    uuid = Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    first_name = Column(String(50))
    last_name = Column(String(50))
    
    # User roles and permissions
    role = Column(String(20), default='user')  # admin, user, viewer
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime)
    
    # Preferences
    preferences = Column(JSON, default=lambda: {})
    
    # API access
    api_key_hash = Column(String(255))
    api_key_created = Column(DateTime)
    
    # Relationships
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('ix_users_username', 'username'),
        Index('ix_users_email', 'email'),
        Index('ix_users_uuid', 'uuid'),
    )
    
    def set_password(self, password: str):
        """Set password with hashing"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password: str) -> bool:
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def generate_api_key(self) -> str:
        """Generate new API key"""
        api_key = str(uuid.uuid4())
        self.api_key_hash = generate_password_hash(api_key)
        self.api_key_created = datetime.now(timezone.utc)
        return api_key
    
    def check_api_key(self, api_key: str) -> bool:
        """Check API key against hash"""
        if not self.api_key_hash:
            return False
        return check_password_hash(self.api_key_hash, api_key)
    
    @hybrid_property
    def full_name(self):
        """Get user's full name"""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.username
    
    def to_dict(self, include_sensitive=False):
        """Convert to dictionary"""
        data = {
            'id': self.id,
            'uuid': str(self.uuid),
            'username': self.username,
            'email': self.email if include_sensitive else None,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'full_name': self.full_name,
            'role': self.role,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'preferences': self.preferences
        }
        return data


class Scan(Base):
    """Enhanced scan model with user association"""
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    uuid = Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False)
    
    # User association
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # Scan details
    target = Column(String(255), nullable=False)
    scan_types = Column(JSON, nullable=False)  # List of scan types
    
    # Status and timing
    status = Column(String(20), default='pending')  # pending, running, completed, failed, cancelled
    progress = Column(Float, default=0.0)  # 0.0 to 100.0
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    # Results
    vulnerabilities_found = Column(Integer, default=0)
    error_message = Column(Text)
    
    # Configuration
    options = Column(JSON, default=lambda: {})
    
    # Task tracking
    celery_task_id = Column(String(255))
    
    # Relationships
    user = relationship("User", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    agents = relationship("Agent", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
    progress_tracking = relationship("ScanProgress", back_populates="scan", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('ix_scans_user_id', 'user_id'),
        Index('ix_scans_status', 'status'),
        Index('ix_scans_created_at', 'created_at'),
        Index('ix_scans_uuid', 'uuid'),
    )
    
    @hybrid_property
    def duration(self):
        """Calculate scan duration"""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'uuid': str(self.uuid),
            'user_id': self.user_id,
            'target': self.target,
            'scan_types': self.scan_types,
            'status': self.status,
            'progress': self.progress,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration': str(self.duration) if self.duration else None,
            'vulnerabilities_found': self.vulnerabilities_found,
            'error_message': self.error_message,
            'options': self.options,
            'celery_task_id': self.celery_task_id
        }


class Vulnerability(Base):
    """Enhanced vulnerability model"""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    
    # Vulnerability details
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
    type = Column(String(50))  # xss, sqli, csrf, etc.
    
    # Location details
    url = Column(String(500))
    parameter = Column(String(255))
    method = Column(String(10))  # GET, POST, etc.
    
    # Technical details
    payload = Column(Text)
    evidence = Column(JSON)
    request_data = Column(Text)
    response_data = Column(Text)
    
    # Risk assessment
    cvss_score = Column(Float)
    cve_id = Column(String(20))
    cwe_id = Column(String(20))
    
    # Recommendations
    recommendation = Column(Text)
    remediation_effort = Column(String(20))  # low, medium, high
    
    # Status
    status = Column(String(20), default='open')  # open, acknowledged, fixed, false_positive
    
    # Timestamps
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")
    
    # Indexes
    __table_args__ = (
        Index('ix_vulnerabilities_scan_id', 'scan_id'),
        Index('ix_vulnerabilities_severity', 'severity'),
        Index('ix_vulnerabilities_type', 'type'),
        Index('ix_vulnerabilities_status', 'status'),
    )
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'type': self.type,
            'url': self.url,
            'parameter': self.parameter,
            'method': self.method,
            'payload': self.payload,
            'evidence': self.evidence,
            'cvss_score': self.cvss_score,
            'cve_id': self.cve_id,
            'cwe_id': self.cwe_id,
            'recommendation': self.recommendation,
            'remediation_effort': self.remediation_effort,
            'status': self.status,
            'discovered_at': self.discovered_at.isoformat() if self.discovered_at else None
        }


class Agent(Base):
    """Agent execution tracking"""
    __tablename__ = 'agents'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    
    name = Column(String(50), nullable=False)
    status = Column(String(20), default='pending')  # pending, running, completed, failed
    
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    results = Column(JSON)
    error_message = Column(Text)
    
    # Relationships
    scan = relationship("Scan", back_populates="agents")
    
    # Indexes
    __table_args__ = (
        Index('ix_agents_scan_id', 'scan_id'),
        Index('ix_agents_name', 'name'),
        Index('ix_agents_status', 'status'),
    )
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'name': self.name,
            'status': self.status,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'results': self.results,
            'error_message': self.error_message
        }


class ScanProgress(Base):
    """Detailed scan progress tracking"""
    __tablename__ = 'scan_progress'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    
    total_steps = Column(Integer, default=0)
    current_step = Column(Integer, default=0)
    status = Column(String(100))
    message = Column(Text)
    
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    scan = relationship("Scan", back_populates="progress_tracking")
    
    # Indexes
    __table_args__ = (
        Index('ix_scan_progress_scan_id', 'scan_id'),
    )
    
    @hybrid_property
    def progress_percentage(self):
        """Calculate progress percentage"""
        if self.total_steps == 0:
            return 0.0
        return (self.current_step / self.total_steps) * 100.0
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'total_steps': self.total_steps,
            'current_step': self.current_step,
            'progress_percentage': self.progress_percentage,
            'status': self.status,
            'message': self.message,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class Report(Base):
    """Report generation tracking"""
    __tablename__ = 'reports'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    
    format = Column(String(20), nullable=False)  # json, markdown, pdf
    content = Column(Text)  # For text formats
    file_path = Column(String(500))  # For file exports
    
    generated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    report_metadata = Column(JSON)
    
    # Relationships
    scan = relationship("Scan", back_populates="reports")
    
    # Indexes
    __table_args__ = (
        Index('ix_reports_scan_id', 'scan_id'),
        Index('ix_reports_format', 'format'),
    )
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'format': self.format,
            'file_path': self.file_path,
            'generated_at': self.generated_at.isoformat() if self.generated_at else None,
            'metadata': self.report_metadata,
            'has_content': bool(self.content)
        }


class APIKey(Base):
    """API key management"""
    __tablename__ = 'api_keys'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    name = Column(String(100), nullable=False)
    key_hash = Column(String(255), nullable=False)
    
    is_active = Column(Boolean, default=True)
    
    permissions = Column(JSON, default=lambda: ['read'])  # read, write, admin
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime)
    last_used = Column(DateTime)
    
    # Usage tracking
    usage_count = Column(Integer, default=0)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
    
    # Indexes
    __table_args__ = (
        Index('ix_api_keys_user_id', 'user_id'),
        Index('ix_api_keys_key_hash', 'key_hash'),
    )
    
    def check_key(self, api_key: str) -> bool:
        """Check API key against hash"""
        return check_password_hash(self.key_hash, api_key)
    
    def is_valid(self) -> bool:
        """Check if API key is valid and not expired"""
        if not self.is_active:
            return False
        if self.expires_at and self.expires_at < datetime.now(timezone.utc):
            return False
        return True
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'name': self.name,
            'is_active': self.is_active,
            'permissions': self.permissions,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'usage_count': self.usage_count
        }


class UserSession(Base):
    """User session tracking"""
    __tablename__ = 'user_sessions'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    session_id = Column(String(255), unique=True, nullable=False)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    # Indexes
    __table_args__ = (
        Index('ix_user_sessions_user_id', 'user_id'),
        Index('ix_user_sessions_session_id', 'session_id'),
    )
    
    def is_valid(self) -> bool:
        """Check if session is valid and not expired"""
        if not self.is_active:
            return False
        if self.expires_at and self.expires_at < datetime.now(timezone.utc):
            return False
        return True
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'ip_address': self.ip_address,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_active': self.is_active
        }
