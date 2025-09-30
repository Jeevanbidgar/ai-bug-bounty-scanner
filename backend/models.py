"""
Database models for AI Bug Bounty Scanner

Pydantic models for API responses and SQLAlchemy models for database persistence.
"""

import json
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from enum import Enum

from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.asyncio import AsyncAttrs
import uuid

from backend.database import Base

# SQLAlchemy Models
class Scan(Base, AsyncAttrs):
    """Scan configuration and tracking model"""
    __tablename__ = 'scans'

    id = Column(String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    target = Column(String(255), nullable=False)
    status = Column(String(20), nullable=False, default='pending')  # pending, running, completed, failed, cancelled
    scan_type = Column(String(50), nullable=False)  # Quick Scan, Full Scan, Custom
    started = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    completed = Column(DateTime, nullable=True)
    progress = Column(Integer, default=0)  # 0-100
    current_test = Column(String(255))  # Current test being performed
    agents = Column(Text)  # JSON string of agent names
    command_log = Column(Text)  # JSON string of executed commands and outputs
    target_validated = Column(Boolean, default=False)

    # Relationships
    vulnerabilities = relationship('Vulnerability', back_populates='scan', cascade='all, delete-orphan')
    reports = relationship('Report', back_populates='scan', cascade='all, delete-orphan')

    def to_dict(self):
        """Convert scan to dictionary for serialization"""
        vuln_counts = {
            'critical': sum(1 for v in self.vulnerabilities if v.severity.lower() == 'critical'),
            'high': sum(1 for v in self.vulnerabilities if v.severity.lower() == 'high'),
            'medium': sum(1 for v in self.vulnerabilities if v.severity.lower() == 'medium'),
            'low': sum(1 for v in self.vulnerabilities if v.severity.lower() == 'low')
        }

        return {
            'id': self.id,
            'target': self.target,
            'status': self.status,
            'scanType': self.scan_type,
            'started': self.started.isoformat() if self.started else None,
            'completed': self.completed.isoformat() if self.completed else None,
            'progress': self.progress,
            'current_test': self.current_test,
            'agents': json.loads(self.agents) if self.agents else [],
            'vulnerabilities': len(self.vulnerabilities),
            'critical': vuln_counts['critical'],
            'high': vuln_counts['high'],
            'medium': vuln_counts['medium'],
            'low': vuln_counts['low'],
            'target_validated': self.target_validated
        }

class Vulnerability(Base, AsyncAttrs):
    """Vulnerability findings model"""
    __tablename__ = 'vulnerabilities'

    id = Column(String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(50), ForeignKey('scans.id'), nullable=False)
    title = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False)  # Critical, High, Medium, Low
    cvss = Column(Float, nullable=True)
    description = Column(Text, nullable=False)
    url = Column(String(500), nullable=True)
    parameter = Column(String(100), nullable=True)
    payload = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    discovered_by = Column(String(100), nullable=False)  # Tool/agent name
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    false_positive = Column(Boolean, default=False)
    confirmed = Column(Boolean, default=False)
    evidence = Column(Text)  # JSON string with evidence data

    # Relationships
    scan = relationship('Scan', back_populates='vulnerabilities')

    def to_dict(self):
        """Convert vulnerability to dictionary for serialization"""
        return {
            'id': self.id,
            'scanId': self.scan_id,
            'title': self.title,
            'severity': self.severity,
            'cvss': self.cvss,
            'description': self.description,
            'url': self.url,
            'parameter': self.parameter,
            'payload': self.payload,
            'remediation': self.remediation,
            'discoveredBy': self.discovered_by,
            'timestamp': self.timestamp.isoformat(),
            'falsePositive': self.false_positive,
            'confirmed': self.confirmed,
            'evidence': json.loads(self.evidence) if self.evidence else None
        }

class Report(Base, AsyncAttrs):
    """Generated reports model"""
    __tablename__ = 'reports'

    id = Column(String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(50), ForeignKey('scans.id'), nullable=False)
    title = Column(String(255), nullable=False)
    generated = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    format = Column(String(10), nullable=False)  # PDF, HTML, JSON, CSV
    content = Column(Text, nullable=True)  # Report content (JSON/HTML)
    file_path = Column(String(500), nullable=True)  # Path to generated file
    summary = Column(Text)  # Executive summary

    # Relationships
    scan = relationship('Scan', back_populates='reports')

    def to_dict(self):
        """Convert report to dictionary for serialization"""
        scan = self.scan
        vulnerability_count = len(scan.vulnerabilities) if scan else 0

        # Determine severity based on highest severity vulnerability
        severity = 'Low'
        if scan and scan.vulnerabilities:
            severities = [v.severity for v in scan.vulnerabilities]
            if 'Critical' in severities:
                severity = 'Critical'
            elif 'High' in severities:
                severity = 'High'
            elif 'Medium' in severities:
                severity = 'Medium'

        return {
            'id': self.id,
            'title': self.title,
            'generated': self.generated.isoformat(),
            'target': scan.target if scan else 'Unknown',
            'vulnerabilities': vulnerability_count,
            'format': self.format,
            'filePath': self.file_path,
            'summary': self.summary,
            'severity': severity
        }

class Tool(Base, AsyncAttrs):
    """Available security tools model"""
    __tablename__ = 'tools'

    id = Column(String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text, nullable=False)
    category = Column(String(50), nullable=False)  # recon, web, network, exploit, etc.
    command_template = Column(Text, nullable=False)  # Command template with placeholders
    available = Column(Boolean, default=True)
    installed = Column(Boolean, default=False)
    version = Column(String(20), nullable=True)
    last_check = Column(DateTime, nullable=True)

    def to_dict(self):
        """Convert tool to dictionary for serialization"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'category': self.category,
            'commandTemplate': self.command_template,
            'available': self.available,
            'installed': self.installed,
            'version': self.version,
            'lastCheck': self.last_check.isoformat() if self.last_check else None
        }

class ReconPlan(Base, AsyncAttrs):
    """Human-readable reconnaissance plans"""
    __tablename__ = 'recon_plans'

    id = Column(String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    target_type = Column(String(50), nullable=False)  # domain, ip, url, cidr
    phases = Column(Text, nullable=False)  # JSON array of phases
    tools = Column(Text, nullable=False)  # JSON array of tool configurations
    created = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        """Convert recon plan to dictionary for serialization"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'targetType': self.target_type,
            'phases': json.loads(self.phases) if self.phases else [],
            'tools': json.loads(self.tools) if self.tools else [],
            'created': self.created.isoformat(),
            'updated': self.updated.isoformat()
        }

class WorkflowExecution(Base, AsyncAttrs):
    """Workflow execution tracking"""
    __tablename__ = 'workflow_executions'

    id = Column(String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    workflow_name = Column(String(100), nullable=False)
    target = Column(String(255), nullable=False)
    status = Column(String(20), nullable=False, default='pending')  # pending, running, completed, failed
    started_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    results = Column(Text, nullable=True)  # JSON string of execution results
    error = Column(Text, nullable=True)

    # Relationships
    steps = relationship('WorkflowStep', back_populates='execution', cascade='all, delete-orphan')

    def to_dict(self):
        """Convert workflow execution to dictionary"""
        return {
            'id': self.id,
            'workflow_name': self.workflow_name,
            'target': self.target,
            'status': self.status,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'results': json.loads(self.results) if self.results else None,
            'error': self.error,
            'steps_count': len(self.steps)
        }

class WorkflowStep(Base, AsyncAttrs):
    """Individual workflow step execution"""
    __tablename__ = 'workflow_steps'

    id = Column(String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    execution_id = Column(String(50), ForeignKey('workflow_executions.id'), nullable=False)
    tool_name = Column(String(100), nullable=False)
    parameters = Column(Text, nullable=False)  # JSON string of parameters
    result = Column(Text, nullable=True)  # JSON string of execution result
    status = Column(String(20), nullable=False, default='pending')  # pending, running, completed, failed

    # Relationships
    execution = relationship('WorkflowExecution', back_populates='steps')

    def to_dict(self):
        """Convert workflow step to dictionary"""
        return {
            'id': self.id,
            'execution_id': self.execution_id,
            'tool_name': self.tool_name,
            'parameters': json.loads(self.parameters) if self.parameters else {},
            'result': json.loads(self.result) if self.result else None,
            'status': self.status
        }

# Pydantic Models for API
class ScanType(str, Enum):
    QUICK = "Quick Scan"
    FULL = "Full Scan"
    CUSTOM = "Custom Scan"

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class ReportFormat(str, Enum):
    PDF = "PDF"
    HTML = "HTML"
    JSON = "JSON"
    CSV = "CSV"

# Request/Response Models
from pydantic import BaseModel, Field
from typing import Optional, List

class ScanCreate(BaseModel):
    target: str = Field(..., description="Target URL, domain, or IP address")
    scan_type: ScanType = Field(default=ScanType.QUICK, description="Type of scan to perform")
    agents: Optional[List[str]] = Field(default=None, description="List of agents to use (for custom scans)")

class ScanResponse(BaseModel):
    id: str
    target: str
    status: ScanStatus
    scan_type: ScanType
    started: Optional[str]
    completed: Optional[str]
    progress: int
    current_test: Optional[str]
    agents: List[str]
    vulnerabilities: int
    critical: int
    high: int
    medium: int
    low: int
    target_validated: bool

class VulnerabilityCreate(BaseModel):
    scan_id: str
    title: str
    severity: Severity
    cvss: Optional[float] = None
    description: str
    url: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    remediation: Optional[str] = None
    discovered_by: str
    evidence: Optional[Dict[str, Any]] = None

class VulnerabilityResponse(BaseModel):
    id: str
    scan_id: str
    title: str
    severity: Severity
    cvss: Optional[float]
    description: str
    url: Optional[str]
    parameter: Optional[str]
    payload: Optional[str]
    remediation: Optional[str]
    discovered_by: str
    timestamp: str
    false_positive: bool
    confirmed: bool
    evidence: Optional[Dict[str, Any]]

class ReportCreate(BaseModel):
    scan_id: str
    title: Optional[str] = None
    format: ReportFormat = ReportFormat.HTML

class ReportResponse(BaseModel):
    id: str
    title: str
    generated: str
    target: str
    vulnerabilities: int
    format: ReportFormat
    file_path: Optional[str]
    summary: Optional[str]
    severity: str

class ToolResponse(BaseModel):
    id: str
    name: str
    description: str
    category: str
    command_template: str
    available: bool
    installed: bool
    version: Optional[str]
    last_check: Optional[str]

class ReconPlanResponse(BaseModel):
    id: str
    name: str
    description: str
    target_type: str
    phases: List[Dict[str, Any]]
    tools: List[Dict[str, Any]]
    created: str
    updated: str

# Statistics Models
class SystemStats(BaseModel):
    total_scans: int
    active_scans: int
    total_vulnerabilities: int
    critical_issues: int
    tools_available: int
    system_health: str

class ScanStats(BaseModel):
    scan_id: str
    progress: int
    current_test: Optional[str]
    status: ScanStatus
    vulnerabilities_found: int
    start_time: Optional[str]
    estimated_completion: Optional[str]
