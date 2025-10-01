"""
Database models for AI Bug Bounty Scanner

Pydantic models for API responses and SQLAlchemy models for database persistence.
"""

import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any

from pydantic import BaseModel, Field
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.asyncio import AsyncAttrs

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
            'scan_type': self.scan_type,  # Changed from 'scanType' to match Pydantic model
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
    """Workflow execution tracking model"""
    __tablename__ = 'workflow_executions'

    id = Column(String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    workflow_id = Column(String(100), nullable=False)
    workflow_name = Column(String(100), nullable=False)
    status = Column(String(20), nullable=False, default='pending')  # pending, running, completed, failed, cancelled
    started = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    completed = Column(DateTime, nullable=True)
    inputs = Column(Text)  # JSON string of input parameters
    error_message = Column(Text)

    # Relationships
    steps = relationship('WorkflowStep', back_populates='execution', cascade='all, delete-orphan')
    artifacts = relationship('WorkflowArtifact', back_populates='execution', cascade='all, delete-orphan')
    findings = relationship('WorkflowFinding', back_populates='execution', cascade='all, delete-orphan')

    def to_dict(self):
        """Convert workflow execution to dictionary"""
        return {
            'id': self.id,
            'workflow_id': self.workflow_id,
            'workflow_name': self.workflow_name,
            'status': self.status,
            'started': self.started.isoformat() if self.started else None,
            'completed': self.completed.isoformat() if self.completed else None,
            'inputs': json.loads(self.inputs) if self.inputs else {},
            'error_message': self.error_message,
            'steps_count': len(self.steps),
            'artifacts_count': len(self.artifacts),
            'findings_count': len(self.findings)
        }

class WorkflowStep(Base, AsyncAttrs):
    """Individual step execution within a workflow"""
    __tablename__ = 'workflow_steps'

    id = Column(String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    execution_id = Column(String(50), ForeignKey('workflow_executions.id'), nullable=False)
    step_id = Column(String(100), nullable=False)  # ID from workflow template
    step_name = Column(String(100), nullable=False)
    status = Column(String(20), nullable=False, default='pending')  # pending, running, completed, failed, cancelled
    started = Column(DateTime, nullable=True)
    completed = Column(DateTime, nullable=True)
    command = Column(Text)  # JSON string of executed command
    exit_code = Column(Integer, nullable=True)
    stdout = Column(Text)
    stderr = Column(Text)
    error_message = Column(Text)
    artifacts = Column(Text)  # JSON string of produced artifacts

    # Relationships
    execution = relationship('WorkflowExecution', back_populates='steps')

    def to_dict(self):
        """Convert workflow step to dictionary"""
        return {
            'id': self.id,
            'execution_id': self.execution_id,
            'step_id': self.step_id,
            'step_name': self.step_name,
            'status': self.status,
            'started': self.started.isoformat() if self.started else None,
            'completed': self.completed.isoformat() if self.completed else None,
            'command': json.loads(self.command) if self.command else None,
            'exit_code': self.exit_code,
            'stdout': self.stdout,
            'stderr': self.stderr,
            'error_message': self.error_message,
            'artifacts': json.loads(self.artifacts) if self.artifacts else []
        }

class WorkflowArtifact(Base, AsyncAttrs):
    """Artifacts produced by workflow steps"""
    __tablename__ = 'workflow_artifacts'

    id = Column(String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    execution_id = Column(String(50), ForeignKey('workflow_executions.id'), nullable=False)
    step_id = Column(String(100), nullable=False)
    artifact_name = Column(String(100), nullable=False)
    artifact_type = Column(String(50), nullable=False)  # file, data, etc.
    file_path = Column(String(500), nullable=True)  # Path if file artifact
    content = Column(Text, nullable=True)  # Content if data artifact
    artifact_metadata = Column(Text)  # JSON string of metadata

    # Relationships
    execution = relationship('WorkflowExecution', back_populates='artifacts')

    def to_dict(self):
        """Convert workflow artifact to dictionary"""
        return {
            'id': self.id,
            'execution_id': self.execution_id,
            'step_id': self.step_id,
            'artifact_name': self.artifact_name,
            'artifact_type': self.artifact_type,
            'file_path': self.file_path,
            'content': self.content,
            'metadata': json.loads(self.artifact_metadata) if self.artifact_metadata else {}
        }

class WorkflowFinding(Base, AsyncAttrs):
    """Findings extracted from workflow outputs (e.g., nuclei results)"""
    __tablename__ = 'workflow_findings'

    id = Column(String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    execution_id = Column(String(50), ForeignKey('workflow_executions.id'), nullable=False)
    step_id = Column(String(100), nullable=False)
    finding_type = Column(String(50), nullable=False)  # vulnerability, subdomain, port, etc.
    title = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=True)  # Critical, High, Medium, Low, Info
    description = Column(Text, nullable=True)
    url = Column(String(500), nullable=True)
    cvss = Column(Float, nullable=True)
    cwe = Column(String(20), nullable=True)
    tags = Column(Text)  # JSON string of tags
    evidence = Column(Text)  # JSON string of evidence data
    raw_data = Column(Text)  # Original JSON from tool

    # Relationships
    execution = relationship('WorkflowExecution', back_populates='findings')

    def to_dict(self):
        """Convert workflow finding to dictionary"""
        return {
            'id': self.id,
            'execution_id': self.execution_id,
            'step_id': self.step_id,
            'finding_type': self.finding_type,
            'title': self.title,
            'severity': self.severity,
            'description': self.description,
            'url': self.url,
            'cvss': self.cvss,
            'cwe': self.cwe,
            'tags': json.loads(self.tags) if self.tags else [],
            'evidence': json.loads(self.evidence) if self.evidence else {},
            'raw_data': json.loads(self.raw_data) if self.raw_data else {}
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
    name: str
    description: str
    category: str
    status: str
    installed: bool
    available: bool
    version: Optional[str]
    raw_version: Optional[str] = None
    path: Optional[str] = None
    command_template: List[str]
    output_format: str
    os_dependencies: List[str] = Field(default_factory=list)
    missing_dependencies: List[str] = Field(default_factory=list)
    last_check: Optional[str] = None
    last_seen: Optional[str] = None
    last_error: Optional[str] = None

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

# Workflow Models
class WorkflowStepOutput(BaseModel):
    """Output specification for a workflow step"""
    name: str = Field(..., description="Output name")
    type: str = Field(..., description="Output type (file, data, etc.)")
    path: Optional[str] = Field(None, description="File path if file output")
    description: Optional[str] = Field(None, description="Output description")

class WorkflowStepRetry(BaseModel):
    """Retry policy for a workflow step"""
    max_attempts: int = Field(default=1, description="Maximum retry attempts")
    delay: int = Field(default=0, description="Delay between retries in seconds")
    backoff_factor: float = Field(default=1.0, description="Exponential backoff factor")

class WorkflowStepModel(BaseModel):
    """Individual step in a workflow template"""
    id: str = Field(..., description="Unique step identifier")
    name: str = Field(..., description="Human-readable step name")
    description: Optional[str] = Field(None, description="Step description")
    needs: List[str] = Field(default_factory=list, description="List of step IDs this step depends on")
    run: List[str] = Field(..., description="Command to execute as argv array")
    env: Dict[str, str] = Field(default_factory=dict, description="Environment variables")
    timeout: int = Field(default=300, description="Timeout in seconds")
    retry: WorkflowStepRetry = Field(default_factory=WorkflowStepRetry, description="Retry policy")
    outputs: List[WorkflowStepOutput] = Field(default_factory=list, description="Expected outputs")
    working_directory: Optional[str] = Field(None, description="Working directory for the step")

class WorkflowTemplate(BaseModel):
    """Complete workflow template"""
    id: str = Field(..., description="Unique workflow identifier")
    name: str = Field(..., description="Human-readable workflow name")
    description: str = Field(..., description="Workflow description")
    category: str = Field(..., description="Workflow category")
    version: str = Field(default="1.0.0", description="Workflow version")
    author: Optional[str] = Field(None, description="Workflow author")
    tags: List[str] = Field(default_factory=list, description="Workflow tags")
    inputs: Dict[str, str] = Field(default_factory=dict, description="Input parameters schema")
    steps: List[WorkflowStepModel] = Field(..., description="Workflow steps")
    outputs: List[WorkflowStepOutput] = Field(default_factory=list, description="Workflow-level outputs")

class WorkflowExecutionResponse(BaseModel):
    """Response for workflow execution"""
    execution_id: str = Field(..., description="Unique execution identifier")
    status: str = Field(..., description="Execution status")
    message: str = Field(..., description="Status message")

class WorkflowExecutionStatus(BaseModel):
    """Status of a workflow execution"""
    id: str = Field(..., description="Execution ID")
    workflow_id: str = Field(..., description="Workflow template ID")
    workflow_name: str = Field(..., description="Workflow name")
    status: str = Field(..., description="Execution status")
    started: Optional[str] = Field(None, description="Start time")
    completed: Optional[str] = Field(None, description="Completion time")
    inputs: Dict[str, str] = Field(default_factory=dict, description="Input parameters")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    steps_count: int = Field(default=0, description="Number of steps")
    artifacts_count: int = Field(default=0, description="Number of artifacts")
    findings_count: int = Field(default=0, description="Number of findings")

class WorkflowStepStatus(BaseModel):
    """Status of an individual workflow step"""
    id: str = Field(..., description="Step execution ID")
    execution_id: str = Field(..., description="Execution ID")
    step_id: str = Field(..., description="Template step ID")
    step_name: str = Field(..., description="Step name")
    status: str = Field(..., description="Step status")
    started: Optional[str] = Field(None, description="Start time")
    completed: Optional[str] = Field(None, description="Completion time")
    command: Optional[List[str]] = Field(None, description="Executed command")
    exit_code: Optional[int] = Field(None, description="Exit code")
    error_message: Optional[str] = Field(None, description="Error message")
    artifacts: List[str] = Field(default_factory=list, description="Produced artifacts")

class WorkflowTemplateResponse(BaseModel):
    """Response containing workflow template information"""
    id: str = Field(..., description="Workflow ID")
    name: str = Field(..., description="Workflow name")
    description: str = Field(..., description="Workflow description")
    category: str = Field(..., description="Workflow category")
    version: str = Field(..., description="Workflow version")
    author: Optional[str] = Field(None, description="Workflow author")
    tags: List[str] = Field(default_factory=list, description="Workflow tags")
    inputs: Dict[str, str] = Field(default_factory=dict, description="Input schema")
    steps_count: int = Field(..., description="Number of steps")
    outputs_count: int = Field(..., description="Number of outputs")

class WorkflowExecuteRequest(BaseModel):
    """Request to execute a workflow"""
    workflow_id: Optional[str] = Field(None, description="Workflow template ID")
    template: Optional[WorkflowTemplate] = Field(None, description="Inline workflow template")
    inputs: Dict[str, str] = Field(default_factory=dict, description="Input parameters")
    working_directory: Optional[str] = Field(None, description="Working directory")
