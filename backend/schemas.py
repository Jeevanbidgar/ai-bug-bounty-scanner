"""
Pydantic schemas for request/response validation.
Enhanced with security validations to prevent injection attacks.
"""

import re
from typing import Optional, List
from pydantic import BaseModel, Field, validator, field_validator
from datetime import datetime


class ScanCreateRequest(BaseModel):
    """Schema for creating a new scan"""
    target: str = Field(..., min_length=3, max_length=255, description="Target domain or IP address")
    scan_type: str = Field(default="quick", regex="^(quick|deep|custom)$", description="Type of scan to perform")
    tools: List[str] = Field(default_factory=list, description="List of tools to use")
    description: Optional[str] = Field(None, max_length=500, description="Optional scan description")
    
    @field_validator('target')
    @classmethod
    def validate_target(cls, v: str) -> str:
        """Validate target to prevent command injection"""
        if not v:
            raise ValueError('Target cannot be empty')
        
        # Remove leading/trailing whitespace
        v = v.strip()
        
        # Check for dangerous characters
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '<', '>', '\\x', '../', '..\\']
        for char in dangerous_chars:
            if char in v:
                raise ValueError(f'Target contains dangerous character: {char}')
        
        # Validate domain or IP format
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
        url_pattern = r'^https?://[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*'
        
        if not (re.match(domain_pattern, v) or 
                re.match(ip_pattern, v) or 
                re.match(cidr_pattern, v) or 
                re.match(url_pattern, v)):
            raise ValueError('Invalid target format. Must be a valid domain, IP address, CIDR, or URL')
        
        # Additional IP validation
        if re.match(ip_pattern, v):
            octets = v.split('.')
            for octet in octets:
                if not 0 <= int(octet) <= 255:
                    raise ValueError('Invalid IP address: octets must be 0-255')
        
        return v
    
    @field_validator('tools')
    @classmethod
    def validate_tools(cls, v: List[str]) -> List[str]:
        """Validate tool names"""
        allowed_tools = [
            'subfinder', 'amass', 'nuclei', 'nmap', 'sqlmap',
            'ffuf', 'gobuster', 'waybackurls', 'gau', 'naabu'
        ]
        
        for tool in v:
            if tool not in allowed_tools:
                raise ValueError(f'Unknown tool: {tool}. Allowed tools: {", ".join(allowed_tools)}')
        
        return v


class ToolExecuteRequest(BaseModel):
    """Schema for executing a security tool"""
    tool_name: str = Field(..., min_length=1, max_length=50)
    target: str = Field(..., min_length=3, max_length=255)
    arguments: Optional[dict] = Field(default_factory=dict, description="Additional tool arguments")
    timeout: Optional[int] = Field(default=300, ge=10, le=3600, description="Execution timeout in seconds")
    
    @field_validator('tool_name')
    @classmethod
    def validate_tool_name(cls, v: str) -> str:
        """Validate tool name"""
        if not re.match(r'^[a-z0-9_-]+$', v):
            raise ValueError('Tool name can only contain lowercase letters, numbers, hyphens, and underscores')
        return v
    
    @field_validator('target')
    @classmethod
    def validate_target(cls, v: str) -> str:
        """Reuse target validation from ScanCreateRequest"""
        return ScanCreateRequest.validate_target(v)


class ReportGenerateRequest(BaseModel):
    """Schema for generating a report"""
    scan_id: str = Field(..., description="Scan ID to generate report for")
    format: str = Field(default="html", regex="^(html|pdf|json|markdown)$")
    include_raw_data: bool = Field(default=False, description="Include raw tool outputs")
    
    @field_validator('scan_id')
    @classmethod
    def validate_scan_id(cls, v: str) -> str:
        """Validate scan ID format (UUID)"""
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        if not re.match(uuid_pattern, v, re.IGNORECASE):
            raise ValueError('Invalid scan ID format. Must be a valid UUID')
        return v


class WorkflowCreateRequest(BaseModel):
    """Schema for creating a workflow"""
    name: str = Field(..., min_length=3, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    target: str = Field(..., min_length=3, max_length=255)
    steps: List[dict] = Field(..., min_items=1, description="Workflow steps")
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate workflow name"""
        if not re.match(r'^[a-zA-Z0-9\s_-]+$', v):
            raise ValueError('Workflow name can only contain letters, numbers, spaces, hyphens, and underscores')
        return v.strip()
    
    @field_validator('target')
    @classmethod
    def validate_target(cls, v: str) -> str:
        """Reuse target validation"""
        return ScanCreateRequest.validate_target(v)


class ToolUpdateRequest(BaseModel):
    """Schema for updating tool configuration"""
    enabled: Optional[bool] = Field(None, description="Enable/disable tool")
    timeout: Optional[int] = Field(None, ge=10, le=3600, description="Default timeout")
    custom_args: Optional[str] = Field(None, max_length=500, description="Custom arguments")
    
    @field_validator('custom_args')
    @classmethod
    def validate_custom_args(cls, v: Optional[str]) -> Optional[str]:
        """Validate custom arguments"""
        if v is None:
            return v
        
        # Check for dangerous characters
        dangerous = [';', '&', '|', '`', '$', '$(', '${']
        for char in dangerous:
            if char in v:
                raise ValueError(f'Custom arguments contain dangerous pattern: {char}')
        
        return v.strip()


# Response schemas
class ScanResponse(BaseModel):
    """Schema for scan response"""
    id: str
    target: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class ToolResponse(BaseModel):
    """Schema for tool response"""
    name: str
    description: str
    category: str
    installed: bool
    version: Optional[str] = None
    
    class Config:
        from_attributes = True


class ErrorResponse(BaseModel):
    """Schema for error responses"""
    error: str
    message: str
    details: Optional[dict] = None
    path: Optional[str] = None


class HealthResponse(BaseModel):
    """Schema for health check response"""
    status: str
    checks: Optional[dict] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
