"""
Application configuration management
"""

import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field

class Settings(BaseSettings):
    """Application settings with environment variable support"""
    
    # Application
    app_name: str = "AI Bug Bounty Scanner"
    app_version: str = "2.0.0"
    environment: str = Field(default="development", env="ENVIRONMENT")
    debug: bool = Field(default=True, env="DEBUG")
    
    # Server
    host: str = Field(default="127.0.0.1", env="HOST")
    port: int = Field(default=8000, env="PORT")
    
    # Database
    database_file: Optional[str] = Field(default=None, env="DATABASE_FILE")
    
    # Security
    secret_key: str = Field(default="dev-secret-key-change-in-production", env="SECRET_KEY")
    enable_auth: bool = Field(default=False, env="ENABLE_AUTH")
    
    # Tools
    tools_directory: Optional[str] = Field(default=None, env="TOOLS_DIRECTORY")
    enable_docker: bool = Field(default=True, env="ENABLE_DOCKER")
    docker_timeout: int = Field(default=3600, env="DOCKER_TIMEOUT")  # 1 hour
    
    # Scanning
    max_concurrent_scans: int = Field(default=5, env="MAX_CONCURRENT_SCANS")
    scan_timeout: int = Field(default=7200, env="SCAN_TIMEOUT")  # 2 hours
    
    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_file: Optional[str] = Field(default=None, env="LOG_FILE")
    
    # Sentry Error Tracking
    sentry_dsn: Optional[str] = Field(default=None, env="SENTRY_DSN")
    
    # Rate Limiting
    enable_rate_limiting: bool = Field(default=True, env="ENABLE_RATE_LIMITING")
    rate_limit_storage: str = Field(default="memory://", env="RATE_LIMIT_STORAGE")
    
    # Resource Limits
    max_memory_mb: int = Field(default=1024, env="MAX_MEMORY_MB")
    max_cpu_percent: float = Field(default=80.0, env="MAX_CPU_PERCENT")
    max_execution_time: int = Field(default=600, env="MAX_EXECUTION_TIME")
    max_concurrent_tools: int = Field(default=3, env="MAX_CONCURRENT_TOOLS")
    
    # Monitoring
    enable_metrics: bool = Field(default=True, env="ENABLE_METRICS")
    metrics_port: int = Field(default=8000, env="METRICS_PORT")
    
    # Updates
    check_for_updates: bool = Field(default=True, env="CHECK_FOR_UPDATES")
    update_channel: str = Field(default="stable", env="UPDATE_CHANNEL")  # stable, beta, dev
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"  # Ignore extra fields from .env

# Global settings instance
settings = Settings()

def get_data_directory() -> Path:
    """Get the application data directory"""
    if settings.environment == "development":
        project_root = Path(__file__).resolve().parent.parent
        data_dir = project_root / "data"
    elif os.name == "nt":  # Windows
        app_data = Path(os.getenv("LOCALAPPDATA", "~")).expanduser()
        data_dir = app_data / "AIBugBountyScanner"
    else:  # Linux/Mac
        home = Path.home()
        data_dir = home / ".local" / "share" / "ai-bug-bounty-scanner"
    
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir

def get_scans_directory() -> Path:
    """Get directory for storing scan results"""
    scans_dir = get_data_directory() / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    return scans_dir

def get_reports_directory() -> Path:
    """Get directory for storing generated reports"""
    reports_dir = get_data_directory() / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir

def get_logs_directory() -> Path:
    """Get directory for application logs"""
    logs_dir = get_data_directory() / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    return logs_dir

def get_workflows_directory() -> Path:
    """Get directory for user workflows"""
    workflows_dir = get_data_directory() / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    return workflows_dir

