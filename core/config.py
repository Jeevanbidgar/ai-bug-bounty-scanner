# config.py - Enhanced Configuration Management
"""
Configuration management for AI Bug Bounty Scanner
Supports multiple environments with comprehensive environment variable support
"""

import os
from datetime import timedelta
from dotenv import load_dotenv
import logging

# Load environment variables from .env file
load_dotenv()

class BaseConfig:
    """Base configuration with common settings"""
    
    # Application settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DEBUG = False
    TESTING = False
    
    # Database settings
    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS', 'False').lower() == 'true'
    SQLALCHEMY_RECORD_QUERIES = True
    SQLALCHEMY_POOL_SIZE = int(os.environ.get('SQLALCHEMY_POOL_SIZE', 10))
    SQLALCHEMY_POOL_TIMEOUT = int(os.environ.get('SQLALCHEMY_POOL_TIMEOUT', 20))
    SQLALCHEMY_POOL_RECYCLE = int(os.environ.get('SQLALCHEMY_POOL_RECYCLE', 3600))
    SQLALCHEMY_MAX_OVERFLOW = int(os.environ.get('SQLALCHEMY_MAX_OVERFLOW', 20))
    
    # JWT settings
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', 3600)))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(seconds=int(os.environ.get('JWT_REFRESH_TOKEN_EXPIRES', 86400)))
    
    # External API Keys
    API_KEYS = {
        'abuseipdb': os.environ.get('ABUSEIPDB_API_KEY'),
        'shodan': os.environ.get('SHODAN_API_KEY'),
        'virustotal': os.environ.get('VIRUSTOTAL_API_KEY'),
        'burp': os.environ.get('BURP_API_KEY'),
        'zap': os.environ.get('ZAP_API_KEY'),
        'openai': os.environ.get('OPENAI_API_KEY'),
        'huggingface': os.environ.get('HUGGINGFACE_API_KEY')
    }
    
    # Security Tools Configuration
    TOOLS = {
        'nmap': os.environ.get('NMAP_PATH', 'nmap'),
        'nikto': os.environ.get('NIKTO_PATH', 'nikto'),
        'sqlmap': os.environ.get('SQLMAP_PATH', 'sqlmap'),
        'subfinder': os.environ.get('SUBFINDER_PATH', 'subfinder'),
        'gobuster': os.environ.get('GOBUSTER_PATH', 'gobuster')
    }
    
    # Tool Timeouts
    TIMEOUTS = {
        'nmap': int(os.environ.get('NMAP_TIMEOUT', 300)),
        'nikto': int(os.environ.get('NIKTO_TIMEOUT', 600)),
        'sqlmap': int(os.environ.get('SQLMAP_TIMEOUT', 900)),
        'subfinder': int(os.environ.get('SUBFINDER_TIMEOUT', 300)),
        'gobuster': int(os.environ.get('GOBUSTER_TIMEOUT', 600))
    }
    
    # External Service URLs
    EXTERNAL_URLS = {
        'burp_api': os.environ.get('BURP_API_URL', 'http://127.0.0.1:1337'),
        'zap_api': os.environ.get('ZAP_API_URL', 'http://127.0.0.1:8080'),
        'cve_api': os.environ.get('CVE_API_URL', 'https://cve.circl.lu/api'),
        'urlhaus_api': os.environ.get('URLHAUS_API_URL', 'https://urlhaus-api.abuse.ch/v1'),
        'nvd_api': os.environ.get('NVD_API_URL', 'https://services.nvd.nist.gov/rest/json')
    }
    
    # Scanning Configuration
    MAX_CONCURRENT_SCANS = int(os.environ.get('MAX_CONCURRENT_SCANS', 5))
    SCAN_TIMEOUT = int(os.environ.get('SCAN_TIMEOUT', 3600))
    SCAN_RESULTS_RETENTION_DAYS = int(os.environ.get('SCAN_RESULTS_RETENTION_DAYS', 30))
    AUTO_CLEANUP_ENABLED = os.environ.get('AUTO_CLEANUP_ENABLED', 'True').lower() == 'true'
    
    # Rate Limiting
    RATE_LIMIT_ENABLED = os.environ.get('RATE_LIMIT_ENABLED', 'True').lower() == 'true'
    RATE_LIMIT_REQUESTS_PER_MINUTE = int(os.environ.get('RATE_LIMIT_REQUESTS_PER_MINUTE', 60))
    RATE_LIMIT_REQUESTS_PER_HOUR = int(os.environ.get('RATE_LIMIT_REQUESTS_PER_HOUR', 1000))
    
    # Celery settings
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL') or 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND') or 'redis://localhost:6379/0'
    CELERY_TASK_SERIALIZER = 'json'
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_TIMEZONE = 'UTC'
    CELERY_ENABLE_UTC = True
    
    # Redis Configuration
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    
    # Email Configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', MAIL_USERNAME)
    
    # Notification Configuration
    ENABLE_EMAIL_NOTIFICATIONS = os.environ.get('ENABLE_EMAIL_NOTIFICATIONS', 'False').lower() == 'true'
    ENABLE_SLACK_NOTIFICATIONS = os.environ.get('ENABLE_SLACK_NOTIFICATIONS', 'False').lower() == 'true'
    SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL')
    SLACK_CHANNEL = os.environ.get('SLACK_CHANNEL', '#security-alerts')
    
    # File Upload Configuration
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 16777216))  # 16MB
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    ALLOWED_EXTENSIONS = set(os.environ.get('ALLOWED_EXTENSIONS', 'txt,pdf,png,jpg,jpeg,gif,csv,json,xml').split(','))
    
    # Cache Configuration
    CACHE_TYPE = os.environ.get('CACHE_TYPE', 'simple')
    CACHE_DEFAULT_TIMEOUT = int(os.environ.get('CACHE_DEFAULT_TIMEOUT', 300))
    CACHE_REDIS_URL = os.environ.get('CACHE_REDIS_URL', REDIS_URL)
    
    # Session Configuration
    SESSION_TYPE = os.environ.get('SESSION_TYPE', 'filesystem')
    SESSION_PERMANENT = os.environ.get('SESSION_PERMANENT', 'False').lower() == 'true'
    SESSION_USE_SIGNER = os.environ.get('SESSION_USE_SIGNER', 'True').lower() == 'true'
    SESSION_REDIS = os.environ.get('SESSION_REDIS', REDIS_URL)
    
    # Backup Configuration
    BACKUP_ENABLED = os.environ.get('BACKUP_ENABLED', 'True').lower() == 'true'
    BACKUP_INTERVAL_HOURS = int(os.environ.get('BACKUP_INTERVAL_HOURS', 24))
    BACKUP_RETENTION_DAYS = int(os.environ.get('BACKUP_RETENTION_DAYS', 7))
    BACKUP_LOCATION = os.environ.get('BACKUP_LOCATION', 'backups/')
    
    # Monitoring and Health Checks
    HEALTH_CHECK_ENABLED = os.environ.get('HEALTH_CHECK_ENABLED', 'True').lower() == 'true'
    METRICS_ENABLED = os.environ.get('METRICS_ENABLED', 'False').lower() == 'true'
    PROMETHEUS_PORT = int(os.environ.get('PROMETHEUS_PORT', 9090))
    
    # WebSocket Configuration
    SOCKETIO_ASYNC_MODE = os.environ.get('SOCKETIO_ASYNC_MODE', 'threading')
    SOCKETIO_CORS_ALLOWED_ORIGINS = os.environ.get('SOCKETIO_CORS_ALLOWED_ORIGINS', 'http://localhost:3000').split(',')
    SOCKETIO_PING_TIMEOUT = int(os.environ.get('SOCKETIO_PING_TIMEOUT', 60))
    SOCKETIO_PING_INTERVAL = int(os.environ.get('SOCKETIO_PING_INTERVAL', 25))
    
    # Advanced Security
    ENABLE_2FA = os.environ.get('ENABLE_2FA', 'False').lower() == 'true'
    PASSWORD_MIN_LENGTH = int(os.environ.get('PASSWORD_MIN_LENGTH', 8))
    PASSWORD_REQUIRE_UPPERCASE = os.environ.get('PASSWORD_REQUIRE_UPPERCASE', 'True').lower() == 'true'
    PASSWORD_REQUIRE_LOWERCASE = os.environ.get('PASSWORD_REQUIRE_LOWERCASE', 'True').lower() == 'true'
    PASSWORD_REQUIRE_NUMBERS = os.environ.get('PASSWORD_REQUIRE_NUMBERS', 'True').lower() == 'true'
    PASSWORD_REQUIRE_SYMBOLS = os.environ.get('PASSWORD_REQUIRE_SYMBOLS', 'False').lower() == 'true'
    
    # Threat Intelligence Configuration
    THREAT_INTEL_CACHE_DURATION = int(os.environ.get('THREAT_INTEL_CACHE_DURATION', 3600))
    THREAT_INTEL_MAX_CONCURRENT_REQUESTS = int(os.environ.get('THREAT_INTEL_MAX_CONCURRENT_REQUESTS', 5))
    THREAT_INTEL_TIMEOUT = int(os.environ.get('THREAT_INTEL_TIMEOUT', 30))
    
    # Vulnerability Database
    VULN_DB_UPDATE_INTERVAL = int(os.environ.get('VULN_DB_UPDATE_INTERVAL', 86400))
    VULN_DB_AUTO_UPDATE = os.environ.get('VULN_DB_AUTO_UPDATE', 'True').lower() == 'true'
    
    # Feature Flags
    FEATURES = {
        'advanced_scanning': os.environ.get('ENABLE_ADVANCED_SCANNING', 'True').lower() == 'true',
        'threat_intelligence': os.environ.get('ENABLE_THREAT_INTELLIGENCE', 'True').lower() == 'true',
        'automated_reporting': os.environ.get('ENABLE_AUTOMATED_REPORTING', 'True').lower() == 'true',
        'real_time_monitoring': os.environ.get('ENABLE_REAL_TIME_MONITORING', 'True').lower() == 'true',
        'api_fuzzing': os.environ.get('ENABLE_API_FUZZING', 'True').lower() == 'true',
        'social_engineering_checks': os.environ.get('ENABLE_SOCIAL_ENGINEERING_CHECKS', 'False').lower() == 'true'
    }
    
    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
    LOG_FILE = os.environ.get('LOG_FILE', 'logs/app.log')
    LOG_MAX_SIZE = int(os.environ.get('LOG_MAX_SIZE', 10485760))  # 10MB
    LOG_BACKUP_COUNT = int(os.environ.get('LOG_BACKUP_COUNT', 5))
    
    @staticmethod
    def validate_api_keys():
        """Validate that required API keys are present"""
        missing_keys = []
        
        # Check threat intelligence API keys
        if BaseConfig.FEATURES['threat_intelligence']:
            if not BaseConfig.API_KEYS['abuseipdb']:
                missing_keys.append('ABUSEIPDB_API_KEY')
            if not BaseConfig.API_KEYS['shodan']:
                missing_keys.append('SHODAN_API_KEY')
            if not BaseConfig.API_KEYS['virustotal']:
                missing_keys.append('VIRUSTOTAL_API_KEY')
        
        if missing_keys:
            logging.warning(f"Missing API keys: {', '.join(missing_keys)}")
            logging.warning("Some threat intelligence features may not work properly")
        
        return len(missing_keys) == 0
    
    @staticmethod
    def validate_tools():
        """Validate that required security tools are available"""
        import shutil
        missing_tools = []
        
        for tool_name, tool_path in BaseConfig.TOOLS.items():
            if not shutil.which(tool_path):
                missing_tools.append(f"{tool_name} ({tool_path})")
        
        if missing_tools:
            logging.warning(f"Missing security tools: {', '.join(missing_tools)}")
            logging.warning("Install missing tools for full functionality")
        
        return len(missing_tools) == 0

class DevelopmentConfig(BaseConfig):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///instance/bug_bounty_scanner.db'
    
    # Development-specific settings
    LOG_LEVEL = 'DEBUG'
    ENABLE_PROFILER = os.environ.get('ENABLE_PROFILER', 'False').lower() == 'true'
    ENABLE_DEBUG_TOOLBAR = os.environ.get('ENABLE_DEBUG_TOOLBAR', 'False').lower() == 'true'

class TestingConfig(BaseConfig):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    
    # Disable external services in testing
    ENABLE_EMAIL_NOTIFICATIONS = False
    ENABLE_SLACK_NOTIFICATIONS = False
    CELERY_TASK_ALWAYS_EAGER = True
    CELERY_TASK_EAGER_PROPAGATES = True

class ProductionConfig(BaseConfig):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://scanner_user:scanner_pass@localhost:5432/bug_bounty_scanner'
    
    # Production-specific settings
    LOG_LEVEL = 'WARNING'
    SSL_REDIRECT = os.environ.get('SSL_REDIRECT', 'True').lower() == 'true'
    
    # Stricter security in production
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(hours=12)
    
    # Enhanced rate limiting for production
    RATE_LIMIT_REQUESTS_PER_MINUTE = 30
    RATE_LIMIT_REQUESTS_PER_HOUR = 500

# Configuration mapping
config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

def get_config(config_name=None):
    """Get configuration based on environment"""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    config_class = config_by_name.get(config_name, config_by_name['default'])
    return config_class
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_TIMEZONE = 'UTC'
    CELERY_ENABLE_UTC = True
    
    # Redis settings
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
    
    # File upload settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    
    # Security settings
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None
    
    # Scanning settings
    SCAN_TIMEOUT = 3600  # 1 hour max scan time
    MAX_CONCURRENT_SCANS = 5
    RATE_LIMIT_PER_MINUTE = 60
    
    # External API keys
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')
    
    # Tool paths
    NUCLEI_PATH = os.environ.get('NUCLEI_PATH') or 'nuclei'
    SUBLIST3R_PATH = os.environ.get('SUBLIST3R_PATH') or 'sublist3r'
    AMASS_PATH = os.environ.get('AMASS_PATH') or 'amass'
    SQLMAP_PATH = os.environ.get('SQLMAP_PATH') or 'sqlmap'
    BURP_JAR_PATH = os.environ.get('BURP_JAR_PATH')


class DevelopmentConfig(BaseConfig):
    """Development configuration"""
    DEBUG = True
    
    # Database - Using SQLite for development
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        f'sqlite:///{os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance", "bug_bounty_scanner_dev.db")}'
    
    # Celery (development uses same Redis)
    CELERY_TASK_ALWAYS_EAGER = False  # Enable async tasks in development
    
    # Logging
    LOG_LEVEL = 'DEBUG'
    

class TestingConfig(BaseConfig):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    
    # Use in-memory database for tests
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False
    
    # Celery synchronous for testing
    CELERY_TASK_ALWAYS_EAGER = True
    CELERY_TASK_EAGER_PROPAGATES = True
    
    # Short JWT expiry for testing
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=5)
    

class ProductionConfig(BaseConfig):
    """Production configuration"""
    
    # Database - use environment variable
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://scanner_user:scanner_pass@localhost:5432/bug_bounty_scanner'
    
    # Security enhancements
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Celery production settings
    CELERY_TASK_ALWAYS_EAGER = False
    CELERY_WORKER_CONCURRENCY = 4
    CELERY_TASK_SOFT_TIME_LIMIT = 300
    CELERY_TASK_TIME_LIMIT = 600
    
    # Logging
    LOG_LEVEL = 'INFO'
    

class DockerConfig(BaseConfig):
    """Docker container configuration"""
    
    # Database connection for Docker
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://scanner_user:scanner_pass@db:5432/bug_bounty_scanner'
    
    # Redis connection for Docker
    CELERY_BROKER_URL = 'redis://redis:6379/0'
    CELERY_RESULT_BACKEND = 'redis://redis:6379/0'
    REDIS_URL = 'redis://redis:6379/0'
    

# Configuration mapping
config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'docker': DockerConfig
}


def get_config():
    """Get configuration based on environment"""
    env = os.environ.get('FLASK_ENV', 'development')
    return config_by_name.get(env, DevelopmentConfig)
