"""
Configuration Management for AI Bug Bounty Scanner
Centralizes environment variable handling and application configuration
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    """Base configuration class"""
    
    # Application Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-super-secret-key-change-this-in-production')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-jwt-secret-key-change-this-in-production')
    DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'
    TESTING = os.getenv('TESTING', 'False').lower() == 'true'
    
    # Database Configuration
    # Use the SQLALCHEMY_DATABASE_URI from .env file directly
    # For Windows, ensure proper path formatting
    default_db_uri = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///instance/bug_bounty_scanner.db')
    if default_db_uri.startswith('sqlite:///') and 'instance' in default_db_uri:
        # Ensure proper Windows path handling
        basedir = os.path.abspath(os.path.dirname(__file__))
        instance_dir = os.path.join(basedir, "instance")
        os.makedirs(instance_dir, exist_ok=True)
        db_file_path = os.path.join(instance_dir, "bug_bounty_scanner.db")
        SQLALCHEMY_DATABASE_URI = f'sqlite:///{db_file_path}'
    else:
        SQLALCHEMY_DATABASE_URI = default_db_uri
    SQLALCHEMY_TRACK_MODIFICATIONS = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS', 'False').lower() == 'true'
    SQLALCHEMY_POOL_SIZE = int(os.getenv('SQLALCHEMY_POOL_SIZE', '10'))
    SQLALCHEMY_POOL_TIMEOUT = int(os.getenv('SQLALCHEMY_POOL_TIMEOUT', '20'))
    SQLALCHEMY_POOL_RECYCLE = int(os.getenv('SQLALCHEMY_POOL_RECYCLE', '3600'))
    SQLALCHEMY_MAX_OVERFLOW = int(os.getenv('SQLALCHEMY_MAX_OVERFLOW', '20'))
    
    # Server Configuration
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', '5000'))
    
    # Security Configuration
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:3000,http://127.0.0.1:3000').split(',')
    JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', '3600'))
    JWT_REFRESH_TOKEN_EXPIRES = int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES', '86400'))
    PASSWORD_SALT = os.getenv('PASSWORD_SALT', 'your-password-salt-change-this')
    
    # File Upload Configuration
    MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', '16777216'))  # 16MB
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'uploads')
    ALLOWED_EXTENSIONS = os.getenv('ALLOWED_EXTENSIONS', 'txt,pdf,png,jpg,jpeg,gif,csv,json,xml').split(',')
    
    # External API Keys
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    
    # Security Tools Configuration
    NMAP_PATH = os.getenv('NMAP_PATH', 'nmap')
    NMAP_TIMEOUT = int(os.getenv('NMAP_TIMEOUT', '300'))
    NMAP_MAX_THREADS = int(os.getenv('NMAP_MAX_THREADS', '10'))
    
    NIKTO_PATH = os.getenv('NIKTO_PATH', 'nikto')
    NIKTO_TIMEOUT = int(os.getenv('NIKTO_TIMEOUT', '600'))
    
    SQLMAP_PATH = os.getenv('SQLMAP_PATH', 'sqlmap')
    SQLMAP_TIMEOUT = int(os.getenv('SQLMAP_TIMEOUT', '900'))
    
    BURP_API_URL = os.getenv('BURP_API_URL', 'http://127.0.0.1:1337')
    BURP_API_KEY = os.getenv('BURP_API_KEY', '')
    
    ZAP_API_URL = os.getenv('ZAP_API_URL', 'http://127.0.0.1:8080')
    ZAP_API_KEY = os.getenv('ZAP_API_KEY', '')
    
    SUBFINDER_PATH = os.getenv('SUBFINDER_PATH', 'subfinder')
    SUBFINDER_TIMEOUT = int(os.getenv('SUBFINDER_TIMEOUT', '300'))
    
    GOBUSTER_PATH = os.getenv('GOBUSTER_PATH', 'gobuster')
    GOBUSTER_TIMEOUT = int(os.getenv('GOBUSTER_TIMEOUT', '600'))
    
    # Scanning Configuration
    MAX_CONCURRENT_SCANS = int(os.getenv('MAX_CONCURRENT_SCANS', '5'))
    SCAN_TIMEOUT = int(os.getenv('SCAN_TIMEOUT', '3600'))
    SCAN_RESULTS_RETENTION_DAYS = int(os.getenv('SCAN_RESULTS_RETENTION_DAYS', '30'))
    AUTO_CLEANUP_ENABLED = os.getenv('AUTO_CLEANUP_ENABLED', 'True').lower() == 'true'
    
    # Rate Limiting
    RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', 'True').lower() == 'true'
    RATE_LIMIT_REQUESTS_PER_MINUTE = int(os.getenv('RATE_LIMIT_REQUESTS_PER_MINUTE', '60'))
    RATE_LIMIT_REQUESTS_PER_HOUR = int(os.getenv('RATE_LIMIT_REQUESTS_PER_HOUR', '1000'))
    
    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'logs/app.log')
    LOG_MAX_SIZE = int(os.getenv('LOG_MAX_SIZE', '10485760'))
    LOG_BACKUP_COUNT = int(os.getenv('LOG_BACKUP_COUNT', '5'))
    
    # Redis Configuration
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
    
    # Email Configuration
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', '587'))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', '')
    
    # Notification Configuration
    ENABLE_EMAIL_NOTIFICATIONS = os.getenv('ENABLE_EMAIL_NOTIFICATIONS', 'False').lower() == 'true'
    ENABLE_SLACK_NOTIFICATIONS = os.getenv('ENABLE_SLACK_NOTIFICATIONS', 'False').lower() == 'true'
    SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL', '')
    SLACK_CHANNEL = os.getenv('SLACK_CHANNEL', '#security-alerts')
    
    # External Service URLs
    CVE_API_URL = os.getenv('CVE_API_URL', 'https://cve.circl.lu/api')
    URLHAUS_API_URL = os.getenv('URLHAUS_API_URL', 'https://urlhaus-api.abuse.ch/v1')
    NVD_API_URL = os.getenv('NVD_API_URL', 'https://services.nvd.nist.gov/rest/json')
    
    # Cache Configuration
    CACHE_TYPE = os.getenv('CACHE_TYPE', 'simple')
    CACHE_DEFAULT_TIMEOUT = int(os.getenv('CACHE_DEFAULT_TIMEOUT', '300'))
    
    # Session Configuration
    SESSION_TYPE = os.getenv('SESSION_TYPE', 'filesystem')
    SESSION_PERMANENT = os.getenv('SESSION_PERMANENT', 'False').lower() == 'true'
    SESSION_USE_SIGNER = os.getenv('SESSION_USE_SIGNER', 'True').lower() == 'true'
    
    # Development Tools
    ENABLE_PROFILER = os.getenv('ENABLE_PROFILER', 'False').lower() == 'true'
    ENABLE_DEBUG_TOOLBAR = os.getenv('ENABLE_DEBUG_TOOLBAR', 'False').lower() == 'true'
    
    # AI/ML Configuration
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
    HUGGINGFACE_API_KEY = os.getenv('HUGGINGFACE_API_KEY', '')
    
    # Backup Configuration
    BACKUP_ENABLED = os.getenv('BACKUP_ENABLED', 'True').lower() == 'true'
    BACKUP_INTERVAL_HOURS = int(os.getenv('BACKUP_INTERVAL_HOURS', '24'))
    BACKUP_RETENTION_DAYS = int(os.getenv('BACKUP_RETENTION_DAYS', '7'))
    BACKUP_LOCATION = os.getenv('BACKUP_LOCATION', 'backups/')
    
    # Monitoring and Health Checks
    HEALTH_CHECK_ENABLED = os.getenv('HEALTH_CHECK_ENABLED', 'True').lower() == 'true'
    METRICS_ENABLED = os.getenv('METRICS_ENABLED', 'False').lower() == 'true'
    PROMETHEUS_PORT = int(os.getenv('PROMETHEUS_PORT', '9090'))
    
    # WebSocket Configuration
    SOCKETIO_ASYNC_MODE = os.getenv('SOCKETIO_ASYNC_MODE', 'threading')
    socketio_cors_default = 'http://localhost:3000,http://127.0.0.1:3000,http://localhost:5000,http://127.0.0.1:5000'
    socketio_cors_origins = os.getenv('SOCKETIO_CORS_ALLOWED_ORIGINS', socketio_cors_default)
    # Allow wildcard "*" for development
    if socketio_cors_origins.strip() == '*':
        SOCKETIO_CORS_ALLOWED_ORIGINS = "*"
    else:
        SOCKETIO_CORS_ALLOWED_ORIGINS = socketio_cors_origins.split(',')
    SOCKETIO_PING_TIMEOUT = int(os.getenv('SOCKETIO_PING_TIMEOUT', '60'))
    SOCKETIO_PING_INTERVAL = int(os.getenv('SOCKETIO_PING_INTERVAL', '25'))
    
    # Advanced Security
    ENABLE_2FA = os.getenv('ENABLE_2FA', 'False').lower() == 'true'
    PASSWORD_MIN_LENGTH = int(os.getenv('PASSWORD_MIN_LENGTH', '8'))
    PASSWORD_REQUIRE_UPPERCASE = os.getenv('PASSWORD_REQUIRE_UPPERCASE', 'True').lower() == 'true'
    PASSWORD_REQUIRE_LOWERCASE = os.getenv('PASSWORD_REQUIRE_LOWERCASE', 'True').lower() == 'true'
    PASSWORD_REQUIRE_NUMBERS = os.getenv('PASSWORD_REQUIRE_NUMBERS', 'True').lower() == 'true'
    PASSWORD_REQUIRE_SYMBOLS = os.getenv('PASSWORD_REQUIRE_SYMBOLS', 'False').lower() == 'true'
    
    # API Rate Limiting per Endpoint
    API_RATE_LIMIT_SCAN = os.getenv('API_RATE_LIMIT_SCAN', '10/minute')
    API_RATE_LIMIT_AUTH = os.getenv('API_RATE_LIMIT_AUTH', '30/minute')
    API_RATE_LIMIT_REPORTS = os.getenv('API_RATE_LIMIT_REPORTS', '100/hour')
    
    # Threat Intelligence Configuration
    THREAT_INTEL_CACHE_DURATION = int(os.getenv('THREAT_INTEL_CACHE_DURATION', '3600'))
    THREAT_INTEL_MAX_CONCURRENT_REQUESTS = int(os.getenv('THREAT_INTEL_MAX_CONCURRENT_REQUESTS', '5'))
    THREAT_INTEL_TIMEOUT = int(os.getenv('THREAT_INTEL_TIMEOUT', '30'))
    
    # Vulnerability Database
    VULN_DB_UPDATE_INTERVAL = int(os.getenv('VULN_DB_UPDATE_INTERVAL', '86400'))
    VULN_DB_AUTO_UPDATE = os.getenv('VULN_DB_AUTO_UPDATE', 'True').lower() == 'true'
    
    # Feature Flags
    ENABLE_ADVANCED_SCANNING = os.getenv('ENABLE_ADVANCED_SCANNING', 'True').lower() == 'true'
    ENABLE_THREAT_INTELLIGENCE = os.getenv('ENABLE_THREAT_INTELLIGENCE', 'True').lower() == 'true'
    ENABLE_AUTOMATED_REPORTING = os.getenv('ENABLE_AUTOMATED_REPORTING', 'True').lower() == 'true'
    ENABLE_REAL_TIME_MONITORING = os.getenv('ENABLE_REAL_TIME_MONITORING', 'True').lower() == 'true'
    ENABLE_API_FUZZING = os.getenv('ENABLE_API_FUZZING', 'True').lower() == 'true'
    ENABLE_SOCIAL_ENGINEERING_CHECKS = os.getenv('ENABLE_SOCIAL_ENGINEERING_CHECKS', 'False').lower() == 'true'

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.getenv('TEST_DATABASE_URL', 'sqlite:///:memory:')

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on FLASK_ENV environment variable"""
    env = os.getenv('FLASK_ENV', 'development')
    return config.get(env, config['default'])
