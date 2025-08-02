#!/usr/bin/env python3
"""
Environment Configuration Validator and Setup Script
Validates environment variables and provides setup guidance
"""

import os
import sys
import logging
from pathlib import Path
from config import get_config
from dotenv import load_dotenv

def setup_logging():
    """Setup basic logging for the validator"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def check_env_file():
    """Check if .env file exists and load it"""
    env_path = Path('.env')
    
    if not env_path.exists():
        logging.warning("⚠️ .env file not found!")
        logging.info("📝 Creating .env file from .env.example...")
        
        example_path = Path('.env.example')
        if example_path.exists():
            # Copy .env.example to .env
            with open(example_path, 'r') as src, open(env_path, 'w') as dst:
                dst.write(src.read())
            logging.info("✅ Created .env file from .env.example")
            logging.warning("🔧 Please edit .env file and add your actual API keys")
        else:
            logging.error("❌ .env.example file not found!")
            return False
    
    # Load environment variables
    load_dotenv(env_path)
    logging.info("✅ Environment variables loaded from .env")
    return True

def validate_api_keys(config):
    """Validate API keys configuration"""
    logging.info("🔑 Validating API keys...")
    
    api_key_status = {
        'abuseipdb': config.API_KEYS['abuseipdb'],
        'shodan': config.API_KEYS['shodan'], 
        'virustotal': config.API_KEYS['virustotal']
    }
    
    missing_keys = []
    for service, key in api_key_status.items():
        if not key or key.startswith('your-'):
            missing_keys.append(service.upper())
        else:
            logging.info(f"✅ {service.upper()}: Configured")
    
    if missing_keys:
        logging.warning(f"⚠️ Missing or placeholder API keys: {', '.join(missing_keys)}")
        logging.info("\n📋 To get API keys:")
        logging.info("   • AbuseIPDB: https://www.abuseipdb.com/api")
        logging.info("   • Shodan: https://account.shodan.io/")
        logging.info("   • VirusTotal: https://www.virustotal.com/gui/join-us")
        return False
    else:
        logging.info("✅ All threat intelligence API keys configured")
        return True

def validate_security_tools(config):
    """Validate security tools availability"""
    logging.info("🔧 Validating security tools...")
    
    import shutil
    missing_tools = []
    available_tools = []
    
    for tool_name, tool_path in config.TOOLS.items():
        if shutil.which(tool_path):
            available_tools.append(tool_name)
            logging.info(f"✅ {tool_name}: Available at {tool_path}")
        else:
            missing_tools.append(tool_name)
            logging.warning(f"⚠️ {tool_name}: Not found ({tool_path})")
    
    if missing_tools:
        logging.warning(f"🚨 Missing tools: {', '.join(missing_tools)}")
        logging.info("\n📋 Installation instructions:")
        
        if 'nmap' in missing_tools:
            logging.info("   • Nmap: sudo apt-get install nmap (Linux) or brew install nmap (macOS)")
        if 'nikto' in missing_tools:
            logging.info("   • Nikto: sudo apt-get install nikto (Linux)")
        if 'sqlmap' in missing_tools:
            logging.info("   • SQLMap: sudo apt-get install sqlmap (Linux)")
        if 'subfinder' in missing_tools:
            logging.info("   • Subfinder: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        if 'gobuster' in missing_tools:
            logging.info("   • Gobuster: go install github.com/OJ/gobuster/v3@latest")
        
        return False
    else:
        logging.info("✅ All security tools available")
        return True

def validate_database(config):
    """Validate database configuration"""
    logging.info("🗄️ Validating database configuration...")
    
    db_uri = config.SQLALCHEMY_DATABASE_URI
    
    if 'sqlite' in db_uri:
        # For SQLite, check if directory exists
        if 'instance/' in db_uri:
            instance_dir = Path('instance')
            if not instance_dir.exists():
                instance_dir.mkdir()
                logging.info("✅ Created instance directory for SQLite database")
        logging.info("✅ SQLite database configuration valid")
        return True
    
    elif 'postgresql' in db_uri:
        logging.info("🐘 PostgreSQL database configured")
        # In a real scenario, you might want to test the connection
        logging.warning("⚠️ Please ensure PostgreSQL server is running and accessible")
        return True
    
    elif 'mysql' in db_uri:
        logging.info("🐬 MySQL database configured")
        logging.warning("⚠️ Please ensure MySQL server is running and accessible")
        return True
    
    else:
        logging.warning(f"⚠️ Unknown database type in URI: {db_uri}")
        return False

def validate_directories(config):
    """Validate and create required directories"""
    logging.info("📁 Validating directories...")
    
    directories = [
        'logs',
        'uploads', 
        'backups',
        'instance'
    ]
    
    for dir_name in directories:
        dir_path = Path(dir_name)
        if not dir_path.exists():
            dir_path.mkdir(parents=True, exist_ok=True)
            logging.info(f"✅ Created directory: {dir_name}")
        else:
            logging.info(f"✅ Directory exists: {dir_name}")
    
    return True

def validate_optional_services(config):
    """Validate optional services configuration"""
    logging.info("🔌 Checking optional services...")
    
    # Check Redis
    try:
        import redis
        r = redis.from_url(config.REDIS_URL)
        r.ping()
        logging.info("✅ Redis: Connected")
    except Exception as e:
        logging.warning(f"⚠️ Redis: Not available ({e})")
        logging.info("   Redis is optional but recommended for background tasks")
    
    # Check email configuration
    if config.ENABLE_EMAIL_NOTIFICATIONS:
        if config.MAIL_USERNAME and config.MAIL_PASSWORD:
            logging.info("✅ Email: Configured for notifications")
        else:
            logging.warning("⚠️ Email: Enabled but credentials missing")
    else:
        logging.info("ℹ️ Email notifications: Disabled")
    
    # Check Slack configuration
    if config.ENABLE_SLACK_NOTIFICATIONS:
        if config.SLACK_WEBHOOK_URL:
            logging.info("✅ Slack: Configured for notifications")
        else:
            logging.warning("⚠️ Slack: Enabled but webhook URL missing")
    else:
        logging.info("ℹ️ Slack notifications: Disabled")

def print_summary(api_keys_valid, tools_valid, db_valid):
    """Print validation summary"""
    logging.info("\n" + "="*50)
    logging.info("📊 CONFIGURATION VALIDATION SUMMARY")
    logging.info("="*50)
    
    overall_status = "✅ READY" if all([api_keys_valid, tools_valid, db_valid]) else "⚠️ NEEDS ATTENTION"
    
    logging.info(f"Overall Status: {overall_status}")
    logging.info(f"API Keys: {'✅ Valid' if api_keys_valid else '⚠️ Missing'}")
    logging.info(f"Security Tools: {'✅ Available' if tools_valid else '⚠️ Missing'}")
    logging.info(f"Database: {'✅ Valid' if db_valid else '❌ Invalid'}")
    
    if not api_keys_valid:
        logging.warning("\n🔧 NEXT STEPS:")
        logging.warning("1. Edit .env file and add your actual API keys")
        logging.warning("2. Run this script again to validate")
    
    if not tools_valid:
        logging.warning("\n🔧 NEXT STEPS:")
        logging.warning("1. Install missing security tools")
        logging.warning("2. Update tool paths in .env if needed")
        logging.warning("3. Run this script again to validate")
    
    if all([api_keys_valid, tools_valid, db_valid]):
        logging.info("\n🚀 READY TO START:")
        logging.info("   python app.py")

def main():
    """Main validation function"""
    setup_logging()
    
    logging.info("🔍 AI Bug Bounty Scanner - Environment Validator")
    logging.info("=" * 50)
    
    # Check and load .env file
    if not check_env_file():
        sys.exit(1)
    
    # Get configuration
    try:
        config = get_config()
        logging.info(f"📋 Configuration loaded: {config.__class__.__name__}")
    except Exception as e:
        logging.error(f"❌ Failed to load configuration: {e}")
        sys.exit(1)
    
    # Run validations
    api_keys_valid = validate_api_keys(config)
    tools_valid = validate_security_tools(config)
    db_valid = validate_database(config)
    
    # Create required directories
    validate_directories(config)
    
    # Check optional services
    validate_optional_services(config)
    
    # Print summary
    print_summary(api_keys_valid, tools_valid, db_valid)
    
    # Exit with appropriate code
    if all([api_keys_valid, tools_valid, db_valid]):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
