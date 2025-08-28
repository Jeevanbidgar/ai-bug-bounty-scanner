# AI Bug Bounty Scanner Backend

from flask import Flask, request, jsonify, send_from_directory, Response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from datetime import datetime, timezone
import uuid
import json
import time
import asyncio
import threading
import logging
from typing import Dict, List, Any
import os
from dotenv import load_dotenv
from config import get_config

# Load environment variables from .env file
load_dotenv()

# Get configuration
Config = get_config()

# Configure logging
log_level = getattr(logging, Config.LOG_LEVEL.upper())
os.makedirs(os.path.dirname(Config.LOG_FILE) if os.path.dirname(Config.LOG_FILE) else 'logs', exist_ok=True)

# Create handlers with UTF-8 encoding for Windows compatibility
file_handler = logging.FileHandler(Config.LOG_FILE, encoding='utf-8')
console_handler = logging.StreamHandler()

# Set formatting
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Configure root logger
logging.basicConfig(
    level=log_level,
    handlers=[file_handler, console_handler]
)

logger = logging.getLogger(__name__)
logger.info("AI Bug Bounty Scanner starting up...")

# Import real scanning agents
from agents import SecurityValidator, ReconAgent, WebAppAgent, ReportAgent

ENHANCEMENTS_AVAILABLE = False

# Initialize Flask app
app = Flask(__name__)

# Load configuration from config class
app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)

# CORS configuration from config
CORS(app, origins=Config.CORS_ORIGINS)

# SocketIO configuration from config
socketio = SocketIO(
    app, 
    cors_allowed_origins=Config.SOCKETIO_CORS_ALLOWED_ORIGINS,
    async_mode=Config.SOCKETIO_ASYNC_MODE,
    ping_timeout=Config.SOCKETIO_PING_TIMEOUT,
    ping_interval=Config.SOCKETIO_PING_INTERVAL
)

# Database Models
class Scan(db.Model):
    __tablename__ = 'scans'
    
    id = db.Column(db.String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    target = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, running, completed, failed
    scan_type = db.Column(db.String(50), nullable=False)  # Quick Scan, Full Scan, Custom
    started = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    completed = db.Column(db.DateTime, nullable=True)
    progress = db.Column(db.Integer, default=0)  # 0-100
    current_test = db.Column(db.String(255))  # Current test being performed
    agents = db.Column(db.Text)  # JSON string of agent names
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        # Count vulnerabilities by severity
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
            'low': vuln_counts['low']
        }

class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = db.Column(db.String(50), db.ForeignKey('scans.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # Critical, High, Medium, Low
    cvss = db.Column(db.Float, nullable=True)
    description = db.Column(db.Text, nullable=False)
    url = db.Column(db.String(500), nullable=True)
    parameter = db.Column(db.String(100), nullable=True)
    payload = db.Column(db.Text, nullable=True)
    remediation = db.Column(db.Text, nullable=True)
    discovered_by = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    
    def to_dict(self):
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
            'timestamp': self.timestamp.isoformat()
        }

class Agent(db.Model):
    __tablename__ = 'agents'
    
    id = db.Column(db.String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='active')  # active, inactive, maintenance
    success_rate = db.Column(db.Float, default=0.0)  # 0-100
    last_update = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    capabilities = db.Column(db.Text)  # JSON string of capabilities
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'status': self.status,
            'successRate': self.success_rate,
            'lastUpdate': self.last_update.isoformat(),
            'capabilities': json.loads(self.capabilities) if self.capabilities else []
        }

class Report(db.Model):
    __tablename__ = 'reports'
    
    id = db.Column(db.String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = db.Column(db.String(50), db.ForeignKey('scans.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    generated = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    format = db.Column(db.String(10), nullable=False)  # PDF, HTML, JSON
    content = db.Column(db.Text, nullable=True)  # Report content
    
    def to_dict(self):
        scan = Scan.query.get(self.scan_id)
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
            'pages': max(5, vulnerability_count // 2),  # Estimate pages
            'format': self.format,
            'severity': severity
        }

# API Routes

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics"""
    total_scans = Scan.query.count()
    active_agents = Agent.query.filter_by(status='active').count()
    total_vulnerabilities = Vulnerability.query.count()
    critical_issues = Vulnerability.query.filter_by(severity='Critical').count()
    
    # Calculate average scan time (placeholder)
    avg_scan_time = "45 minutes"
    success_rate = 89
    
    return jsonify({
        'totalScans': total_scans,
        'activeAgents': active_agents,
        'vulnerabilitiesFound': total_vulnerabilities,
        'criticalIssues': critical_issues,
        'averageScanTime': avg_scan_time,
        'successRate': success_rate
    })

@app.route('/api/scans', methods=['GET'])
def get_scans():
    """Get all scans"""
    scans = Scan.query.order_by(Scan.started.desc()).all()
    return jsonify([scan.to_dict() for scan in scans])

@app.route('/api/scans', methods=['POST'])
def create_scan():
    """Create a new scan with scan type validation"""
    data = request.get_json()

    if not data or 'target' not in data:
        return jsonify({'error': 'Target is required'}), 400

    # Scan type configuration
    SCAN_TYPE_CONFIG = {
        'Quick Scan': {
            'agents': ['Web App Agent', 'Report Agent'],
            'description': 'Fast vulnerability assessment focusing on web application security'
        },
        'Full Scan': {
            'agents': ['Recon Agent', 'Web App Agent', 'Report Agent'],
            'description': 'Comprehensive security assessment using all available agents'
        },
        'Custom Scan': {
            'agents': [],  # User defined
            'description': 'Choose specific agents for targeted testing'
        }
    }

    scan_type = data.get('scanType', 'Quick Scan')
    requested_agents = data.get('agents', [])

    # Validate scan type
    if scan_type not in SCAN_TYPE_CONFIG:
        return jsonify({'error': f'Invalid scan type. Must be one of: {list(SCAN_TYPE_CONFIG.keys())}'}), 400

    # Set agents based on scan type
    if scan_type in ['Quick Scan', 'Full Scan', 'Enhanced Scan']:
        # For predefined scan types, use the configured agents
        final_agents = SCAN_TYPE_CONFIG[scan_type]['agents']
        logging.info(f"🔧 {scan_type} using predefined agents: {final_agents}")
    else:
        # For Custom Scan, use user-selected agents (don't default to any if none selected)
        final_agents = requested_agents
        if not final_agents:
            return jsonify({'error': 'Custom Scan requires at least one agent to be selected'}), 400
        logging.info(f"🔧 Custom Scan using selected agents: {final_agents}")

    scan = Scan(
        target=data['target'],
        scan_type=scan_type,
        agents=json.dumps(final_agents),
        status='pending'
    )

    db.session.add(scan)
    db.session.commit()

    logging.info(f"✅ Created {scan_type} for {data['target']} with agents: {final_agents}")

    return jsonify(scan.to_dict()), 201

@app.route('/api/scans/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Get a specific scan"""
    scan = Scan.query.get_or_404(scan_id)
    return jsonify(scan.to_dict())

@app.route('/api/scans/<scan_id>', methods=['PUT'])
def update_scan(scan_id):
    """Update a scan (typically status/progress)"""
    scan = Scan.query.get_or_404(scan_id)
    data = request.get_json()
    
    old_status = scan.status
    
    if 'status' in data:
        scan.status = data['status']
    if 'progress' in data:
        scan.progress = data['progress']
    if data.get('status') == 'completed':
        scan.completed = datetime.now(timezone.utc)
    
    db.session.commit()
    
    # Emit socket event if scan was manually stopped/cancelled
    if data.get('status') == 'failed' and old_status in ['running', 'in_progress']:
        emit_scan_progress(
            scan.id, 
            data.get('progress', 0), 
            scan.current_test or 'Scan cancelled by user', 
            'failed'
        )
        print(f"🛑 Scan {scan_id} manually stopped - emitted socket event")
    
    return jsonify(scan.to_dict())

@app.route('/api/scans/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a scan"""
    scan = Scan.query.get_or_404(scan_id)
    db.session.delete(scan)
    db.session.commit()
    return '', 204

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """Get all vulnerabilities"""
    scan_id = request.args.get('scan_id')
    
    query = Vulnerability.query
    if scan_id:
        query = query.filter_by(scan_id=scan_id)
    
    vulnerabilities = query.order_by(Vulnerability.timestamp.desc()).all()
    return jsonify([vuln.to_dict() for vuln in vulnerabilities])

@app.route('/api/vulnerabilities', methods=['POST'])
def create_vulnerability():
    """Create a new vulnerability"""
    data = request.get_json()
    
    required_fields = ['scanId', 'title', 'severity', 'description', 'discoveredBy']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'{field} is required'}), 400
    
    vulnerability = Vulnerability(
        scan_id=data['scanId'],
        title=data['title'],
        severity=data['severity'],
        cvss=data.get('cvss'),
        description=data['description'],
        url=data.get('url'),
        parameter=data.get('parameter'),
        payload=data.get('payload'),
        remediation=data.get('remediation'),
        discovered_by=data['discoveredBy']
    )
    
    db.session.add(vulnerability)
    db.session.commit()
    
    return jsonify(vulnerability.to_dict()), 201

@app.route('/api/vulnerabilities/<vuln_id>', methods=['DELETE'])
def delete_vulnerability(vuln_id):
    """Delete a vulnerability"""
    vulnerability = Vulnerability.query.get_or_404(vuln_id)
    db.session.delete(vulnerability)
    db.session.commit()
    return '', 204

@app.route('/api/agents', methods=['GET'])
def get_agents():
    """Get all agents"""
    agents = Agent.query.all()
    return jsonify([agent.to_dict() for agent in agents])

@app.route('/api/agents', methods=['POST'])
def create_agent():
    """Create a new agent"""
    data = request.get_json()
    
    if not data or 'name' not in data or 'description' not in data:
        return jsonify({'error': 'Name and description are required'}), 400
    
    agent = Agent(
        name=data['name'],
        description=data['description'],
        capabilities=json.dumps(data.get('capabilities', []))
    )
    
    db.session.add(agent)
    db.session.commit()
    
    return jsonify(agent.to_dict()), 201

@app.route('/api/agents/<agent_id>', methods=['PUT'])
def update_agent(agent_id):
    """Update an agent"""
    agent = Agent.query.get_or_404(agent_id)
    data = request.get_json()
    
    if 'status' in data:
        agent.status = data['status']
    if 'successRate' in data:
        agent.success_rate = data['successRate']
    
    agent.last_update = datetime.now(timezone.utc)
    db.session.commit()
    
    return jsonify(agent.to_dict())

@app.route('/api/reports', methods=['GET'])
def get_reports():
    """Get all reports"""
    reports = Report.query.order_by(Report.generated.desc()).all()
    return jsonify([report.to_dict() for report in reports])

@app.route('/api/reports/<report_id>', methods=['GET'])
def get_report(report_id):
    """Get a specific report with content"""
    report = Report.query.get_or_404(report_id)

    # Get the scan and vulnerabilities for this report
    scan = Scan.query.get(report.scan_id)
    vulnerabilities = scan.vulnerabilities if scan else []

    report_data = report.to_dict()
    report_data['content'] = report.content
    report_data['scan'] = scan.to_dict() if scan else None
    report_data['vulnerabilities'] = [vuln.to_dict() for vuln in vulnerabilities]

    return jsonify(report_data)

@app.route('/api/reports', methods=['POST'])
def create_report():
    """Create a new report"""
    data = request.get_json()
    
    if not data or 'scanId' not in data:
        return jsonify({'error': 'Scan ID is required'}), 400
    
    scan = Scan.query.get_or_404(data['scanId'])
    
    report = Report(
        scan_id=data['scanId'],
        title=data.get('title', f'Security Assessment - {scan.target}'),
        format=data.get('format', 'HTML'),
        content=data.get('content', '')
    )
    
    db.session.add(report)
    db.session.commit()
    
    return jsonify(report.to_dict()), 201

# Real scanning endpoints
@app.route('/api/scan/<scan_id>', methods=['POST'])
def start_real_scan(scan_id):
    """Start a real security scan using actual scanning agents"""
    scan = Scan.query.get_or_404(scan_id)

    try:
        # Validate target before scanning
        SecurityValidator.validate_target(scan.target)

        # Update scan to running
        scan.status = 'running'
        scan.progress = 10
        db.session.commit()

        # Start real scanning in background thread
        def run_scan():
            with app.app_context():  # Add Flask application context
                # Create a new database session for this thread
                from sqlalchemy.orm import sessionmaker
                Session = sessionmaker(bind=db.engine)
                session = Session()

                # Get the scan object in this session
                scan_obj = session.get(Scan, scan.id)
                if not scan_obj:
                    logging.error(f"❌ Scan {scan.id} not found in database")
                    session.close()
                    return

                try:
                    # Run the actual scan
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)

                    agents = json.loads(scan_obj.agents) if scan_obj.agents else []
                    vulnerabilities_found = []
                    scan_results = []

                    # Progress callback function
                    def update_progress(progress, current_test):
                        scan_obj.progress = progress
                        scan_obj.current_test = current_test
                        session.commit()
                        logging.info(f"📊 Progress: {progress}% - {current_test}")

                        # Emit real-time progress update via Socket.IO
                        emit_scan_progress(scan_obj.id, progress, current_test, scan_obj.status)

                    # Run Recon Agent if selected
                    if 'Recon Agent' in agents:
                        update_progress(20, "🔍 Starting Reconnaissance Scan...")
                        logging.info(f"🔍 Running Recon Agent for {scan_obj.target}")

                        try:
                            recon_agent = ReconAgent()
                            recon_results = loop.run_until_complete(recon_agent.scan_target(scan_obj.target))
                            scan_results.append(recon_results)
                            logging.info(f"✅ Recon Agent completed for {scan_obj.target}")
                            logging.info(f"📊 Recon Agent found {len(recon_results.get('vulnerabilities', []))} vulnerabilities")

                            # Store vulnerabilities found by Recon Agent
                            for vuln_data in recon_results.get('vulnerabilities', []):
                                vulnerability = Vulnerability(
                                    scan_id=scan_obj.id,
                                    title=vuln_data['title'],
                                severity=vuln_data['severity'],
                                cvss=vuln_data.get('cvss', 0.0),
                                description=vuln_data['description'],
                                url=vuln_data.get('url', scan_obj.target),
                                parameter=vuln_data.get('parameter', ''),
                                payload=vuln_data.get('payload', ''),
                                remediation=vuln_data.get('remediation', ''),
                                discovered_by=vuln_data['discovered_by']
                            )
                            session.add(vulnerability)
                            vulnerabilities_found.append(vulnerability)
                            
                            # Commit vulnerabilities immediately
                            session.commit()
                            logging.info(f"💾 Stored {len(recon_results.get('vulnerabilities', []))} vulnerabilities from Recon Agent")

                        except Exception as e:
                            logging.error(f"❌ Recon Agent failed: {e}")
                            logging.error(f"📊 Recon Agent error details: {type(e).__name__}: {str(e)}")
                            # Continue with other agents

                    # Run Web App Agent if selected
                    if 'Web App Agent' in agents:
                        update_progress(40, "🌐 Starting Web Application Security Scan...")
                        logging.info(f"🌐 Running Web App Agent for {scan_obj.target}")

                        try:
                            webapp_agent = WebAppAgent()
                            webapp_results = loop.run_until_complete(webapp_agent.scan_target(scan_obj.target, update_progress))
                            scan_results.append(webapp_results)
                            logging.info(f"✅ Web App Agent completed for {scan_obj.target}")
                            logging.info(f"📊 Web App Agent found {len(webapp_results.get('vulnerabilities', []))} vulnerabilities")

                            # Store vulnerabilities found by Web App Agent
                            for vuln_data in webapp_results.get('vulnerabilities', []):
                                vulnerability = Vulnerability(
                                    scan_id=scan_obj.id,
                                    title=vuln_data['title'],
                                    severity=vuln_data['severity'],
                                    cvss=vuln_data.get('cvss', 0.0),
                                    description=vuln_data['description'],
                                    url=vuln_data.get('url', scan_obj.target),
                                    parameter=vuln_data.get('parameter', ''),
                                    payload=vuln_data.get('payload', ''),
                                    remediation=vuln_data.get('remediation', ''),
                                    discovered_by=vuln_data['discovered_by']
                                )
                                session.add(vulnerability)
                                vulnerabilities_found.append(vulnerability)
                                
                            # Commit vulnerabilities immediately
                            session.commit()
                            logging.info(f"💾 Stored {len(webapp_results.get('vulnerabilities', []))} vulnerabilities from Web App Agent")

                        except Exception as e:
                            logging.error(f"❌ Web App Agent failed: {e}")
                            logging.error(f"📊 Web App Agent error details: {type(e).__name__}: {str(e)}")
                            # Continue with other agents


                    # Run Report Agent if selected
                    if 'Report Agent' in agents:
                        update_progress(90, "📊 Generating comprehensive security report...")
                        logging.info(f"📊 Running Report Agent for {scan_obj.target}")

                        try:
                            report_agent = ReportAgent()
                            report_results = loop.run_until_complete(report_agent.generate_report(scan_results, scan_obj.target, update_progress))

                            # Create detailed report in database
                            detailed_report = Report(
                                scan_id=scan_obj.id,
                                title=f'Detailed Security Assessment - {scan_obj.target}',
                                format='JSON',
                                content=json.dumps(report_results, indent=2)
                            )
                            session.add(detailed_report)
                            logging.info(f"✅ Report Agent completed for {scan_obj.target}")

                        except Exception as e:
                            logging.error(f"❌ Report Agent failed: {e}")
                            # Continue with scan completion

                    # Complete the scan
                    scan_obj.status = 'completed'
                    scan_obj.progress = 100
                    scan_obj.current_test = f"✅ Scan completed: found {len(vulnerabilities_found)} vulnerabilities"
                    scan_obj.completed = datetime.now(timezone.utc)
                    session.commit()

                    # Emit final progress update
                    emit_scan_progress(scan_obj.id, 100, scan_obj.current_test, 'completed')
                    
                    logging.info(f"Real scan completed for {scan_obj.target}, found {len(vulnerabilities_found)} vulnerabilities")

                    # Auto-generate basic report for completed scan
                    try:
                        report = Report(
                            scan_id=scan_obj.id,
                            title=f'Security Assessment Report - {scan_obj.target}',
                            format='HTML',
                            content=f'Comprehensive security scan completed for {scan_obj.target}. Found {len(vulnerabilities_found)} vulnerabilities across {len(scan_results)} security agents.'
                        )
                        session.add(report)
                        session.commit()
                        logging.info(f"✅ Auto-generated report for scan {scan_obj.id}")
                    except Exception as e:
                        logging.error(f"❌ Failed to generate report: {e}")

                    # Close the session
                    session.close()

                except Exception as e:
                    # Handle scan errors
                    try:
                        scan_obj.status = 'failed'
                        scan_obj.progress = 0
                        scan_obj.current_test = f"❌ Scan failed: {str(e)}"
                        session.commit()
                        
                        # Emit final progress update for failed scan
                        emit_scan_progress(scan_obj.id, 0, scan_obj.current_test, 'failed')
                        
                        logging.error(f"Scan failed for {scan_obj.target}: {e}")
                    except:
                        logging.error(f"Failed to update scan status: {e}")
                    finally:
                        session.close()

        # Start scan in background thread
        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()

        return jsonify({'message': 'Real scan started', 'scan_id': scan_id})

    except ValueError as e:
        # Target validation failed
        scan.status = 'failed'
        db.session.commit()
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        # Other errors
        scan.status = 'failed'
        db.session.commit()
        return jsonify({'error': f'Failed to start scan: {str(e)}'}), 500



def init_db():
    """Initialize database and create security agents"""
    import os

    # Get database path from URI
    db_uri = app.config['SQLALCHEMY_DATABASE_URI']
    logger.info(f"Initializing database with URI: {db_uri}")
    
    if db_uri.startswith('sqlite:///'):
        db_path = db_uri.replace('sqlite:///', '')
        
        # Convert to absolute path if not already
        if not os.path.isabs(db_path):
            db_path = os.path.abspath(db_path)
            
        db_dir = os.path.dirname(db_path)
        logger.info(f"Database path: {db_path}")
        logger.info(f"Database directory: {db_dir}")

        # Create database directory if it doesn't exist
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            logger.info(f"Created database directory: {db_dir}")
        elif db_dir:
            logger.info(f"Database directory exists: {db_dir}")

        # Check if database file exists
        db_exists = os.path.exists(db_path)
        if not db_exists:
            logger.info(f"Creating new database: {db_path}")
        else:
            logger.info(f"Using existing database: {db_path}")
    else:
        logger.info("Using non-SQLite database")

    # Create all tables
    db.create_all()
    logger.info("Database tables created/verified successfully")

    # Create security agents if they don't exist
    if Agent.query.count() == 0:
        agents_data = [
            {
                'name': 'Recon Agent',
                'description': 'Performs subdomain enumeration, asset discovery, and reconnaissance',
                'capabilities': ['Subdomain Discovery', 'Port Scanning', 'Technology Detection', 'DNS Enumeration'],
                'success_rate': 94
            },
            {
                'name': 'Web App Agent',
                'description': 'Scans for common web application vulnerabilities',
                'capabilities': ['XSS Detection', 'SQL Injection', 'CSRF Testing', 'Authentication Bypass'],
                'success_rate': 87
            },
            {
                'name': 'Report Agent',
                'description': 'Generates comprehensive vulnerability reports with AI analysis',
                'capabilities': ['Report Generation', 'Risk Assessment', 'Executive Summaries', 'Remediation Planning'],
                'success_rate': 96
            }
        ]
        
        for agent_data in agents_data:
            agent = Agent(
                name=agent_data['name'],
                description=agent_data['description'],
                capabilities=json.dumps(agent_data['capabilities']),
                success_rate=agent_data['success_rate']
            )
            db.session.add(agent)
        
        db.session.commit()
        print("✅ Security agents initialized successfully")
        print(f"📊 Created {len(agents_data)} security agents")
    else:
        print(f"📊 Found {Agent.query.count()} existing security agents")

    # Show database statistics
    scan_count = Scan.query.count()
    vuln_count = Vulnerability.query.count()
    report_count = Report.query.count()

    print(f"📈 Database Statistics:")
    print(f"   - Scans: {scan_count}")
    print(f"   - Vulnerabilities: {vuln_count}")
    print(f"   - Reports: {report_count}")
    print(f"   - Agents: {Agent.query.count()}")

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now(timezone.utc).isoformat()})

# Socket.IO Event Handlers for Real-time Communication
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logging.info(f"Client connected: {request.sid}")
    emit('connection_status', {'status': 'connected', 'message': 'Connected to AI Bug Bounty Scanner'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logging.info(f"Client disconnected: {request.sid}")

@socketio.on('ping')
def handle_ping(data):
    """Handle ping from client"""
    emit('pong', {'timestamp': datetime.now(timezone.utc).isoformat(), 'data': data})

@socketio.on('scan_progress_request')
def handle_scan_progress_request(data):
    """Handle request for scan progress updates"""
    scan_id = data.get('scan_id')
    if scan_id:
        scan = Scan.query.get(scan_id)
        if scan:
            emit('scan_progress_update', {
                'scan_id': scan_id,
                'progress': scan.progress,
                'current_test': scan.current_test,
                'status': scan.status
            })

def emit_scan_progress(scan_id, progress, current_test, status):
    """Emit scan progress to all clients in the scan room"""
    socketio.emit('scan_progress_update', {
        'scan_id': scan_id,
        'progress': progress,
        'current_test': current_test,
        'status': status
    })

if __name__ == '__main__':
    with app.app_context():
        init_db()
    
    print("Starting AI Bug Bounty Scanner Backend...")
    print("Backend URL: http://localhost:5000")
    print("Socket.IO URL: http://localhost:5000")
    print("Available endpoints:")
    print("  GET  /api/stats - Dashboard statistics")
    print("  GET  /api/scans - List all scans")
    print("  POST /api/scans - Create new scan")
    print("  GET  /api/vulnerabilities - List vulnerabilities")
    print("  GET  /api/agents - List all agents")
    print("  GET  /api/reports - List all reports")
    print("Real-time features:")
    print("  Socket.IO events: connect, disconnect, ping, scan_progress_request")

@app.route('/')
def index():
    """Serve the main HTML file"""
    return send_from_directory('.', 'index.html')

@app.route('/<path:filename>')
def static_files(filename):
    """Serve static files"""
    return send_from_directory('.', filename)

if __name__ == '__main__':
    # Get configuration from config class
    logger.info(f"🌐 Starting server on {Config.HOST}:{Config.PORT}")
    logger.info(f"🔧 Debug mode: {Config.DEBUG}")
    logger.info(f"📊 Database: {app.config['SQLALCHEMY_DATABASE_URI']}")
    logger.info(f"🔐 CORS origins: {Config.CORS_ORIGINS}")
    
    socketio.run(app, debug=Config.DEBUG, host=Config.HOST, port=Config.PORT)