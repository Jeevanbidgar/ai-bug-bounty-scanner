# AI Bug Bounty Scanner Backend

from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from datetime import datetime, timezone
import uuid
import json
from typing import Dict, List, Any
import os
import asyncio
import threading
import logging

# Import real scanning agents
from agents import SecurityValidator, ReconAgent, WebAppAgent, NetworkAgent, APIAgent, ReportAgent

# Import enhanced modules
try:
    from enhancements.threat_intelligence import ThreatIntelligenceAgent
    from enhancements.enhanced_security_agent import EnhancedSecurityAgent
    ENHANCEMENTS_AVAILABLE = True
    
    # Test threat intelligence initialization
    threat_test = ThreatIntelligenceAgent()
    threat_status = threat_test.get_agent_status()
    print(f"🛡️  Threat Intelligence: {threat_status['api_keys_configured']}/3 API keys configured")
    if threat_status['api_keys_configured'] > 0:
        print("✅ Threat intelligence features available")
    else:
        print("⚠️  Limited threat intelligence (no API keys)")
        
except ImportError as e:
    ENHANCEMENTS_AVAILABLE = False
    print(f"⚠️  Enhanced modules not available: {e}")
    print("   Install with: pip install aiohttp requests scikit-learn")

# Initialize Flask app
app = Flask(__name__)
import os
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "instance", "bug_bounty_scanner.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'

# Initialize extensions
db = SQLAlchemy(app)
CORS(app)  # Enable CORS for frontend connection
socketio = SocketIO(app, cors_allowed_origins="*")  # Enable real-time communication

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
            'agents': ['Recon Agent', 'Web App Agent', 'Network Agent', 'API Agent', 'Report Agent'],
            'description': 'Comprehensive security assessment using all available agents'
        },
        'Enhanced Scan': {
            'agents': ['Recon Agent', 'Web App Agent', 'Network Agent', 'API Agent', 'Enhanced Security Agent', 'Threat Intelligence Agent', 'Report Agent'],
            'description': 'Advanced security assessment with ML-powered vulnerability detection and threat intelligence'
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
    
    if 'status' in data:
        scan.status = data['status']
    if 'progress' in data:
        scan.progress = data['progress']
    if data.get('status') == 'completed':
        scan.completed = datetime.now(timezone.utc)
    
    db.session.commit()
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

                    # Run Network Agent if selected
                    if 'Network Agent' in agents:
                        update_progress(60, "🔌 Starting Network Security Scan...")
                        logging.info(f"🔌 Running Network Agent for {scan_obj.target}")

                        try:
                            network_agent = NetworkAgent()
                            network_results = loop.run_until_complete(network_agent.scan_target(scan_obj.target))
                            scan_results.append(network_results)
                            logging.info(f"✅ Network Agent completed for {scan_obj.target}")
                            logging.info(f"📊 Network Agent found {len(network_results.get('vulnerabilities', []))} vulnerabilities")

                            # Store vulnerabilities found by Network Agent
                            for vuln_data in network_results.get('vulnerabilities', []):
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
                            logging.info(f"💾 Stored {len(network_results.get('vulnerabilities', []))} vulnerabilities from Network Agent")

                        except Exception as e:
                            logging.error(f"❌ Network Agent failed: {e}")
                            logging.error(f"📊 Network Agent error details: {type(e).__name__}: {str(e)}")
                            # Continue with other agents

                    # Run API Agent if selected
                    if 'API Agent' in agents:
                        update_progress(75, "🔌 Starting API Security Scan...")
                        logging.info(f"🔌 Running API Agent for {scan_obj.target}")

                        try:
                            api_agent = APIAgent()
                            api_results = loop.run_until_complete(api_agent.scan_target(scan_obj.target))
                            scan_results.append(api_results)
                            logging.info(f"✅ API Agent completed for {scan_obj.target}")
                            logging.info(f"📊 API Agent found {len(api_results.get('vulnerabilities', []))} vulnerabilities")

                            # Store vulnerabilities found by API Agent
                            for vuln_data in api_results.get('vulnerabilities', []):
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
                            logging.info(f"💾 Stored {len(api_results.get('vulnerabilities', []))} vulnerabilities from API Agent")

                        except Exception as e:
                            logging.error(f"❌ API Agent failed: {e}")
                            logging.error(f"📊 API Agent error details: {type(e).__name__}: {str(e)}")
                            # Continue with other agents

                    # Run Enhanced Security Agent if available and selected
                    if ENHANCEMENTS_AVAILABLE and 'Enhanced Security Agent' in agents:
                        update_progress(85, "🔬 Running Enhanced Security Analysis...")
                        logging.info(f"🔬 Running Enhanced Security Agent for {scan_obj.target}")

                        try:
                            from enhancements.enhanced_security_agent import EnhancedSecurityAgent
                            enhanced_agent = EnhancedSecurityAgent()
                            
                            # Use async function wrapper for Enhanced Security Agent
                            async def run_enhanced_security_scan():
                                results = await enhanced_agent.comprehensive_security_scan(scan_obj.target)
                                await enhanced_agent.close()
                                return results
                            
                            enhanced_results = loop.run_until_complete(run_enhanced_security_scan())
                            scan_results.append({'agent': 'Enhanced Security Agent', 'results': enhanced_results})
                            logging.info(f"✅ Enhanced Security Agent completed for {scan_obj.target}")
                            logging.info(f"📊 Enhanced Security Agent found {len(enhanced_results)} vulnerabilities")

                            # Store vulnerabilities found by Enhanced Security Agent
                            for vuln_data in enhanced_results:
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
                                    discovered_by=vuln_data['discoveredBy']
                                )
                                session.add(vulnerability)
                                vulnerabilities_found.append(vulnerability)
                                
                            # Commit vulnerabilities immediately
                            session.commit()
                            logging.info(f"💾 Stored {len(enhanced_results)} vulnerabilities from Enhanced Security Agent")

                        except Exception as e:
                            logging.error(f"❌ Enhanced Security Agent failed: {e}")
                            logging.error(f"📊 Enhanced Security Agent error details: {type(e).__name__}: {str(e)}")
                            # Continue with other agents

                    # Run Threat Intelligence Analysis if available and selected
                    if ENHANCEMENTS_AVAILABLE and ('Threat Intelligence Agent' in agents or len(vulnerabilities_found) > 0):
                        update_progress(88, "🛡️ Analyzing threats and enriching vulnerability data...")
                        logging.info(f"🛡️ Running Threat Intelligence Analysis for {scan_obj.target}")

                        try:
                            from enhancements.threat_intelligence import ThreatIntelligenceAgent
                            threat_agent = ThreatIntelligenceAgent()
                            
                            # Analyze target reputation
                            reputation_data = loop.run_until_complete(threat_agent.analyze_target_reputation(scan_obj.target))
                            logging.info(f"📊 Threat Intelligence: Target risk score {reputation_data.get('threat_score', 0)}/100")
                            
                            # Store threat intelligence as a special vulnerability/finding
                            if reputation_data.get('threat_score', 0) > 30:  # If significant threat indicators
                                threat_finding = Vulnerability(
                                    scan_id=scan_obj.id,
                                    title=f'Threat Intelligence: {scan_obj.target}',
                                    severity='Medium' if reputation_data['threat_score'] < 70 else 'High',
                                    cvss=min(10.0, reputation_data['threat_score'] / 10),
                                    description=f"Threat analysis revealed risk score of {reputation_data['threat_score']}/100. {', '.join(reputation_data.get('recommendations', []))}",
                                    url=scan_obj.target,
                                    parameter='threat_intelligence',
                                    payload=json.dumps(reputation_data, indent=2),
                                    remediation='Review threat intelligence findings and implement recommended security measures',
                                    discovered_by='Threat Intelligence Agent'
                                )
                                session.add(threat_finding)
                                vulnerabilities_found.append(threat_finding)

                            # Enrich existing vulnerabilities with threat intelligence
                            for vuln in vulnerabilities_found[-10:]:  # Last 10 vulnerabilities
                                if hasattr(vuln, 'title'):
                                    enriched_data = loop.run_until_complete(threat_agent.enrich_vulnerability_data({
                                        'title': vuln.title,
                                        'severity': vuln.severity,
                                        'description': vuln.description
                                    }))
                                    
                                    # Update vulnerability description with threat intelligence
                                    if enriched_data.get('threat_intel'):
                                        vuln.description += f"\n\nThreat Intelligence: {enriched_data['threat_intel']['mitigation_priority']} priority"

                            logging.info(f"✅ Threat Intelligence Analysis completed for {scan_obj.target}")

                        except Exception as e:
                            logging.error(f"❌ Threat Intelligence Analysis failed: {e}")
                            logging.error(f"📊 Threat Intelligence error details: {type(e).__name__}: {str(e)}")
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
    if db_uri.startswith('sqlite:///'):
        db_path = db_uri.replace('sqlite:///', '')
        db_dir = os.path.dirname(db_path)

        # Create database directory if it doesn't exist
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            print(f"✅ Created database directory: {db_dir}")
        elif db_dir:
            print(f"📁 Database directory exists: {db_dir}")

        # Check if database file exists
        db_exists = os.path.exists(db_path)
        if not db_exists:
            print(f"�️ Creating new database: {db_path}")
        else:
            print(f"🗄️ Using existing database: {db_path}")
    else:
        print("🗄️ Using non-SQLite database")

    # Create all tables
    db.create_all()
    print("✅ Database tables created/verified successfully")

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
                'name': 'Network Agent',
                'description': 'Performs network-level vulnerability assessment',
                'capabilities': ['Port Scanning', 'Service Detection', 'Banner Grabbing', 'Network Mapping'],
                'success_rate': 91
            },
            {
                'name': 'API Agent',
                'description': 'Tests REST and GraphQL APIs for security issues',
                'capabilities': ['Endpoint Discovery', 'Authentication Testing', 'Input Validation', 'Rate Limiting'],
                'success_rate': 89
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
        
        # Initialize enhanced agents if available
        if ENHANCEMENTS_AVAILABLE:
            enhanced_agents_data = [
                {
                    'name': 'Threat Intelligence Agent',
                    'description': 'Provides real-time threat intelligence and reputation analysis',
                    'capabilities': ['CVE Integration', 'IP Reputation', 'Domain Analysis', 'Threat Feeds'],
                    'success_rate': 95
                },
                {
                    'name': 'Enhanced Security Agent',
                    'description': 'Advanced security testing with ML-powered vulnerability detection',
                    'capabilities': ['Advanced XSS', 'Time-based SQLi', 'SSL Analysis', 'WAF Detection'],
                    'success_rate': 92
                }
            ]
            
            for agent_data in enhanced_agents_data:
                # Check if agent already exists
                existing_agent = Agent.query.filter_by(name=agent_data['name']).first()
                if not existing_agent:
                    agent = Agent(
                        name=agent_data['name'],
                        description=agent_data['description'],
                        capabilities=json.dumps(agent_data['capabilities']),
                        success_rate=agent_data['success_rate']
                    )
                    db.session.add(agent)
            
            db.session.commit()
            print("🚀 Enhanced agents initialized successfully")
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
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)