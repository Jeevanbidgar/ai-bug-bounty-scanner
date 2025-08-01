# AI Bug Bounty Scanner Backend

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
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

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bug_bounty_scanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'

# Initialize extensions
db = SQLAlchemy(app)
CORS(app)  # Enable CORS for frontend connection

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
    """Create a new scan"""
    data = request.get_json()
    
    if not data or 'target' not in data:
        return jsonify({'error': 'Target is required'}), 400
    
    scan = Scan(
        target=data['target'],
        scan_type=data.get('scanType', 'Quick Scan'),
        agents=json.dumps(data.get('agents', [])),
        status='pending'
    )
    
    db.session.add(scan)
    db.session.commit()
    
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

                    # Run Recon Agent if selected
                    if 'Recon Agent' in agents:
                        scan_obj.progress = 20
                        session.commit()
                        logging.info(f"🔍 Running Recon Agent for {scan_obj.target}")

                        try:
                            recon_agent = ReconAgent()
                            recon_results = loop.run_until_complete(recon_agent.scan_target(scan_obj.target))
                            scan_results.append(recon_results)
                            logging.info(f"✅ Recon Agent completed for {scan_obj.target}")

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

                        except Exception as e:
                            logging.error(f"❌ Recon Agent failed: {e}")
                            # Continue with other agents

                    # Run Web App Agent if selected
                    if 'Web App Agent' in agents:
                        scan_obj.progress = 40
                        session.commit()
                        logging.info(f"🌐 Running Web App Agent for {scan_obj.target}")

                        try:
                            webapp_agent = WebAppAgent()
                            webapp_results = loop.run_until_complete(webapp_agent.scan_target(scan_obj.target))
                            scan_results.append(webapp_results)
                            logging.info(f"✅ Web App Agent completed for {scan_obj.target}")

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

                        except Exception as e:
                            logging.error(f"❌ Web App Agent failed: {e}")
                            # Continue with other agents

                    # Run Network Agent if selected
                    if 'Network Agent' in agents:
                        scan_obj.progress = 60
                        session.commit()
                        logging.info(f"🔌 Running Network Agent for {scan_obj.target}")

                        try:
                            network_agent = NetworkAgent()
                            network_results = loop.run_until_complete(network_agent.scan_target(scan_obj.target))
                            scan_results.append(network_results)
                            logging.info(f"✅ Network Agent completed for {scan_obj.target}")

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

                        except Exception as e:
                            logging.error(f"❌ Network Agent failed: {e}")
                            # Continue with other agents

                    # Run API Agent if selected
                    if 'API Agent' in agents:
                        scan_obj.progress = 80
                        session.commit()
                        logging.info(f"🔌 Running API Agent for {scan_obj.target}")

                        try:
                            api_agent = APIAgent()
                            api_results = loop.run_until_complete(api_agent.scan_target(scan_obj.target))
                            scan_results.append(api_results)
                            logging.info(f"✅ API Agent completed for {scan_obj.target}")

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

                        except Exception as e:
                            logging.error(f"❌ API Agent failed: {e}")
                            # Continue with other agents

                    # Update scan progress
                    scan_obj.progress = 90
                    session.commit()

                    # Complete the scan
                    scan_obj.status = 'completed'
                    scan_obj.progress = 100
                    scan_obj.completed = datetime.now(timezone.utc)
                    session.commit()

                    logging.info(f"Real scan completed for {scan_obj.target}, found {len(vulnerabilities_found)} vulnerabilities")

                    # Close the session
                    session.close()

                except Exception as e:
                    # Handle scan errors
                    try:
                        scan_obj.status = 'failed'
                        scan_obj.progress = 0
                        session.commit()
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

# Keep simulation endpoint for backward compatibility and testing
@app.route('/api/simulate/scan/<scan_id>', methods=['POST'])
def simulate_scan(scan_id):
    """Simulate running a scan (for demo/testing purposes)"""
    scan = Scan.query.get_or_404(scan_id)

    # Update scan to running
    scan.status = 'running'
    scan.progress = 10
    db.session.commit()

    # Create some sample vulnerabilities for demo
    sample_vulnerabilities = [
        {
            'title': 'Demo: Cross-Site Scripting (XSS) in Contact Form',
            'severity': 'High',
            'cvss': 7.2,
            'description': 'DEMO: Reflected XSS vulnerability found in the contact form parameter \'message\'',
            'url': f'{scan.target}/contact',
            'parameter': 'message',
            'payload': '<script>alert(\'XSS\')</script>',
            'remediation': 'Implement proper input validation and output encoding',
            'discovered_by': 'Demo Agent'
        }
    ]

    for vuln_data in sample_vulnerabilities:
        vulnerability = Vulnerability(
            scan_id=scan.id,
            title=vuln_data['title'],
            severity=vuln_data['severity'],
            cvss=vuln_data['cvss'],
            description=vuln_data['description'],
            url=vuln_data['url'],
            parameter=vuln_data['parameter'],
            payload=vuln_data['payload'],
            remediation=vuln_data['remediation'],
            discovered_by=vuln_data['discovered_by']
        )
        db.session.add(vulnerability)

    # Complete the scan
    scan.status = 'completed'
    scan.progress = 100
    scan.completed = datetime.now(timezone.utc)
    db.session.commit()

    return jsonify({'message': 'Demo scan simulation completed'})

def init_db():
    """Initialize database with sample data"""
    db.create_all()
    
    # Create sample agents if they don't exist
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
        print("Sample agents created successfully")

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now(timezone.utc).isoformat()})

if __name__ == '__main__':
    with app.app_context():
        init_db()
    
    print("Starting AI Bug Bounty Scanner Backend...")
    print("Backend URL: http://localhost:5000")
    print("Available endpoints:")
    print("  GET  /api/stats - Dashboard statistics")
    print("  GET  /api/scans - List all scans")
    print("  POST /api/scans - Create new scan")
    print("  GET  /api/vulnerabilities - List vulnerabilities")
    print("  GET  /api/agents - List all agents")
    print("  GET  /api/reports - List all reports")
    print("  POST /api/simulate/scan/<id> - Simulate scan (demo)")
    
    app.run(debug=True, host='0.0.0.0', port=5000)