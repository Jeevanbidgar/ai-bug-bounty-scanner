# AI Bug Bounty Scanner Backend - Enhanced Version
"""
Enhanced Flask backend with:
- PostgreSQL database support
- Celery for async scanning
- JWT authentication
- Advanced API endpoints
- Real-time notifications
"""

import os
import logging
import asyncio
import threading
import uuid
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional

from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, create_refresh_token
from werkzeug.security import generate_password_hash, check_password_hash
from celery import Celery
import structlog

# Import scanning agents
from agents import SecurityValidator, ReconAgent, WebAppAgent, NetworkAgent, APIAgent, ReportAgent

# Import enhanced modules
try:
    from enhancements.threat_intelligence import ThreatIntelligenceAgent
    from enhancements.enhanced_security_agent import EnhancedSecurityAgent
    ENHANCEMENTS_AVAILABLE = True
except ImportError as e:
    ENHANCEMENTS_AVAILABLE = False
    print(f"⚠️  Enhanced modules not available: {e}")

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

def create_app(config_name='production'):
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Configuration
    if config_name == 'development':
        app.config['DEBUG'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///development.db'
    else:
        app.config['DEBUG'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
            'DATABASE_URL', 
            'postgresql://scanner_user:scanner_pass_2024@localhost:5432/bug_bounty_scanner'
        )
    
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-this-in-production')
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret-change-this')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
    
    # Celery configuration
    app.config['CELERY_BROKER_URL'] = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    app.config['CELERY_RESULT_BACKEND'] = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
    
    return app

# Create app instance
app = create_app(os.getenv('FLASK_ENV', 'production'))

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
CORS(app, resources={r"/api/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Initialize Celery
def make_celery(app):
    """Create Celery instance"""
    celery = Celery(
        app.import_name,
        backend=app.config['CELERY_RESULT_BACKEND'],
        broker=app.config['CELERY_BROKER_URL']
    )
    
    celery.conf.update(
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        task_track_started=True,
        task_routes={
            'scanning.tasks.*': {'queue': 'scanning'},
            'reports.tasks.*': {'queue': 'reports'},
        }
    )
    
    class ContextTask(celery.Task):
        """Make celery tasks work with Flask app context"""
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery.Task = ContextTask
    return celery

celery = make_celery(app)

# Database Models
class User(db.Model):
    """User model for authentication"""
    __tablename__ = 'users'
    
    id = db.Column(db.String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    scans = db.relationship('Scan', backref='user', lazy=True)
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password"""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'is_active': self.is_active,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class Scan(db.Model):
    """Enhanced Scan model with user association"""
    __tablename__ = 'scans'
    
    id = db.Column(db.String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(50), db.ForeignKey('users.id'), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')
    scan_type = db.Column(db.String(50), nullable=False)
    started = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    completed = db.Column(db.DateTime, nullable=True)
    progress = db.Column(db.Integer, default=0)
    current_test = db.Column(db.String(255))
    agents = db.Column(db.Text)  # JSON string
    task_id = db.Column(db.String(255), nullable=True)  # Celery task ID
    
    # Enhanced fields
    priority = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    tags = db.Column(db.Text)  # JSON array of tags
    notes = db.Column(db.Text)
    scan_config = db.Column(db.Text)  # JSON configuration
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True, cascade='all, delete-orphan')
    reports = db.relationship('Report', backref='scan', lazy=True)
    
    def to_dict(self, include_vulnerabilities=False):
        result = {
            'id': self.id,
            'user_id': self.user_id,
            'target': self.target,
            'status': self.status,
            'scanType': self.scan_type,
            'started': self.started.isoformat(),
            'completed': self.completed.isoformat() if self.completed else None,
            'progress': self.progress,
            'current_test': self.current_test,
            'agents': json.loads(self.agents) if self.agents else [],
            'task_id': self.task_id,
            'priority': self.priority,
            'tags': json.loads(self.tags) if self.tags else [],
            'notes': self.notes,
            'scan_config': json.loads(self.scan_config) if self.scan_config else {},
            'vulnerabilities_count': len(self.vulnerabilities)
        }
        
        if include_vulnerabilities:
            result['vulnerabilities'] = [v.to_dict() for v in self.vulnerabilities]
        
        return result

class Vulnerability(db.Model):
    """Enhanced Vulnerability model"""
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = db.Column(db.String(50), db.ForeignKey('scans.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    cvss = db.Column(db.Float, nullable=True)
    description = db.Column(db.Text, nullable=False)
    url = db.Column(db.String(500), nullable=True)
    parameter = db.Column(db.String(100), nullable=True)
    payload = db.Column(db.Text, nullable=True)
    remediation = db.Column(db.Text, nullable=True)
    discovered_by = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Enhanced fields
    cve_id = db.Column(db.String(20), nullable=True)
    owasp_category = db.Column(db.String(50), nullable=True)
    confidence = db.Column(db.String(20), default='medium')  # low, medium, high
    false_positive = db.Column(db.Boolean, default=False)
    verified = db.Column(db.Boolean, default=False)
    exploitability = db.Column(db.String(20), nullable=True)
    
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
            'timestamp': self.timestamp.isoformat(),
            'cve_id': self.cve_id,
            'owasp_category': self.owasp_category,
            'confidence': self.confidence,
            'false_positive': self.false_positive,
            'verified': self.verified,
            'exploitability': self.exploitability
        }

class Report(db.Model):
    """Enhanced Report model"""
    __tablename__ = 'reports'
    
    id = db.Column(db.String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = db.Column(db.String(50), db.ForeignKey('scans.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    generated = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    format = db.Column(db.String(10), nullable=False)  # PDF, HTML, JSON, MD
    content = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(500), nullable=True)
    status = db.Column(db.String(20), default='generating')  # generating, completed, failed
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'title': self.title,
            'generated': self.generated.isoformat(),
            'format': self.format,
            'status': self.status,
            'file_path': self.file_path
        }

# Authentication routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    """User registration"""
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password') or not data.get('username'):
        return jsonify({'error': 'Email, username and password are required'}), 400
    
    # Check if user exists
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 409
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already taken'}), 409
    
    # Create new user
    user = User(
        email=data['email'],
        username=data['username']
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    logger.info("User registered", user_id=user.id, email=user.email)
    
    return jsonify({
        'message': 'User registered successfully',
        'user': user.to_dict()
    }), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login"""
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password are required'}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not user.is_active:
        return jsonify({'error': 'Account is deactivated'}), 401
    
    # Update last login
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()
    
    # Create tokens
    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)
    
    logger.info("User logged in", user_id=user.id, email=user.email)
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': user.to_dict()
    })

@app.route('/api/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token"""
    current_user_id = get_jwt_identity()
    new_token = create_access_token(identity=current_user_id)
    return jsonify({'access_token': new_token})

@app.route('/api/auth/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """Get user profile"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify(user.to_dict())

# Enhanced API routes
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        
        # Check Redis connection
        from redis import Redis
        redis_client = Redis.from_url(app.config['CELERY_BROKER_URL'])
        redis_client.ping()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'version': '2.0.0',
            'components': {
                'database': 'healthy',
                'redis': 'healthy',
                'enhancements': ENHANCEMENTS_AVAILABLE
            }
        })
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 503

@app.route('/api/stats', methods=['GET'])
@jwt_required()
def get_stats():
    """Get dashboard statistics for authenticated user"""
    current_user_id = get_jwt_identity()
    
    # User-specific stats
    user_scans = Scan.query.filter_by(user_id=current_user_id).count()
    user_vulnerabilities = db.session.query(Vulnerability).join(Scan).filter(
        Scan.user_id == current_user_id
    ).count()
    
    # Global stats (for admins or overview)
    total_scans = Scan.query.count()
    total_vulnerabilities = Vulnerability.query.count()
    
    # Recent activity
    recent_scans = Scan.query.filter_by(user_id=current_user_id).order_by(
        Scan.started.desc()
    ).limit(5).all()
    
    return jsonify({
        'user_stats': {
            'scans': user_scans,
            'vulnerabilities': user_vulnerabilities,
            'recent_scans': [scan.to_dict() for scan in recent_scans]
        },
        'global_stats': {
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulnerabilities
        }
    })

# Celery tasks
@celery.task(bind=True)
def run_security_scan(self, scan_id, user_id):
    """
    Celery task to run security scan in background
    """
    logger.info("Starting security scan task", scan_id=scan_id, task_id=self.request.id)
    
    try:
        scan = Scan.query.get(scan_id)
        if not scan:
            raise Exception(f"Scan {scan_id} not found")
        
        # Update scan status
        scan.status = 'running'
        scan.task_id = self.request.id
        db.session.commit()
        
        # Emit real-time update
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'progress': 10,
            'status': 'running',
            'message': 'Initializing security scan...'
        }, room=f'user_{user_id}')
        
        # Import and run scanning agents
        agents_list = json.loads(scan.agents) if scan.agents else []
        vulnerabilities_found = []
        
        # Progress tracking
        total_agents = len(agents_list)
        current_agent = 0
        
        def update_progress(agent_progress, message):
            """Update scan progress"""
            base_progress = (current_agent / total_agents) * 80 if total_agents > 0 else 0
            agent_contribution = (agent_progress / 100) * (80 / total_agents) if total_agents > 0 else 0
            total_progress = min(base_progress + agent_contribution + 10, 90)
            
            scan.progress = int(total_progress)
            scan.current_test = message
            db.session.commit()
            
            socketio.emit('scan_progress', {
                'scan_id': scan_id,
                'progress': scan.progress,
                'status': 'running',
                'message': message
            }, room=f'user_{user_id}')
        
        # Run agents asynchronously
        async def run_all_agents():
            nonlocal current_agent, vulnerabilities_found
            
            for agent_name in agents_list:
                current_agent += 1
                logger.info("Running agent", agent=agent_name, scan_id=scan_id)
                
                try:
                    if agent_name == 'Recon Agent':
                        agent = ReconAgent()
                        results = await agent.scan_target(scan.target)
                        
                    elif agent_name == 'Web App Agent':
                        agent = WebAppAgent()
                        results = await agent.scan_target(scan.target, 
                            lambda p, m: update_progress(p, m))
                        
                    elif agent_name == 'Network Agent':
                        agent = NetworkAgent()
                        results = await agent.scan_target(scan.target)
                        
                    elif agent_name == 'API Agent':
                        agent = APIAgent()
                        results = await agent.scan_target(scan.target)
                        
                    elif agent_name == 'Enhanced Security Agent' and ENHANCEMENTS_AVAILABLE:
                        from enhancements.enhanced_security_agent import EnhancedSecurityAgent
                        agent = EnhancedSecurityAgent()
                        results = await agent.comprehensive_security_scan(scan.target)
                        await agent.close()
                        
                    else:
                        continue
                    
                    # Store vulnerabilities
                    for vuln_data in results.get('vulnerabilities', []):
                        vulnerability = Vulnerability(
                            scan_id=scan.id,
                            title=vuln_data['title'],
                            severity=vuln_data['severity'],
                            cvss=vuln_data.get('cvss', 0.0),
                            description=vuln_data['description'],
                            url=vuln_data.get('url', scan.target),
                            parameter=vuln_data.get('parameter', ''),
                            payload=vuln_data.get('payload', ''),
                            remediation=vuln_data.get('remediation', ''),
                            discovered_by=vuln_data['discovered_by']
                        )
                        db.session.add(vulnerability)
                        vulnerabilities_found.append(vulnerability)
                    
                    db.session.commit()
                    logger.info("Agent completed", agent=agent_name, 
                              vulnerabilities=len(results.get('vulnerabilities', [])))
                    
                except Exception as e:
                    logger.error("Agent failed", agent=agent_name, error=str(e))
                    continue
        
        # Run the async function
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_all_agents())
        
        # Complete scan
        scan.status = 'completed'
        scan.progress = 100
        scan.completed = datetime.now(timezone.utc)
        scan.current_test = f"Scan completed: {len(vulnerabilities_found)} vulnerabilities found"
        db.session.commit()
        
        # Emit completion
        socketio.emit('scan_progress', {
            'scan_id': scan_id,
            'progress': 100,
            'status': 'completed',
            'message': f'Scan completed successfully! Found {len(vulnerabilities_found)} vulnerabilities.'
        }, room=f'user_{user_id}')
        
        logger.info("Security scan completed", scan_id=scan_id, 
                   vulnerabilities=len(vulnerabilities_found))
        
        return {
            'status': 'completed',
            'vulnerabilities_found': len(vulnerabilities_found)
        }
        
    except Exception as e:
        logger.error("Security scan failed", scan_id=scan_id, error=str(e))
        
        # Update scan status
        scan = Scan.query.get(scan_id)
        if scan:
            scan.status = 'failed'
            scan.current_test = f"Scan failed: {str(e)}"
            db.session.commit()
            
            socketio.emit('scan_progress', {
                'scan_id': scan_id,
                'progress': 0,
                'status': 'failed',
                'message': f'Scan failed: {str(e)}'
            }, room=f'user_{user_id}')
        
        raise

# Enhanced scan endpoints
@app.route('/api/scans', methods=['POST'])
@jwt_required()
def create_scan():
    """Create a new scan"""
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data or 'target' not in data:
        return jsonify({'error': 'Target is required'}), 400
    
    try:
        # Validate target
        SecurityValidator.validate_target(data['target'])
        
        # Create scan
        scan = Scan(
            user_id=current_user_id,
            target=data['target'],
            scan_type=data.get('scanType', 'Quick Scan'),
            agents=json.dumps(data.get('agents', ['Web App Agent'])),
            priority=data.get('priority', 'medium'),
            tags=json.dumps(data.get('tags', [])),
            notes=data.get('notes', ''),
            scan_config=json.dumps(data.get('config', {}))
        )
        
        db.session.add(scan)
        db.session.commit()
        
        logger.info("Scan created", scan_id=scan.id, target=scan.target, 
                   user_id=current_user_id)
        
        return jsonify(scan.to_dict()), 201
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error("Failed to create scan", error=str(e))
        return jsonify({'error': 'Failed to create scan'}), 500

@app.route('/api/scans/<scan_id>/start', methods=['POST'])
@jwt_required()
def start_scan(scan_id):
    """Start a scan using Celery"""
    current_user_id = get_jwt_identity()
    
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user_id).first()
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    if scan.status != 'pending':
        return jsonify({'error': 'Scan already started or completed'}), 400
    
    # Start async scan task
    task = run_security_scan.delay(scan_id, current_user_id)
    
    # Update scan with task ID
    scan.task_id = task.id
    scan.status = 'queued'
    db.session.commit()
    
    logger.info("Scan started", scan_id=scan_id, task_id=task.id)
    
    return jsonify({
        'message': 'Scan started successfully',
        'task_id': task.id
    })

@app.route('/api/scans', methods=['GET'])
@jwt_required()
def get_scans():
    """Get user's scans"""
    current_user_id = get_jwt_identity()
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    status = request.args.get('status')
    
    query = Scan.query.filter_by(user_id=current_user_id)
    
    if status:
        query = query.filter_by(status=status)
    
    scans = query.order_by(Scan.started.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'scans': [scan.to_dict() for scan in scans.items],
        'total': scans.total,
        'pages': scans.pages,
        'current_page': page
    })

# Socket.IO events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info("Client connected", sid=request.sid)

@socketio.on('join_user_room')
def handle_join_user_room(data):
    """Join user-specific room for real-time updates"""
    user_id = data.get('user_id')
    if user_id:
        join_room(f'user_{user_id}')
        logger.info("User joined room", user_id=user_id, sid=request.sid)

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info("Client disconnected", sid=request.sid)

# Initialize database
def init_db():
    """Initialize database with default data"""
    db.create_all()
    
    # Create default admin user if none exists
    if User.query.count() == 0:
        admin = User(
            email='admin@scanner.local',
            username='admin',
            is_admin=True
        )
        admin.set_password('admin123')  # Change in production
        db.session.add(admin)
        db.session.commit()
        
        logger.info("Default admin user created", email=admin.email)

if __name__ == '__main__':
    with app.app_context():
        init_db()
    
    logger.info("Starting AI Bug Bounty Scanner Backend v2.0")
    socketio.run(app, debug=app.config['DEBUG'], host='0.0.0.0', port=5000)
