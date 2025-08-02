# app.py - Enhanced Flask Application Entry Point
"""
AI Bug Bounty Scanner v2.0 - Enhanced Flask Application
Integrates async task processing, authentication, external tools, and advanced features
"""

import os
import sys
import logging
from datetime import datetime, timezone
from flask import Flask, jsonify, request, g
from flask_cors import CORS
from flask_socketio import SocketIO
from werkzeug.exceptions import HTTPException

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

# Import configuration and core modules
from core.config import get_config
from database.database import DatabaseManager, init_database, create_tables
from core.celery_app import make_celery

# Import API blueprints
from api.scan_routes import scan_bp
from api.report_routes import report_bp
from api.admin_routes import admin_bp
from api.dashboard_routes import dashboard_bp

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


def create_app(config_name=None):
    """
    Application factory pattern
    Creates and configures Flask application with all extensions
    """
    app = Flask(__name__)
    
    # Load configuration
    if not config_name:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    config = get_config()
    app.config.from_object(config)
    
    # Ensure required directories exist
    os.makedirs('logs', exist_ok=True)
    os.makedirs('exports', exist_ok=True)
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('instance', exist_ok=True)
    
    # Initialize extensions
    setup_extensions(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Setup error handlers
    setup_error_handlers(app)
    
    # Setup request/response processors
    setup_request_processors(app)
    
    # Initialize database
    with app.app_context():
        try:
            init_database(app.config['SQLALCHEMY_DATABASE_URI'])
            create_tables()
            create_default_admin_user()
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Database initialization failed: {str(e)}")
    
    logger.info(f"Application created with config: {config_name}")
    return app


def setup_extensions(app):
    """Initialize Flask extensions"""
    
    # CORS
    CORS(app, 
         origins=['http://localhost:3000', 'http://localhost:8080'],
         supports_credentials=True)
    
    # SocketIO for real-time updates
    socketio = SocketIO(
        app,
        cors_allowed_origins=['http://localhost:3000', 'http://localhost:8080'],
        async_mode='threading'
    )
    app.socketio = socketio
    
    # Database
    db_manager = DatabaseManager(app)
    app.db_manager = db_manager
    
    # Celery
    celery = make_celery(app)
    app.celery = celery
    
    return app


def register_blueprints(app):
    """Register API blueprints"""
    
    # API prefix - simplified to match frontend
    api_prefix = '/api'
    
    # Scanning routes
    app.register_blueprint(scan_bp, url_prefix=f'{api_prefix}/scans')
    
    # Report routes
    app.register_blueprint(report_bp, url_prefix=f'{api_prefix}/reports')
    
    # Admin routes (for system info)
    app.register_blueprint(admin_bp, url_prefix=f'{api_prefix}/admin')
    
    # Dashboard routes
    app.register_blueprint(dashboard_bp, url_prefix=f'{api_prefix}/dashboard')
    
    # Health check endpoint
    @app.route(f'{api_prefix}/health')
    def health_check():
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'version': '2.0.0',
            'services': {
                'database': check_database_health(),
                'redis': check_redis_health(),
                'celery': check_celery_health()
            }
        })
    
    # API info endpoint
    @app.route('/api/v1/info')
    def api_info():
        return jsonify({
            'name': 'AI Bug Bounty Scanner API',
            'version': '2.0.0',
            'description': 'Enhanced vulnerability scanner with async processing',
            'features': [
                'Async task processing with Celery',
                'Multi-user authentication',
                'External security tool integration',
                'Real-time scanning updates',
                'Comprehensive reporting',
                'API key authentication',
                'Role-based access control'
            ],
            'endpoints': {
                'auth': f'/api/v1/auth',
                'users': f'/api/v1/users',
                'scans': f'/api/v1/scans',
                'reports': f'/api/v1/reports',
                'admin': f'/api/v1/admin'
            }
        })


def setup_error_handlers(app):
    """Setup global error handlers"""
    
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({
            'error': 'Bad Request',
            'message': str(error.description),
            'status_code': 400
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({
            'error': 'Unauthorized',
            'message': 'Authentication required',
            'status_code': 401
        }), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({
            'error': 'Forbidden',
            'message': 'Insufficient permissions',
            'status_code': 403
        }), 403
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            'error': 'Not Found',
            'message': 'Resource not found',
            'status_code': 404
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {str(error)}")
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred',
            'status_code': 500
        }), 500
    
    @app.errorhandler(HTTPException)
    def handle_http_exception(error):
        return jsonify({
            'error': error.name,
            'message': error.description,
            'status_code': error.code
        }), error.code
    
    @app.errorhandler(Exception)
    def handle_generic_exception(error):
        logger.error(f"Unhandled exception: {str(error)}", exc_info=True)
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred',
            'status_code': 500
        }), 500


def setup_request_processors(app):
    """Setup request and response processors"""
    
    @app.before_request
    def before_request():
        """Log requests and setup request context"""
        g.start_time = datetime.now()
        logger.debug(f"{request.method} {request.path} - {request.remote_addr}")
    
    @app.after_request
    def after_request(response):
        """Log responses and add security headers"""
        if hasattr(g, 'start_time'):
            duration = datetime.now() - g.start_time
            logger.debug(f"Request completed in {duration.total_seconds():.3f}s")
        
        # Security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        return response


def create_default_admin_user():
    """Create default admin user if none exists"""
    try:
        from database.database import get_db_session
        from database.models import User
        
        with get_db_session() as session:
            admin_exists = session.query(User).filter(User.role == 'admin').first()
            
            if not admin_exists:
                admin_user = User(
                    username=os.environ.get('ADMIN_USERNAME', 'admin'),
                    email=os.environ.get('ADMIN_EMAIL', 'admin@scanner.local'),
                    first_name='System',
                    last_name='Administrator',
                    role='admin',
                    is_verified=True
                )
                admin_user.set_password(os.environ.get('ADMIN_PASSWORD', 'admin123'))
                
                session.add(admin_user)
                session.commit()
                
                logger.info("Default admin user created")
            
    except Exception as e:
        logger.error(f"Failed to create default admin user: {str(e)}")


def check_database_health():
    """Check database connection health"""
    try:
        from database.database import check_database_health
        return 'healthy' if check_database_health() else 'unhealthy'
    except Exception:
        return 'unhealthy'


def check_redis_health():
    """Check Redis connection health"""
    try:
        import redis
        from core.config import get_config
        
        config = get_config()
        r = redis.from_url(config.REDIS_URL)
        r.ping()
        return 'healthy'
    except Exception:
        return 'unhealthy'


def check_celery_health():
    """Check Celery worker health"""
    try:
        from core.celery_app import celery_app
        
        # Check if workers are active
        inspect = celery_app.control.inspect()
        stats = inspect.stats()
        
        if stats:
            return 'healthy'
        else:
            return 'no_workers'
    except Exception:
        return 'unhealthy'


# Create Flask application
app = create_app()

# SocketIO event handlers
@app.socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")

@app.socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.sid}")

@app.socketio.on('join_scan')
def handle_join_scan(data):
    """Join scan room for real-time updates"""
    scan_id = data.get('scan_id')
    if scan_id:
        room = f"scan_{scan_id}"
        from flask_socketio import join_room
        join_room(room)
        logger.info(f"Client {request.sid} joined scan room: {room}")

if __name__ == '__main__':
    # Development server
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    app.socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=debug,
        use_reloader=debug
    )
