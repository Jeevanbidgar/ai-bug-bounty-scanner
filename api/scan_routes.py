# api/scan_routes.py - Scanning API Routes
"""
Vulnerability scanning API endpoints
Supports async scanning with external tools and real-time updates
"""

import logging
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, g, current_app
from flask_socketio import emit
from auth.decorators import login_required, permission_required, validate_json
from database.database import get_db_session
from database.models import Scan, Vulnerability, Agent
from tasks.scanning_tasks import run_full_scan, run_agent_scan, run_integrated_scan

logger = logging.getLogger(__name__)

scan_bp = Blueprint('scans', __name__)


@scan_bp.route('/', methods=['GET'])
@login_required
def get_scans():
    """Get user's scans with pagination and filtering"""
    try:
        # Parse query parameters
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 10)), 100)
        status = request.args.get('status')
        
        with get_db_session() as session:
            query = session.query(Scan).filter(
                Scan.user_id == g.current_user.id
            )
            
            # Apply status filter
            if status:
                query = query.filter(Scan.status == status)
            
            # Apply ordering
            query = query.order_by(Scan.created_at.desc())
            
            # Apply pagination
            offset = (page - 1) * per_page
            scans = query.offset(offset).limit(per_page).all()
            total = query.count()
            
            return jsonify({
                'scans': [scan.to_dict() for scan in scans],
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'pages': (total + per_page - 1) // per_page
                }
            })
            
    except Exception as e:
        logger.error(f"Failed to get scans: {str(e)}")
        return jsonify({'error': 'Failed to retrieve scans'}), 500


@scan_bp.route('/<int:scan_id>', methods=['GET'])
@login_required
def get_scan(scan_id):
    """Get specific scan details"""
    try:
        with get_db_session() as session:
            scan = session.query(Scan).filter(
                Scan.id == scan_id,
                Scan.user_id == g.current_user.id
            ).first()
            
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
            
            # Get related data
            vulnerabilities = session.query(Vulnerability).filter(
                Vulnerability.scan_id == scan_id
            ).all()
            
            agents = session.query(Agent).filter(
                Agent.scan_id == scan_id
            ).all()
            
            return jsonify({
                'scan': scan.to_dict(),
                'vulnerabilities': [vuln.to_dict() for vuln in vulnerabilities],
                'agents': [agent.to_dict() for agent in agents]
            })
            
    except Exception as e:
        logger.error(f"Failed to get scan {scan_id}: {str(e)}")
        return jsonify({'error': 'Failed to retrieve scan'}), 500


@scan_bp.route('/', methods=['POST'])
@permission_required('write')
@validate_json(required_fields=['target', 'scan_types'])
def create_scan():
    """Create and start a new vulnerability scan"""
    data = g.json_data
    
    try:
        # Validate scan types
        valid_scan_types = ['recon', 'webapp', 'network', 'api']
        scan_types = data['scan_types']
        
        if not all(st in valid_scan_types for st in scan_types):
            return jsonify({
                'error': 'Invalid scan types',
                'valid_types': valid_scan_types
            }), 400
        
        with get_db_session() as session:
            # Create scan record
            scan = Scan(
                user_id=g.current_user.id,
                target=data['target'],
                scan_types=scan_types,
                options=data.get('options', {}),
                status='pending'
            )
            session.add(scan)
            session.commit()
            
            # Start async scan task
            task = run_full_scan.delay(
                scan.id,
                data['target'],
                scan_types,
                data.get('options', {})
            )
            
            # Update scan with task ID
            scan.celery_task_id = task.id
            session.commit()
            
            logger.info(f"Scan created: {scan.id} for {g.current_user.username}")
            
            return jsonify({
                'message': 'Scan started successfully',
                'scan': scan.to_dict(),
                'task_id': task.id
            }), 201
            
    except Exception as e:
        logger.error(f"Failed to create scan: {str(e)}")
        return jsonify({'error': 'Failed to create scan'}), 500


@scan_bp.route('/agent', methods=['POST'])
@permission_required('write')
@validate_json(required_fields=['target', 'agent'])
def run_single_agent():
    """Run a single scanning agent"""
    data = g.json_data
    
    try:
        valid_agents = ['recon', 'webapp', 'network', 'api']
        agent_name = data['agent']
        
        if agent_name not in valid_agents:
            return jsonify({
                'error': 'Invalid agent',
                'valid_agents': valid_agents
            }), 400
        
        with get_db_session() as session:
            # Create scan record for agent
            scan = Scan(
                user_id=g.current_user.id,
                target=data['target'],
                scan_types=[agent_name],
                options=data.get('options', {}),
                status='pending'
            )
            session.add(scan)
            session.commit()
            
            # Start agent task
            task = run_agent_scan.delay(
                scan.id,
                data['target'],
                agent_name,
                data.get('options', {})
            )
            
            scan.celery_task_id = task.id
            session.commit()
            
            logger.info(f"Agent scan started: {agent_name} for {g.current_user.username}")
            
            return jsonify({
                'message': f'{agent_name} scan started',
                'scan': scan.to_dict(),
                'task_id': task.id
            }), 201
            
    except Exception as e:
        logger.error(f"Failed to start agent scan: {str(e)}")
        return jsonify({'error': 'Failed to start agent scan'}), 500


@scan_bp.route('/tools', methods=['POST'])
@permission_required('write')
@validate_json(required_fields=['target', 'tools'])
def run_external_tools():
    """Run external security tools scan"""
    data = g.json_data
    
    try:
        valid_tools = ['nuclei', 'sublist3r', 'amass', 'sqlmap', 'shodan', 'virustotal']
        tools = data['tools']
        
        invalid_tools = [tool for tool in tools if tool not in valid_tools]
        if invalid_tools:
            return jsonify({
                'error': 'Invalid tools',
                'invalid_tools': invalid_tools,
                'valid_tools': valid_tools
            }), 400
        
        with get_db_session() as session:
            # Create scan record
            scan = Scan(
                user_id=g.current_user.id,
                target=data['target'],
                scan_types=['external_tools'],
                options={
                    'tools': tools,
                    **data.get('options', {})
                },
                status='pending'
            )
            session.add(scan)
            session.commit()
            
            # Start integrated tools task
            task = run_integrated_scan.delay(
                scan.id,
                data['target'],
                tools,
                data.get('options', {})
            )
            
            scan.celery_task_id = task.id
            session.commit()
            
            logger.info(f"External tools scan started: {tools} for {g.current_user.username}")
            
            return jsonify({
                'message': 'External tools scan started',
                'scan': scan.to_dict(),
                'task_id': task.id,
                'tools': tools
            }), 201
            
    except Exception as e:
        logger.error(f"Failed to start tools scan: {str(e)}")
        return jsonify({'error': 'Failed to start tools scan'}), 500


@scan_bp.route('/<int:scan_id>/status', methods=['GET'])
@login_required
def get_scan_status(scan_id):
    """Get real-time scan status and progress"""
    try:
        with get_db_session() as session:
            scan = session.query(Scan).filter(
                Scan.id == scan_id,
                Scan.user_id == g.current_user.id
            ).first()
            
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
            
            # Get task status if available
            task_info = None
            if scan.celery_task_id:
                from celery.result import AsyncResult
                task = AsyncResult(scan.celery_task_id, app=current_app.celery)
                task_info = {
                    'state': task.state,
                    'info': task.info if task.info else {}
                }
            
            # Get progress information
            from database.models import ScanProgress
            progress = session.query(ScanProgress).filter(
                ScanProgress.scan_id == scan_id
            ).first()
            
            return jsonify({
                'scan': scan.to_dict(),
                'task': task_info,
                'progress': progress.to_dict() if progress else None
            })
            
    except Exception as e:
        logger.error(f"Failed to get scan status: {str(e)}")
        return jsonify({'error': 'Failed to get scan status'}), 500


@scan_bp.route('/<int:scan_id>/cancel', methods=['POST'])
@login_required
def cancel_scan(scan_id):
    """Cancel a running scan"""
    try:
        with get_db_session() as session:
            scan = session.query(Scan).filter(
                Scan.id == scan_id,
                Scan.user_id == g.current_user.id
            ).first()
            
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
            
            if scan.status not in ['pending', 'running']:
                return jsonify({'error': 'Scan cannot be cancelled'}), 400
            
            # Cancel Celery task if exists
            if scan.celery_task_id:
                from celery.result import AsyncResult
                task = AsyncResult(scan.celery_task_id, app=current_app.celery)
                task.revoke(terminate=True)
            
            # Update scan status
            scan.status = 'cancelled'
            scan.completed_at = datetime.now(timezone.utc)
            session.commit()
            
            logger.info(f"Scan cancelled: {scan_id} by {g.current_user.username}")
            
            return jsonify({
                'message': 'Scan cancelled successfully',
                'scan': scan.to_dict()
            })
            
    except Exception as e:
        logger.error(f"Failed to cancel scan: {str(e)}")
        return jsonify({'error': 'Failed to cancel scan'}), 500


@scan_bp.route('/<int:scan_id>', methods=['DELETE'])
@login_required
def delete_scan(scan_id):
    """Delete a scan and its data"""
    try:
        with get_db_session() as session:
            scan = session.query(Scan).filter(
                Scan.id == scan_id,
                Scan.user_id == g.current_user.id
            ).first()
            
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
            
            # Cancel if running
            if scan.status in ['pending', 'running'] and scan.celery_task_id:
                from celery.result import AsyncResult
                task = AsyncResult(scan.celery_task_id, app=current_app.celery)
                task.revoke(terminate=True)
            
            # Delete scan (cascades to related data)
            session.delete(scan)
            session.commit()
            
            logger.info(f"Scan deleted: {scan_id} by {g.current_user.username}")
            
            return jsonify({'message': 'Scan deleted successfully'})
            
    except Exception as e:
        logger.error(f"Failed to delete scan: {str(e)}")
        return jsonify({'error': 'Failed to delete scan'}), 500


@scan_bp.route('/<int:scan_id>/vulnerabilities', methods=['GET'])
@login_required
def get_scan_vulnerabilities(scan_id):
    """Get vulnerabilities for a specific scan"""
    try:
        # Parse query parameters
        severity = request.args.get('severity')
        vuln_type = request.args.get('type')
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        
        with get_db_session() as session:
            # Verify scan ownership
            scan = session.query(Scan).filter(
                Scan.id == scan_id,
                Scan.user_id == g.current_user.id
            ).first()
            
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
            
            # Build vulnerability query
            query = session.query(Vulnerability).filter(
                Vulnerability.scan_id == scan_id
            )
            
            # Apply filters
            if severity:
                query = query.filter(Vulnerability.severity == severity)
            if vuln_type:
                query = query.filter(Vulnerability.type == vuln_type)
            
            # Apply ordering and pagination
            query = query.order_by(
                Vulnerability.severity.desc(),
                Vulnerability.discovered_at.desc()
            )
            
            offset = (page - 1) * per_page
            vulnerabilities = query.offset(offset).limit(per_page).all()
            total = query.count()
            
            return jsonify({
                'vulnerabilities': [vuln.to_dict() for vuln in vulnerabilities],
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'pages': (total + per_page - 1) // per_page
                },
                'scan': scan.to_dict()
            })
            
    except Exception as e:
        logger.error(f"Failed to get vulnerabilities: {str(e)}")
        return jsonify({'error': 'Failed to retrieve vulnerabilities'}), 500


@scan_bp.route('/vulnerabilities/<int:vuln_id>', methods=['GET'])
@login_required
def get_vulnerability(vuln_id):
    """Get specific vulnerability details"""
    try:
        with get_db_session() as session:
            vulnerability = session.query(Vulnerability).join(Scan).filter(
                Vulnerability.id == vuln_id,
                Scan.user_id == g.current_user.id
            ).first()
            
            if not vulnerability:
                return jsonify({'error': 'Vulnerability not found'}), 404
            
            return jsonify({
                'vulnerability': vulnerability.to_dict()
            })
            
    except Exception as e:
        logger.error(f"Failed to get vulnerability: {str(e)}")
        return jsonify({'error': 'Failed to retrieve vulnerability'}), 500


@scan_bp.route('/vulnerabilities/<int:vuln_id>/status', methods=['PUT'])
@login_required
@validate_json(required_fields=['status'])
def update_vulnerability_status(vuln_id):
    """Update vulnerability status (open, acknowledged, fixed, false_positive)"""
    data = g.json_data
    
    try:
        valid_statuses = ['open', 'acknowledged', 'fixed', 'false_positive']
        status = data['status']
        
        if status not in valid_statuses:
            return jsonify({
                'error': 'Invalid status',
                'valid_statuses': valid_statuses
            }), 400
        
        with get_db_session() as session:
            vulnerability = session.query(Vulnerability).join(Scan).filter(
                Vulnerability.id == vuln_id,
                Scan.user_id == g.current_user.id
            ).first()
            
            if not vulnerability:
                return jsonify({'error': 'Vulnerability not found'}), 404
            
            vulnerability.status = status
            session.commit()
            
            logger.info(f"Vulnerability status updated: {vuln_id} -> {status}")
            
            return jsonify({
                'message': 'Vulnerability status updated',
                'vulnerability': vulnerability.to_dict()
            })
            
    except Exception as e:
        logger.error(f"Failed to update vulnerability status: {str(e)}")
        return jsonify({'error': 'Failed to update vulnerability status'}), 500
