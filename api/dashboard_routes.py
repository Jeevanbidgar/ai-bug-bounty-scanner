# api/dashboard_routes.py - Dashboard API Routes
"""
Dashboard statistics and overview API endpoints
"""

import logging
from flask import Blueprint, jsonify, g
from auth.decorators import login_required
from database.database import get_db_session
from database.models import Scan, Vulnerability, User

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/stats', methods=['GET'])
@login_required
def get_dashboard_stats():
    """Get dashboard statistics for current user"""
    try:
        with get_db_session() as session:
            # Get user's scan statistics
            total_scans = session.query(Scan).filter(
                Scan.user_id == g.current_user.id
            ).count()
            
            active_scans = session.query(Scan).filter(
                Scan.user_id == g.current_user.id,
                Scan.status.in_(['running', 'pending'])
            ).count()
            
            completed_scans = session.query(Scan).filter(
                Scan.user_id == g.current_user.id,
                Scan.status == 'completed'
            ).count()
            
            # Get vulnerability count from user's scans
            total_vulnerabilities = session.query(Vulnerability).join(Scan).filter(
                Scan.user_id == g.current_user.id
            ).count()
            
            return jsonify({
                'totalScans': total_scans,
                'activeScans': active_scans,
                'completedScans': completed_scans,
                'totalVulnerabilities': total_vulnerabilities
            })
            
    except Exception as e:
        logger.error(f"Failed to get dashboard stats: {str(e)}")
        return jsonify({
            'totalScans': 0,
            'activeScans': 0,
            'completedScans': 0,
            'totalVulnerabilities': 0
        })


@dashboard_bp.route('/recent-activity', methods=['GET'])
@login_required
def get_recent_activity():
    """Get recent scans and vulnerabilities for dashboard"""
    try:
        with get_db_session() as session:
            # Get recent scans
            recent_scans = session.query(Scan).filter(
                Scan.user_id == g.current_user.id
            ).order_by(Scan.created_at.desc()).limit(5).all()
            
            # Get recent vulnerabilities from user's scans
            recent_vulnerabilities = session.query(Vulnerability).join(Scan).filter(
                Scan.user_id == g.current_user.id
            ).order_by(Vulnerability.created_at.desc()).limit(5).all()
            
            return jsonify({
                'recentScans': [scan.to_dict() for scan in recent_scans],
                'recentVulnerabilities': [vuln.to_dict() for vuln in recent_vulnerabilities]
            })
            
    except Exception as e:
        logger.error(f"Failed to get recent activity: {str(e)}")
        return jsonify({
            'recentScans': [],
            'recentVulnerabilities': []
        })
