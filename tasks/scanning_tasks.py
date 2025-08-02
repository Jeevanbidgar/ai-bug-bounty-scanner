# tasks/scanning_tasks.py - Asynchronous Scanning Tasks
"""
Celery tasks for vulnerability scanning operations
Provides asynchronous, distributed scanning capabilities
"""

import os
import sys
import json
import traceback
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from celery import current_task
from celery.utils.log import get_task_logger

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from core.celery_app import celery_app
from database.models import Scan, Vulnerability, Agent, ScanProgress
from database.database import get_db_session
from agents.recon_agent import ReconAgent
from agents.webapp_agent import WebAppAgent
from agents.network_agent import NetworkAgent
from agents.api_agent import APIAgent
from utils.scanning_agents import IntegratedSecurityScanner

# Setup logging
logger = get_task_logger(__name__)


@celery_app.task(bind=True, name='tasks.scanning_tasks.run_full_scan')
def run_full_scan(self, scan_id: int, target: str, scan_types: List[str], options: Dict[str, Any] = None):
    """
    Run a complete vulnerability scan asynchronously
    
    Args:
        scan_id: Database ID of the scan
        target: Target URL or IP to scan
        scan_types: List of scan types to execute
        options: Additional scanning options
    """
    options = options or {}
    
    try:
        # Update task state
        self.update_state(
            state='PROGRESS',
            meta={'current': 0, 'total': len(scan_types), 'status': 'Starting scan...'}
        )
        
        logger.info(f"Starting full scan {scan_id} for target: {target}")
        
        # Get database session
        with get_db_session() as session:
            scan = session.query(Scan).get(scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")
            
            # Update scan status
            scan.status = 'running'
            scan.started_at = datetime.now(timezone.utc)
            session.commit()
            
            # Initialize progress tracking
            progress = ScanProgress(
                scan_id=scan_id,
                total_steps=len(scan_types),
                current_step=0,
                status='initializing'
            )
            session.add(progress)
            session.commit()
            
            vulnerabilities = []
            step = 0
            
            for scan_type in scan_types:
                step += 1
                logger.info(f"Running {scan_type} scan (step {step}/{len(scan_types)})")
                
                # Update progress
                progress.current_step = step
                progress.status = f'Running {scan_type} scan'
                session.commit()
                
                self.update_state(
                    state='PROGRESS',
                    meta={
                        'current': step,
                        'total': len(scan_types),
                        'status': f'Running {scan_type} scan',
                        'scan_type': scan_type
                    }
                )
                
                try:
                    # Run specific scan type
                    scan_results = run_scan_type(target, scan_type, options, session)
                    vulnerabilities.extend(scan_results.get('vulnerabilities', []))
                    
                    # Store agent results
                    agent = Agent(
                        scan_id=scan_id,
                        name=scan_type,
                        status='completed',
                        results=json.dumps(scan_results),
                        completed_at=datetime.now(timezone.utc)
                    )
                    session.add(agent)
                    session.commit()
                    
                except Exception as e:
                    logger.error(f"Error in {scan_type} scan: {str(e)}")
                    # Continue with other scan types
                    agent = Agent(
                        scan_id=scan_id,
                        name=scan_type,
                        status='failed',
                        error_message=str(e),
                        completed_at=datetime.now(timezone.utc)
                    )
                    session.add(agent)
                    session.commit()
            
            # Store vulnerabilities
            total_vulns = 0
            for vuln_data in vulnerabilities:
                vulnerability = Vulnerability(
                    scan_id=scan_id,
                    title=vuln_data.get('title', 'Unknown Vulnerability'),
                    description=vuln_data.get('description', ''),
                    severity=vuln_data.get('severity', 'info'),
                    type=vuln_data.get('type', 'unknown'),
                    url=vuln_data.get('url', target),
                    payload=vuln_data.get('payload', ''),
                    evidence=json.dumps(vuln_data.get('evidence', {})),
                    recommendation=vuln_data.get('recommendation', ''),
                    cve_id=vuln_data.get('cve_id'),
                    cvss_score=vuln_data.get('cvss_score')
                )
                session.add(vulnerability)
                total_vulns += 1
            
            # Complete scan
            scan.status = 'completed'
            scan.completed_at = datetime.now(timezone.utc)
            scan.vulnerabilities_found = total_vulns
            
            progress.status = 'completed'
            progress.current_step = len(scan_types)
            
            session.commit()
            
            logger.info(f"Scan {scan_id} completed. Found {total_vulns} vulnerabilities")
            
            return {
                'scan_id': scan_id,
                'status': 'completed',
                'vulnerabilities_found': total_vulns,
                'scan_types_completed': scan_types,
                'completed_at': datetime.now(timezone.utc).isoformat()
            }
            
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {str(e)}")
        logger.error(traceback.format_exc())
        
        # Update scan status to failed
        try:
            with get_db_session() as session:
                scan = session.query(Scan).get(scan_id)
                if scan:
                    scan.status = 'failed'
                    scan.error_message = str(e)
                    scan.completed_at = datetime.now(timezone.utc)
                    session.commit()
        except Exception as db_e:
            logger.error(f"Failed to update scan status: {str(db_e)}")
        
        # Update task state
        self.update_state(
            state='FAILURE',
            meta={'error': str(e), 'traceback': traceback.format_exc()}
        )
        
        raise


@celery_app.task(bind=True, name='tasks.scanning_tasks.run_agent_scan')
def run_agent_scan(self, scan_id: int, target: str, agent_name: str, options: Dict[str, Any] = None):
    """
    Run a specific agent scan asynchronously
    
    Args:
        scan_id: Database ID of the scan
        target: Target URL or IP to scan
        agent_name: Name of the agent to run
        options: Additional scanning options
    """
    options = options or {}
    
    try:
        logger.info(f"Starting {agent_name} scan for target: {target}")
        
        self.update_state(
            state='PROGRESS',
            meta={'status': f'Running {agent_name} scan', 'agent': agent_name}
        )
        
        with get_db_session() as session:
            # Run the specific scan
            results = run_scan_type(target, agent_name, options, session)
            
            # Store agent results
            agent = Agent(
                scan_id=scan_id,
                name=agent_name,
                status='completed',
                results=json.dumps(results),
                completed_at=datetime.now(timezone.utc)
            )
            session.add(agent)
            
            # Store vulnerabilities
            vulns_added = 0
            for vuln_data in results.get('vulnerabilities', []):
                vulnerability = Vulnerability(
                    scan_id=scan_id,
                    title=vuln_data.get('title', 'Unknown Vulnerability'),
                    description=vuln_data.get('description', ''),
                    severity=vuln_data.get('severity', 'info'),
                    type=vuln_data.get('type', 'unknown'),
                    url=vuln_data.get('url', target),
                    payload=vuln_data.get('payload', ''),
                    evidence=json.dumps(vuln_data.get('evidence', {})),
                    recommendation=vuln_data.get('recommendation', ''),
                    cve_id=vuln_data.get('cve_id'),
                    cvss_score=vuln_data.get('cvss_score')
                )
                session.add(vulnerability)
                vulns_added += 1
            
            session.commit()
            
            return {
                'agent': agent_name,
                'status': 'completed',
                'vulnerabilities_found': vulns_added,
                'results': results
            }
            
    except Exception as e:
        logger.error(f"Agent scan {agent_name} failed: {str(e)}")
        
        self.update_state(
            state='FAILURE',
            meta={'error': str(e), 'agent': agent_name}
        )
        
        raise


@celery_app.task(bind=True, name='tasks.scanning_tasks.run_integrated_scan')
def run_integrated_scan(self, scan_id: int, target: str, tools: List[str], options: Dict[str, Any] = None):
    """
    Run integrated external tool scan
    
    Args:
        scan_id: Database ID of the scan
        target: Target URL or IP to scan
        tools: List of external tools to run
        options: Additional scanning options
    """
    options = options or {}
    
    try:
        logger.info(f"Starting integrated tool scan for target: {target} with tools: {tools}")
        
        self.update_state(
            state='PROGRESS',
            meta={'status': 'Running integrated tool scan', 'tools': tools}
        )
        
        with get_db_session() as session:
            # Initialize integrated scanner
            scanner = IntegratedSecurityScanner()
            
            # Run tool scan
            results = scanner.run_comprehensive_scan(target, tools, options)
            
            # Store results
            agent = Agent(
                scan_id=scan_id,
                name='integrated_tools',
                status='completed',
                results=json.dumps(results),
                completed_at=datetime.now(timezone.utc)
            )
            session.add(agent)
            
            # Process and store vulnerabilities
            vulns_added = 0
            for tool_results in results.get('tool_results', {}).values():
                for vuln_data in tool_results.get('vulnerabilities', []):
                    vulnerability = Vulnerability(
                        scan_id=scan_id,
                        title=vuln_data.get('title', 'Tool-detected Vulnerability'),
                        description=vuln_data.get('description', ''),
                        severity=vuln_data.get('severity', 'info'),
                        type=vuln_data.get('type', 'external_tool'),
                        url=vuln_data.get('url', target),
                        payload=vuln_data.get('payload', ''),
                        evidence=json.dumps(vuln_data.get('evidence', {})),
                        recommendation=vuln_data.get('recommendation', ''),
                        cve_id=vuln_data.get('cve_id'),
                        cvss_score=vuln_data.get('cvss_score')
                    )
                    session.add(vulnerability)
                    vulns_added += 1
            
            session.commit()
            
            return {
                'tools': tools,
                'status': 'completed',
                'vulnerabilities_found': vulns_added,
                'results': results
            }
            
    except Exception as e:
        logger.error(f"Integrated tool scan failed: {str(e)}")
        
        self.update_state(
            state='FAILURE',
            meta={'error': str(e), 'tools': tools}
        )
        
        raise


def run_scan_type(target: str, scan_type: str, options: Dict[str, Any], session) -> Dict[str, Any]:
    """
    Run a specific type of scan
    
    Args:
        target: Target to scan
        scan_type: Type of scan to run
        options: Scanning options
        session: Database session
        
    Returns:
        Dictionary containing scan results
    """
    results = {'vulnerabilities': [], 'metadata': {}}
    
    try:
        if scan_type == 'recon':
            agent = ReconAgent()
            results = agent.scan(target, options)
            
        elif scan_type == 'webapp':
            agent = WebAppAgent()
            results = agent.scan(target, options)
            
        elif scan_type == 'network':
            agent = NetworkAgent()
            results = agent.scan(target, options)
            
        elif scan_type == 'api':
            agent = APIAgent()
            results = agent.scan(target, options)
            
        else:
            logger.warning(f"Unknown scan type: {scan_type}")
            results['error'] = f"Unknown scan type: {scan_type}"
            
    except Exception as e:
        logger.error(f"Error running {scan_type} scan: {str(e)}")
        results['error'] = str(e)
        results['traceback'] = traceback.format_exc()
    
    return results


@celery_app.task(name='tasks.scanning_tasks.cleanup_old_scans')
def cleanup_old_scans(days_old: int = 30):
    """
    Clean up old scan data
    
    Args:
        days_old: Number of days after which to delete scans
    """
    try:
        from datetime import timedelta
        
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_old)
        
        with get_db_session() as session:
            # Delete old scans and related data
            old_scans = session.query(Scan).filter(
                Scan.created_at < cutoff_date,
                Scan.status.in_(['completed', 'failed'])
            ).all()
            
            deleted_count = 0
            for scan in old_scans:
                session.delete(scan)
                deleted_count += 1
            
            session.commit()
            
            logger.info(f"Cleaned up {deleted_count} old scans")
            return {'deleted_scans': deleted_count}
            
    except Exception as e:
        logger.error(f"Cleanup failed: {str(e)}")
        raise
