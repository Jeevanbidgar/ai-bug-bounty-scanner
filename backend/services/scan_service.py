"""
Scan service for orchestrating security scans
"""

import json
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from backend.models import Scan, ScanStatus, Vulnerability
from backend.services.tool_service import ToolService

logger = structlog.get_logger()

class ScanService:
    """Service for managing security scans"""

    def __init__(self):
        self.tool_service = ToolService()

    async def run_scan(self, scan_id: str, db: AsyncSession):
        """Run a security scan"""
        try:
            # Get scan details
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()

            if not scan:
                logger.error("Scan not found", scan_id=scan_id)
                return

            logger.info("Starting scan", scan_id=scan_id, target=scan.target)

            # Update scan status to running
            scan.status = ScanStatus.RUNNING.value
            scan.progress = 10
            await db.commit()

            # Get agents to run
            agents = json.loads(scan.agents) if scan.agents else []

            # Run each agent
            vulnerabilities_found = []

            for i, agent in enumerate(agents):
                try:
                    progress = 20 + (i / len(agents)) * 70  # 20-90% progress
                    scan.progress = int(progress)
                    scan.current_test = f"Running {agent}..."
                    await db.commit()

                    logger.info("Running agent", scan_id=scan_id, agent=agent)

                    # Run the agent (placeholder for actual agent execution)
                    agent_vulnerabilities = await self._run_agent(agent, scan.target)

                    # Store vulnerabilities
                    for vuln_data in agent_vulnerabilities:
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
                            discovered_by=agent
                        )
                        db.add(vulnerability)
                        vulnerabilities_found.append(vulnerability)

                    await db.commit()

                    logger.info("Agent completed", scan_id=scan_id, agent=agent, vulnerabilities=len(agent_vulnerabilities))

                except Exception as e:
                    logger.error("Agent failed", scan_id=scan_id, agent=agent, error=str(e))
                    # Continue with other agents

            # Complete the scan
            scan.status = ScanStatus.COMPLETED.value
            scan.progress = 100
            scan.completed = datetime.now()
            scan.current_test = f"Scan completed: {len(vulnerabilities_found)} vulnerabilities found"
            await db.commit()

            logger.info("Scan completed", scan_id=scan_id, vulnerabilities=len(vulnerabilities_found))

        except Exception as e:
            logger.error("Scan failed", scan_id=scan_id, error=str(e))

            # Update scan status to failed
            try:
                result = await db.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalar_one_or_none()
                if scan:
                    scan.status = ScanStatus.FAILED.value
                    scan.current_test = f"Scan failed: {str(e)}"
                    await db.commit()
            except Exception as update_error:
                logger.error("Failed to update scan status", error=str(update_error))

    async def _run_agent(self, agent: str, target: str) -> List[Dict[str, Any]]:
        """Run a specific security agent (placeholder implementation)"""
        # This is a placeholder - in the real implementation, this would
        # call the actual agent code (subfinder, nuclei, etc.)

        vulnerabilities = []

        if agent == "subfinder":
            # Simulate subdomain discovery
            vulnerabilities.append({
                'title': 'Subdomain Discovered',
                'severity': 'Low',
                'description': f'Discovered subdomain via {agent}',
                'url': f'https://subdomain.{target}',
                'discovered_by': agent
            })

        elif agent == "nuclei":
            # Simulate vulnerability discovery
            vulnerabilities.extend([
                {
                    'title': 'XSS Vulnerability',
                    'severity': 'High',
                    'cvss': 7.5,
                    'description': 'Cross-Site Scripting vulnerability detected',
                    'url': f'https://{target}/search',
                    'parameter': 'q',
                    'payload': '<script>alert("xss")</script>',
                    'remediation': 'Implement proper input sanitization and CSP headers',
                    'discovered_by': agent
                },
                {
                    'title': 'SQL Injection',
                    'severity': 'Critical',
                    'cvss': 9.8,
                    'description': 'SQL injection vulnerability detected',
                    'url': f'https://{target}/api/search',
                    'parameter': 'query',
                    'payload': "' OR '1'='1",
                    'remediation': 'Use parameterized queries and input validation',
                    'discovered_by': agent
                }
            ])

        elif agent == "nmap":
            # Simulate port scanning
            vulnerabilities.append({
                'title': 'Open Port Detected',
                'severity': 'Medium',
                'description': f'Port 80 found open via {agent}',
                'url': f'https://{target}:80',
                'discovered_by': agent
            })

        # Simulate some processing time
        await asyncio.sleep(2)

        return vulnerabilities

    async def cancel_scan(self, scan_id: str, db: AsyncSession):
        """Cancel a running scan"""
        try:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()

            if not scan:
                raise ValueError("Scan not found")

            if scan.status != ScanStatus.RUNNING.value:
                raise ValueError("Scan is not running")

            scan.status = ScanStatus.CANCELLED.value
            scan.current_test = "Scan cancelled by user"
            await db.commit()

            logger.info("Scan cancelled", scan_id=scan_id)

        except Exception as e:
            logger.error("Failed to cancel scan", scan_id=scan_id, error=str(e))
            raise

    async def get_scan_progress(self, scan_id: str, db: AsyncSession) -> Dict[str, Any]:
        """Get scan progress information"""
        try:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()

            if not scan:
                raise ValueError("Scan not found")

            return {
                'scan_id': scan_id,
                'progress': scan.progress,
                'status': scan.status,
                'current_test': scan.current_test,
                'started': scan.started.isoformat() if scan.started else None,
                'estimated_completion': self._estimate_completion(scan)
            }

        except Exception as e:
            logger.error("Failed to get scan progress", scan_id=scan_id, error=str(e))
            raise

    def _estimate_completion(self, scan) -> Optional[str]:
        """Estimate scan completion time"""
        if scan.status != ScanStatus.RUNNING.value or not scan.started:
            return None

        # Simple estimation based on progress
        elapsed = (datetime.now() - scan.started).total_seconds()
        if scan.progress > 0:
            total_estimated = elapsed * 100 / scan.progress
            remaining = total_estimated - elapsed
            completion_time = datetime.now() + timedelta(seconds=remaining)
            return completion_time.isoformat()

        return None
