"""
Nuclei output parser for structured results in AI Bug Bounty Scanner

Parses nuclei JSONL and JSON export outputs into structured findings
for database storage and reporting.
"""

import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime, timezone

from backend.models import WorkflowFinding

logger = logging.getLogger(__name__)

class NucleiParserError(Exception):
    """Raised when nuclei output parsing fails"""
    pass

class NucleiParser:
    """Parser for nuclei JSONL and JSON export outputs"""

    def __init__(self):
        self.severity_mapping = {
            'info': 'Info',
            'low': 'Low',
            'medium': 'Medium',
            'high': 'High',
            'critical': 'Critical'
        }

    def parse_jsonl_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse nuclei JSONL output file

        Args:
            file_path: Path to nuclei JSONL output file

        Returns:
            List of parsed finding dictionaries

        Raises:
            NucleiParserError: If parsing fails
        """
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        # Parse JSONL line
                        data = json.loads(line)
                        finding = self._parse_nuclei_result(data)
                        findings.append(finding)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Invalid JSON on line {line_num}: {e}")
                        continue
                    except Exception as e:
                        logger.error(f"Error parsing nuclei result on line {line_num}: {e}")
                        continue

        except FileNotFoundError:
            raise NucleiParserError(f"Nuclei output file not found: {file_path}")
        except Exception as e:
            raise NucleiParserError(f"Failed to read nuclei file {file_path}: {e}")

        logger.info(f"Parsed {len(findings)} findings from {file_path}")
        return findings

    def parse_json_export_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse nuclei JSON export file

        Args:
            file_path: Path to nuclei JSON export file

        Returns:
            List of parsed finding dictionaries

        Raises:
            NucleiParserError: If parsing fails
        """
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Handle both array and object formats
            if isinstance(data, list):
                results = data
            elif isinstance(data, dict) and 'results' in data:
                results = data['results']
            elif isinstance(data, dict) and 'templates' in data:
                # Handle newer nuclei export format
                results = []
                for template_data in data['templates']:
                    if 'results' in template_data:
                        results.extend(template_data['results'])
            else:
                raise NucleiParserError(f"Unexpected JSON export format in {file_path}")

            for result in results:
                finding = self._parse_nuclei_result(result)
                findings.append(finding)

        except FileNotFoundError:
            raise NucleiParserError(f"Nuclei export file not found: {file_path}")
        except json.JSONDecodeError as e:
            raise NucleiParserError(f"Invalid JSON in nuclei export file {file_path}: {e}")
        except Exception as e:
            raise NucleiParserError(f"Failed to parse nuclei export file {file_path}: {e}")

        logger.info(f"Parsed {len(findings)} findings from export file {file_path}")
        return findings

    def parse_nuclei_output(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse nuclei output file (auto-detect format)

        Supports both JSONL (-j) and JSON export (-je) formats

        Args:
            file_path: Path to nuclei output file

        Returns:
            List of parsed finding dictionaries
        """
        if file_path.endswith('.jsonl'):
            return self.parse_jsonl_file(file_path)
        elif file_path.endswith('.json'):
            return self.parse_json_export_file(file_path)
        else:
            # Try to detect format by reading first few lines
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    first_line = f.readline().strip()
                    if first_line.startswith('{'):
                        # JSON format
                        return self.parse_json_export_file(file_path)
                    else:
                        # Assume JSONL
                        return self.parse_jsonl_file(file_path)
            except Exception:
                raise NucleiParserError(f"Cannot determine format for {file_path}")

    def _parse_nuclei_result(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a single nuclei result into a finding dictionary"""

        # Extract basic information
        template_id = data.get('template-id', '')
        template_name = data.get('info', {}).get('name', template_id)
        severity = data.get('info', {}).get('severity', 'info')

        # Map nuclei severity to our severity levels
        mapped_severity = self.severity_mapping.get(severity.lower(), 'Info')

        # Extract findings details
        finding = {
            'finding_type': 'vulnerability',
            'title': template_name,
            'severity': mapped_severity,
            'description': data.get('info', {}).get('description', ''),
            'url': data.get('matched-at', ''),
            'cvss': self._extract_cvss_score(data),
            'cwe': self._extract_cwe(data),
            'tags': data.get('info', {}).get('tags', []),
            'evidence': {
                'template_id': template_id,
                'template_path': data.get('template-path', ''),
                'matched_at': data.get('matched-at', ''),
                'extracted_results': data.get('extracted-results', []),
                'request': data.get('request', ''),
                'response': data.get('response', ''),
            },
            'raw_data': data
        }

        return finding

    def _extract_cvss_score(self, data: Dict[str, Any]) -> Optional[float]:
        """Extract CVSS score from nuclei result"""
        # Nuclei doesn't typically provide CVSS scores directly
        # This could be enhanced to look up CVSS scores based on CWE or template
        return None

    def _extract_cwe(self, data: Dict[str, Any]) -> Optional[str]:
        """Extract CWE ID from nuclei result"""
        # Nuclei doesn't typically provide CWE IDs directly
        # This could be enhanced to map template IDs to CWE IDs
        return None

    def convert_to_db_model(self, finding: Dict[str, Any], execution_id: str, step_id: str) -> WorkflowFinding:
        """Convert parsed finding to WorkflowFinding database model"""

        return WorkflowFinding(
            execution_id=execution_id,
            step_id=step_id,
            finding_type=finding['finding_type'],
            title=finding['title'],
            severity=finding['severity'],
            description=finding['description'],
            url=finding['url'],
            cvss=finding['cvss'],
            cwe=finding['cwe'],
            tags=json.dumps(finding['tags']),
            evidence=json.dumps(finding['evidence']),
            raw_data=json.dumps(finding['raw_data'])
        )

    def parse_and_store_findings(
        self,
        file_path: str,
        execution_id: str,
        step_id: str,
        db_session
    ) -> int:
        """Parse nuclei output and store findings in database

        Args:
            file_path: Path to nuclei output file
            execution_id: Workflow execution ID
            step_id: Workflow step ID
            db_session: Database session

        Returns:
            Number of findings stored
        """
        findings_data = []

        # Determine file type and parse accordingly
        if file_path.endswith('.jsonl'):
            findings_data = self.parse_jsonl_file(file_path)
        elif file_path.endswith('.json'):
            findings_data = self.parse_json_export_file(file_path)
        else:
            raise NucleiParserError(f"Unsupported file format: {file_path}")

        # Convert to database models and store
        stored_count = 0
        for finding_data in findings_data:
            try:
                finding_model = self.convert_to_db_model(finding_data, execution_id, step_id)
                db_session.add(finding_model)
                stored_count += 1
            except Exception as e:
                logger.error(f"Failed to store finding: {e}")
                continue

        # Commit all findings
        try:
            db_session.commit()
            logger.info(f"Stored {stored_count} findings from {file_path}")
        except Exception as e:
            db_session.rollback()
            raise NucleiParserError(f"Failed to commit findings: {e}")

        return stored_count

# Global nuclei parser instance
nuclei_parser = NucleiParser()
