#!/usr/bin/env python3
"""
Nuclei JSONL Parser - Standalone script for parsing nuclei outputs

This script processes nuclei JSONL (-j) or JSON Lines Export (-jle) outputs
and normalizes them into structured vulnerability data for the application.

Usage:
    python nuclei_parser.py input.jsonl output.json
    python nuclei_parser.py --input-file input.jsonl --output-file output.json
    echo '{"type":"result", ...}' | python nuclei_parser.py --stdin --output-file output.json

Input formats supported:
    - JSONL (JSON Lines) from nuclei -j flag
    - JSON Lines Export from nuclei -jle flag
    - Standard JSON output from nuclei -json flag

Output format:
    Normalized JSON with vulnerability details, CVSS scoring, and metadata
"""

import json
import sys
import argparse
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import re
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NucleiParser:
    """Parser for nuclei JSON outputs"""

    def __init__(self):
        self.vulnerabilities = []
        self.stats = {
            'total_findings': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

    def parse_jsonl_file(self, input_file: str) -> List[Dict[str, Any]]:
        """Parse nuclei JSONL file"""
        logger.info(f"Parsing nuclei JSONL file: {input_file}")

        findings = []

        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                        normalized = self.normalize_finding(data)
                        if normalized:
                            findings.append(normalized)

                    except json.JSONDecodeError as e:
                        logger.warning(f"Invalid JSON on line {line_num}: {e}")
                        continue

        except FileNotFoundError:
            logger.error(f"Input file not found: {input_file}")
            return []
        except Exception as e:
            logger.error(f"Error reading file {input_file}: {e}")
            return []

        logger.info(f"Parsed {len(findings)} findings from {input_file}")
        return findings

    def parse_jsonl_stdin(self) -> List[Dict[str, Any]]:
        """Parse nuclei JSONL from stdin"""
        logger.info("Parsing nuclei JSONL from stdin")

        findings = []

        try:
            for line_num, line in enumerate(sys.stdin, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)
                    normalized = self.normalize_finding(data)
                    if normalized:
                        findings.append(normalized)

                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON on line {line_num}: {e}")
                    continue

        except Exception as e:
            logger.error(f"Error reading from stdin: {e}")
            return []

        logger.info(f"Parsed {len(findings)} findings from stdin")
        return findings

    def parse_json_file(self, input_file: str) -> List[Dict[str, Any]]:
        """Parse nuclei JSON file"""
        logger.info(f"Parsing nuclei JSON file: {input_file}")

        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Handle both single result and array of results
            if isinstance(data, dict):
                results = [data] if self.is_result_data(data) else []
            elif isinstance(data, list):
                results = [item for item in data if self.is_result_data(item)]
            else:
                logger.warning("Unexpected JSON structure")
                return []

            findings = []
            for result in results:
                normalized = self.normalize_finding(result)
                if normalized:
                    findings.append(normalized)

            logger.info(f"Parsed {len(findings)} findings from {input_file}")
            return findings

        except FileNotFoundError:
            logger.error(f"Input file not found: {input_file}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in file {input_file}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error parsing file {input_file}: {e}")
            return []

    def is_result_data(self, data: Dict[str, Any]) -> bool:
        """Check if data structure represents a nuclei result"""
        required_fields = ['type', 'info']
        return all(field in data for field in required_fields) and data.get('type') == 'result'

    def normalize_finding(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normalize nuclei finding into standard format"""
        if not self.is_result_data(data):
            return None

        info = data.get('info', {})
        matched_at = data.get('matched-at', {})
        timestamp = data.get('timestamp', '')

        # Extract severity
        severity = self.normalize_severity(info.get('severity', 'unknown'))

        # Calculate CVSS score
        cvss_score = self.calculate_cvss_score(info, severity)

        # Generate unique ID
        vuln_id = f"nuclei_{data.get('template-id', 'unknown')}_{hash(str(data))}"

        # Extract URL and parameters
        url = matched_at.get('url', '')
        parameter = self.extract_parameter(url, data)

        # Build normalized finding
        finding = {
            'id': vuln_id,
            'title': info.get('name', 'Unknown Vulnerability'),
            'severity': severity,
            'cvss': cvss_score,
            'description': info.get('description', ''),
            'remediation': info.get('remediation', ''),
            'references': info.get('reference', []),
            'classification': info.get('classification', {}),
            'metadata': info.get('metadata', {}),

            # Location information
            'url': url,
            'host': matched_at.get('hostname', ''),
            'ip': matched_at.get('ip', ''),
            'port': matched_at.get('port', ''),
            'parameter': parameter,
            'method': matched_at.get('method', ''),

            # Detection details
            'template_id': data.get('template-id', ''),
            'template_path': data.get('template-path', ''),
            'type': data.get('type', ''),
            'matched_at': matched_at.get('matched-line', ''),

            # Timing and discovery
            'timestamp': timestamp,
            'discovered_by': 'nuclei',
            'tags': data.get('tags', []),

            # Raw data for debugging
            'raw': data
        }

        # Update statistics
        self.stats['total_findings'] += 1
        severity_key = severity.lower()
        if severity_key in self.stats:
            self.stats[severity_key] += 1

        return finding

    def normalize_severity(self, severity: str) -> str:
        """Normalize severity values"""
        severity_lower = severity.lower()
        if severity_lower in ['critical', 'high', 'medium', 'low', 'info']:
            return severity_lower.title()
        return 'Unknown'

    def calculate_cvss_score(self, info: Dict[str, Any], severity: str) -> float:
        """Calculate CVSS score based on severity and metadata"""
        # Default scores based on severity
        severity_scores = {
            'critical': 9.5,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 0.0
        }

        base_score = severity_scores.get(severity.lower(), 0.0)

        # Adjust based on metadata if available
        metadata = info.get('metadata', {})
        if 'cvss-score' in metadata:
            try:
                return float(metadata['cvss-score'])
            except (ValueError, TypeError):
                pass

        if 'cvss-metrics' in metadata:
            # Could implement full CVSS calculation here
            pass

        return base_score

    def extract_parameter(self, url: str, data: Dict[str, Any]) -> Optional[str]:
        """Extract vulnerable parameter from URL or request data"""
        # Try to extract from matched line
        matched_at = data.get('matched-at', {})
        matched_line = matched_at.get('matched-line', '')

        if matched_line:
            # Look for parameter patterns in matched line
            param_patterns = [
                r'(\w+)=([^&\s]+)',  # URL parameters
                r'["\'](\w+)["\']\s*[:=]\s*["\']([^"\']+)["\']',  # JSON-like
            ]

            for pattern in param_patterns:
                matches = re.findall(pattern, matched_line)
                if matches:
                    return matches[0][0]  # Return first parameter name

        # Fallback: extract from URL query parameters
        if '?' in url:
            query = url.split('?', 1)[1]
            if '&' in query:
                first_param = query.split('&')[0]
                if '=' in first_param:
                    return first_param.split('=')[0]

        return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get parsing statistics"""
        return self.stats.copy()

    def save_results(self, findings: List[Dict[str, Any]], output_file: str) -> bool:
        """Save normalized findings to output file"""
        try:
            # Create output directory if it doesn't exist
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Prepare output data
            output_data = {
                'metadata': {
                    'parser': 'nuclei_parser.py',
                    'version': '1.0.0',
                    'generated_at': datetime.utcnow().isoformat(),
                    'total_findings': len(findings),
                    'statistics': self.get_statistics()
                },
                'findings': findings
            }

            # Write to file
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)

            logger.info(f"Saved {len(findings)} findings to {output_file}")
            return True

        except Exception as e:
            logger.error(f"Error saving results to {output_file}: {e}")
            return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Parse nuclei JSON outputs')
    parser.add_argument('--input-file', '-i', help='Input nuclei JSON/JSONL file')
    parser.add_argument('--output-file', '-o', help='Output file for normalized results')
    parser.add_argument('--stdin', action='store_true', help='Read from stdin')
    parser.add_argument('--format', '-f', choices=['json', 'jsonl'],
                       default='json', help='Input format (default: json)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.input_file and not args.stdin:
        logger.error("Must specify either --input-file or --stdin")
        sys.exit(1)

    if not args.output_file:
        logger.error("Must specify --output-file")
        sys.exit(1)

    # Initialize parser
    nuclei_parser = NucleiParser()

    # Parse input
    if args.stdin:
        findings = nuclei_parser.parse_jsonl_stdin()
    elif args.format == 'jsonl':
        findings = nuclei_parser.parse_jsonl_file(args.input_file)
    else:
        findings = nuclei_parser.parse_json_file(args.input_file)

    if not findings:
        logger.warning("No findings parsed")
        # Still save empty results for consistency
        output_data = {
            'metadata': {
                'parser': 'nuclei_parser.py',
                'version': '1.0.0',
                'generated_at': datetime.utcnow().isoformat(),
                'total_findings': 0,
                'statistics': nuclei_parser.get_statistics()
            },
            'findings': []
        }

        with open(args.output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

        return

    # Save results
    if nuclei_parser.save_results(findings, args.output_file):
        logger.info(f"Successfully processed {len(findings)} findings")
        logger.info(f"Statistics: {nuclei_parser.get_statistics()}")
    else:
        logger.error("Failed to save results")
        sys.exit(1)


if __name__ == '__main__':
    main()