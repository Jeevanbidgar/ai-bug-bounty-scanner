"""
Adapter Manager - Coordinates execution of security tool adapters
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional, Type
from pathlib import Path
from datetime import datetime
import structlog

from .base_adapter import BaseAdapter, AdapterResult
from .subfinder_adapter import SubfinderAdapter
from .amass_adapter import AmassAdapter
from .waybackurls_adapter import WaybackURLsAdapter
from .gau_adapter import GAUAdapter
from .naabu_adapter import NaabuAdapter
from .nmap_adapter import NmapAdapter
from .nuclei_adapter import NucleiAdapter

logger = structlog.get_logger()

class AdapterManager:
    """Manages and coordinates security tool adapters"""

    def __init__(self):
        self.adapters = self._initialize_adapters()
        self.results = {}

    def _initialize_adapters(self) -> Dict[str, BaseAdapter]:
        """Initialize all available adapters"""
        adapters = {}

        # MVP adapters
        adapters['subfinder'] = SubfinderAdapter()
        adapters['amass'] = AmassAdapter()
        adapters['waybackurls'] = WaybackURLsAdapter()
        adapters['gau'] = GAUAdapter()
        adapters['naabu'] = NaabuAdapter()
        adapters['nmap'] = NmapAdapter()
        adapters['nuclei'] = NucleiAdapter()

        # Future adapters can be added here
        # adapters['sqlmap'] = SQLMapAdapter()
        # adapters['gobuster'] = GobusterAdapter()

        logger.info(f"Initialized {len(adapters)} tool adapters")
        return adapters

    def get_adapter(self, tool_name: str) -> Optional[BaseAdapter]:
        """Get adapter by tool name"""
        return self.adapters.get(tool_name)

    def list_adapters(self) -> List[Dict[str, Any]]:
        """List all available adapters with metadata"""
        adapter_info = []

        for name, adapter in self.adapters.items():
            info = {
                'name': name,
                'tool_name': adapter.tool_name,
                'risk_level': adapter.get_risk_level(),
                'requires_auth': adapter.requires_authorization(),
                'containerized': getattr(adapter, 'containerized', False)
            }
            adapter_info.append(info)

        return adapter_info

    async def execute_adapter(self, tool_name: str, target: str, **kwargs) -> AdapterResult:
        """Execute a single adapter"""
        adapter = self.get_adapter(tool_name)

        if not adapter:
            raise ValueError(f"Adapter not found: {tool_name}")

        # Validate target
        if not adapter.validate_target(target):
            raise ValueError(f"Invalid target for {tool_name}: {target}")

        # Check authorization requirements
        if adapter.requires_authorization():
            logger.warning(f"Tool {tool_name} requires authorization for target: {target}")

        # Execute adapter
        result = await adapter.execute(target, **kwargs)

        # Store result
        self.results[f"{tool_name}_{target}_{datetime.now().isoformat()}"] = result

        return result

    async def execute_multiple_adapters(self, tool_names: List[str], target: str,
                                      parallel: bool = True, **kwargs) -> Dict[str, AdapterResult]:
        """Execute multiple adapters"""
        if parallel:
            # Execute in parallel
            tasks = []
            for tool_name in tool_names:
                task = asyncio.create_task(
                    self.execute_adapter(tool_name, target, **kwargs)
                )
                tasks.append((tool_name, task))

            # Wait for all tasks
            results = {}
            for tool_name, task in tasks:
                try:
                    result = await task
                    results[tool_name] = result
                except Exception as e:
                    logger.error(f"Adapter execution failed: {tool_name}", error=str(e))
                    results[tool_name] = AdapterResult(
                        success=False,
                        exit_code=-1,
                        stderr=str(e)
                    )

            return results

        else:
            # Execute sequentially
            results = {}
            for tool_name in tool_names:
                try:
                    result = await self.execute_adapter(tool_name, target, **kwargs)
                    results[tool_name] = result
                except Exception as e:
                    logger.error(f"Adapter execution failed: {tool_name}", error=str(e))
                    results[tool_name] = AdapterResult(
                        success=False,
                        exit_code=-1,
                        stderr=str(e)
                    )

            return results

    async def execute_recon_plan(self, plan_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Execute a complete reconnaissance plan"""
        phases = plan_data.get('phases', [])
        plan_results = {
            'plan_name': plan_data.get('name', 'Custom Plan'),
            'target': target,
            'started_at': datetime.now().isoformat(),
            'phases': [],
            'summary': {
                'total_tools_run': 0,
                'successful_tools': 0,
                'failed_tools': 0,
                'total_findings': 0
            }
        }

        for phase in phases:
            phase_result = {
                'name': phase['name'],
                'description': phase['description'],
                'tools_run': 0,
                'tools_successful': 0,
                'tools_failed': 0,
                'findings': 0,
                'results': {}
            }

            # Get tools for this phase
            phase_tools = [tool.get('tool') for tool in phase.get('tools', [])]

            if phase_tools:
                # Execute tools in this phase
                results = await self.execute_multiple_adapters(phase_tools, target)

                # Process results
                for tool_name, result in results.items():
                    phase_result['results'][tool_name] = {
                        'success': result.success,
                        'execution_time': result.execution_time,
                        'findings': 0
                    }

                    if result.success:
                        phase_result['tools_successful'] += 1
                        # Count findings based on result metadata
                        if 'vulnerabilities_found' in result.metadata:
                            phase_result['findings'] += result.metadata['vulnerabilities_found']
                        elif 'subdomains_found' in result.metadata:
                            phase_result['findings'] += result.metadata['subdomains_found']
                        elif 'urls_found' in result.metadata:
                            phase_result['findings'] += result.metadata['urls_found']
                        elif 'open_ports_found' in result.metadata:
                            phase_result['findings'] += result.metadata['open_ports_found']
                    else:
                        phase_result['tools_failed'] += 1

                phase_result['tools_run'] = len(results)
                plan_results['summary']['total_tools_run'] += len(results)
                plan_results['summary']['successful_tools'] += phase_result['tools_successful']
                plan_results['summary']['failed_tools'] += phase_result['tools_failed']
                plan_results['summary']['total_findings'] += phase_result['findings']

            plan_results['phases'].append(phase_result)

        plan_results['completed_at'] = datetime.now().isoformat()
        plan_results['duration'] = (
            datetime.fromisoformat(plan_results['completed_at']) -
            datetime.fromisoformat(plan_results['started_at'])
        ).total_seconds()

        return plan_results

    def get_execution_stats(self) -> Dict[str, Any]:
        """Get execution statistics"""
        if not self.results:
            return {'total_executions': 0}

        successful = sum(1 for result in self.results.values() if result.success)
        failed = len(self.results) - successful

        return {
            'total_executions': len(self.results),
            'successful_executions': successful,
            'failed_executions': failed,
            'success_rate': (successful / len(self.results)) * 100 if self.results else 0
        }

    def export_results(self, output_file: str = None) -> str:
        """Export all results to JSON file"""
        export_data = {
            'exported_at': datetime.now().isoformat(),
            'stats': self.get_execution_stats(),
            'results': {
                execution_id: {
                    'success': result.success,
                    'exit_code': result.exit_code,
                    'execution_time': result.execution_time,
                    'stdout_length': len(result.stdout),
                    'stderr_length': len(result.stderr),
                    'artifacts_count': len(result.artifacts),
                    'metadata_keys': list(result.metadata.keys()) if result.metadata else []
                }
                for execution_id, result in self.results.items()
            }
        }

        if output_file:
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            return output_file
        else:
            return json.dumps(export_data, indent=2)

    def clear_results(self):
        """Clear stored results"""
        self.results.clear()
        logger.info("Cleared adapter execution results")
