"""
Tool service for managing security tools
"""

import asyncio
import json
import subprocess
from typing import Dict, List, Any, Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from backend.models import Tool
from backend.services.tool_registry import ToolRegistry
from backend.adapters.adapter_manager import AdapterManager
from backend.middleware.error_handler import ToolExecutionError

logger = structlog.get_logger()

class ToolService:
    """Service for managing security tools"""

    def __init__(self):
        self.tool_registry = ToolRegistry()
        self.adapter_manager = AdapterManager()
        self.tools_config = self._get_tools_config()

    def _get_tools_config(self) -> Dict[str, Dict[str, Any]]:
        """Get configuration for available security tools"""
        return {
            'subfinder': {
                'name': 'subfinder',
                'description': 'Fast subdomain enumeration tool',
                'category': 'recon',
                'command_template': 'subfinder -d {target} -o {output_file}',
                'timeout': 600
            },
            'amass': {
                'name': 'amass',
                'description': 'Comprehensive network reconnaissance tool',
                'category': 'recon',
                'command_template': 'amass enum -passive -d {target} -o {output_file}',
                'timeout': 1200
            },
            'nmap': {
                'name': 'nmap',
                'description': 'Network discovery and security auditing tool',
                'category': 'network',
                'command_template': 'nmap -sV -sC -O -p- {target} -oN {output_file} -oX {xml_output_file}',
                'timeout': 1800,
                'requires_root': True
            },
            'nuclei': {
                'name': 'nuclei',
                'description': 'Fast and customizable vulnerability scanner',
                'category': 'web',
                'command_template': 'nuclei -u {target} -o {output_file}',
                'timeout': 900
            },
            'sqlmap': {
                'name': 'sqlmap',
                'description': 'Automatic SQL injection tool',
                'category': 'web',
                'command_template': 'sqlmap -u "{target}" --batch --output-dir={output_dir}',
                'timeout': 1800
            }
        }

    async def initialize_tools_db(self, db: AsyncSession):
        """Initialize tools in the database"""
        try:
            # Check if tools already exist
            result = await db.execute(select(Tool).limit(1))
            existing_tools = result.scalars().all()

            if existing_tools:
                logger.info("Tools already initialized")
                return

            # Create tool records
            tools_to_create = []
            for tool_name, config in self.tools_config.items():
                tool = Tool(
                    name=config['name'],
                    description=config['description'],
                    category=config['category'],
                    command_template=config['command_template'],
                    available=False,  # Will be checked separately
                    installed=False
                )
                tools_to_create.append(tool)

            for tool in tools_to_create:
                db.add(tool)

            await db.commit()
            logger.info(f"Initialized {len(tools_to_create)} tools in database")

        except Exception as e:
            logger.error("Failed to initialize tools", error=str(e))
            raise

    async def check_tool_availability(self, tool_name: str) -> bool:
        """Check if a specific tool is available"""
        if tool_name not in self.tools_config:
            return False

        try:
            # Use asyncio subprocess for async checking
            process = await asyncio.create_subprocess_exec(
                'which', tool_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )

            await process.wait()
            return process.returncode == 0

        except Exception as e:
            logger.debug(f"Error checking tool availability: {tool_name}", error=str(e))
            return False

    async def check_all_tools_availability(self) -> Dict[str, bool]:
        """Check availability of all tools"""
        availability = {}

        for tool_name in self.tools_config.keys():
            availability[tool_name] = await self.check_tool_availability(tool_name)

        return availability

    async def update_tools_availability(self, db: AsyncSession):
        """Update availability status of all tools in database"""
        try:
            availability = await self.check_all_tools_availability()

            for tool_name, available in availability.items():
                result = await db.execute(
                    select(Tool).where(Tool.name == tool_name)
                )
                tool = result.scalar_one_or_none()

                if tool:
                    tool.available = available
                    tool.last_check = datetime.now()

            await db.commit()
            logger.info("Updated tools availability status")

        except Exception as e:
            logger.error("Failed to update tools availability", error=str(e))
            raise ToolExecutionError(
                tool_name="all",
                message=f"Failed to update tools availability: {str(e)}",
                details={"error": str(e)}
            )

    def format_command(self, tool_name: str, target: str, **kwargs) -> str:
        """Format command template with provided parameters"""
        if tool_name not in self.tools_config:
            raise ToolExecutionError(
                tool_name=tool_name,
                message=f"Unknown tool: {tool_name}",
                details={"available_tools": list(self.tools_config.keys())}
            )

        config = self.tools_config[tool_name]

        # Prepare template variables
        template_vars = {
            'target': target,
            'output_file': kwargs.get('output_file', f'{tool_name}_{target.replace("://", "_").replace("/", "_")}.txt'),
            'xml_output_file': kwargs.get('xml_output_file', f'{tool_name}_{target.replace("://", "_").replace("/", "_")}.xml'),
            'output_dir': kwargs.get('output_dir', f'{tool_name}_{target.replace("://", "_").replace("/", "_")}'),
            **kwargs
        }

        # Format command template
        try:
            command = config['command_template'].format(**template_vars)
            return command
        except KeyError as e:
            raise ValueError(f"Missing template variable: {e}")

    async def run_tool(self, tool_name: str, target: str, **kwargs) -> Dict[str, Any]:
        """Run a security tool using the adapter system"""
        if tool_name not in self.tools_config:
            raise ValueError(f"Unknown tool: {tool_name}")

        # Check if tool is available
        if not await self.check_tool_availability(tool_name):
            raise RuntimeError(f"Tool '{tool_name}' is not available")

        # Use adapter system for execution
        try:
            result = await self.adapter_manager.execute_adapter(tool_name, target, **kwargs)

            # Convert AdapterResult to dict format for compatibility
            result_dict = {
                'tool_name': result.tool_name,
                'success': result.success,
                'exit_code': result.exit_code,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'duration': result.execution_time,
                'artifacts': result.artifacts,
                'metadata': result.metadata
            }

            return result_dict

        except Exception as e:
            logger.error("Failed to run tool via adapter", tool=tool_name, error=str(e))
            raise RuntimeError(f"Failed to execute tool '{tool_name}': {str(e)}")

    async def run_tools_parallel(self, tool_configs: List[Dict], target: str) -> List[Dict[str, Any]]:
        """Run multiple tools in parallel using adapter manager"""
        # Convert tool_configs to the format expected by adapter manager
        tool_names = [config['tool'] for config in tool_configs]

        try:
            results = await self.adapter_manager.execute_multiple_adapters(tool_names, target)

            # Convert AdapterResult objects to dict format
            dict_results = []
            for tool_name, result in results.items():
                dict_results.append({
                    'tool_name': result.tool_name,
                    'success': result.success,
                    'exit_code': result.exit_code,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'duration': result.execution_time,
                    'artifacts': result.artifacts,
                    'metadata': result.metadata
                })

            return dict_results

        except Exception as e:
            logger.error("Parallel tool execution failed", error=str(e))
            return [{
                'tool_name': tool_name,
                'success': False,
                'error': str(e),
                'exit_code': -1
            } for tool_name in tool_names]

    async def get_tool_info(self, tool_name: str) -> Dict[str, Any]:
        """Get detailed information about a tool"""
        if tool_name not in self.tools_config:
            raise ValueError(f"Unknown tool: {tool_name}")

        config = self.tools_config[tool_name]
        available = await self.check_tool_availability(tool_name)

        return {
            'name': config['name'],
            'description': config['description'],
            'category': config['category'],
            'command_template': config['command_template'],
            'timeout': config['timeout'],
            'requires_root': config.get('requires_root', False),
            'available': available
        }
