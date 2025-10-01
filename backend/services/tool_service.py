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
from backend.tool_discovery import tool_discovery_service
from backend.adapters.adapter_manager import AdapterManager
from backend.middleware.error_handler import ToolExecutionError

logger = structlog.get_logger()

class ToolService:
    """Service for managing security tools using the unified tool discovery system"""

    def __init__(self):
        self.adapter_manager = AdapterManager()
        # Use tool_discovery_service instead of hardcoded configs

    async def initialize_tools_db(self, db: AsyncSession):
        """Initialize tools in the database using tool discovery service"""
        try:
            # Check if tools already exist
            result = await db.execute(select(Tool).limit(1))
            existing_tools = result.scalars().all()

            if existing_tools:
                logger.info("Tools already initialized")
                return

            # Ensure discovery service is ready
            await tool_discovery_service.ensure_ready()
            
            # Get discovered tools
            discovered_tools = await tool_discovery_service.list_tools()

            # Create tool records from discovered tools
            tools_to_create = []
            for tool_record in discovered_tools:
                tool = Tool(
                    name=tool_record.name,
                    description=tool_record.description,
                    category=tool_record.category,
                    command_template=" ".join(tool_record.command_template),
                    available=tool_record.installed,
                    installed=tool_record.installed,
                    version=tool_record.version,
                    last_check=datetime.fromisoformat(tool_record.last_checked) if tool_record.last_checked else None
                )
                tools_to_create.append(tool)

            for tool in tools_to_create:
                db.add(tool)

            await db.commit()
            logger.info(f"Initialized {len(tools_to_create)} tools in database from discovery service")

        except Exception as e:
            logger.error("Failed to initialize tools", error=str(e))
            raise

    async def check_tool_availability(self, tool_name: str) -> bool:
        """Check if a specific tool is available using discovery service"""
        try:
            tool_record = await tool_discovery_service.get_tool(tool_name)
            return tool_record.installed if tool_record else False
        except Exception as e:
            logger.debug(f"Error checking tool availability: {tool_name}", error=str(e))
            return False

    async def check_all_tools_availability(self) -> Dict[str, bool]:
        """Check availability of all tools using discovery service"""
        await tool_discovery_service.ensure_ready()
        discovered_tools = await tool_discovery_service.list_tools()
        
        availability = {}
        for tool_record in discovered_tools:
            availability[tool_record.name] = tool_record.installed
        
        return availability

    async def update_tools_availability(self, db: AsyncSession):
        """Update availability status of all tools in database using discovery service"""
        try:
            # Refresh all tools in discovery service
            refreshed_tools = await tool_discovery_service.refresh_all(force=True)

            for tool_name, tool_record in refreshed_tools.items():
                result = await db.execute(
                    select(Tool).where(Tool.name == tool_name)
                )
                tool = result.scalar_one_or_none()

                if tool:
                    tool.available = tool_record.installed
                    tool.installed = tool_record.installed
                    tool.version = tool_record.version
                    tool.last_check = datetime.fromisoformat(tool_record.last_checked) if tool_record.last_checked else datetime.now()

            await db.commit()
            logger.info("Updated tools availability status from discovery service")

        except Exception as e:
            logger.error("Failed to update tools availability", error=str(e))
            raise ToolExecutionError(
                tool_name="all",
                message=f"Failed to update tools availability: {str(e)}",
                details={"error": str(e)}
            )

    async def format_command(self, tool_name: str, target: str, **kwargs) -> str:
        """Format command template with provided parameters using discovery service"""
        # Get tool from discovery service
        tool_record = await tool_discovery_service.get_tool(tool_name)
        if not tool_record:
            # Get all available tools for error message
            all_tools = await tool_discovery_service.list_tools()
            raise ToolExecutionError(
                tool_name=tool_name,
                message=f"Unknown tool: {tool_name}",
                details={"available_tools": [t.name for t in all_tools]}
            )

        # Reconstruct command template from list
        command_template_str = " ".join(tool_record.command_template)

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
            command = command_template_str.format(**template_vars)
            return command
        except KeyError as e:
            raise ValueError(f"Missing template variable: {e}")

    async def run_tool(self, tool_name: str, target: str, **kwargs) -> Dict[str, Any]:
        """Run a security tool using the adapter system with discovery service verification"""
        # Verify tool before execution using discovery service (includes health check)
        tool_record = await tool_discovery_service.verify_tool_before_use(tool_name)
        
        if not tool_record.installed:
            raise RuntimeError(
                f"Tool '{tool_name}' is not available. "
                f"Status: {tool_record.status}. "
                f"Missing dependencies: {', '.join(tool_record.missing_dependencies) if tool_record.missing_dependencies else 'None'}"
            )

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
        """Get detailed information about a tool from discovery service"""
        tool_record = await tool_discovery_service.get_tool(tool_name)
        if not tool_record:
            raise ValueError(f"Unknown tool: {tool_name}")

        return {
            'name': tool_record.name,
            'description': tool_record.description,
            'category': tool_record.category,
            'command_template': " ".join(tool_record.command_template),
            'timeout': 300,  # Default timeout, could be made configurable per tool
            'requires_root': False,  # Could be added to ToolDefinition if needed
            'available': tool_record.installed,
            'version': tool_record.version,
            'path': tool_record.path,
            'status': tool_record.status,
            'os_dependencies': tool_record.os_dependencies,
            'missing_dependencies': tool_record.missing_dependencies
        }
