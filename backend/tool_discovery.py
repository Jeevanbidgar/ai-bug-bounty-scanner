"""
Dynamic tool discovery and loading system for AI Bug Bounty Scanner
Automatically detects installed security tools on the system
"""

import asyncio
import os
import shutil
import subprocess
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
import re

logger = logging.getLogger(__name__)

@dataclass
class ToolInfo:
    """Information about a discovered tool"""
    name: str
    description: str
    category: str
    command_template: List[str]
    output_format: str = "text"
    installed: bool = False
    version: Optional[str] = None
    path: Optional[str] = None
    last_check: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for API responses"""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "command_template": self.command_template,
            "output_format": self.output_format,
            "installed": self.installed,
            "version": self.version,
            "path": self.path,
            "last_check": self.last_check
        }

class ToolDiscoveryService:
    """Discovers installed security tools on the system"""

    def __init__(self):
        # Common installation paths for security tools
        self.search_paths = self._get_search_paths()

        # Tool definitions with their expected names and categories
        self.tool_definitions = {
            "subfinder": {
                "name": "subfinder",
                "description": "Fast passive subdomain discovery tool",
                "category": "recon",
                "expected_commands": ["subfinder"],
                "version_flag": "--version",
                "check_command": ["subfinder", "--help"]
            },
            "amass": {
                "name": "amass",
                "description": "Comprehensive network reconnaissance tool",
                "category": "recon",
                "expected_commands": ["amass"],
                "version_flag": "--version",
                "check_command": ["amass", "--help"]
            },
            "nuclei": {
                "name": "nuclei",
                "description": "Fast and customizable vulnerability scanner",
                "category": "vulnerability",
                "expected_commands": ["nuclei"],
                "version_flag": "--version",
                "check_command": ["nuclei", "--help"]
            },
            "nmap": {
                "name": "nmap",
                "description": "Network discovery and security auditing tool",
                "category": "network",
                "expected_commands": ["nmap"],
                "version_flag": "--version",
                "check_command": ["nmap", "--help"]
            },
            "waybackurls": {
                "name": "waybackurls",
                "description": "Fetch URLs from Wayback Machine",
                "category": "recon",
                "expected_commands": ["waybackurls"],
                "version_flag": "--version",
                "check_command": ["waybackurls", "--help"]
            },
            "gau": {
                "name": "gau",
                "description": "Get all URLs from various sources",
                "category": "recon",
                "expected_commands": ["gau"],
                "version_flag": "--version",
                "check_command": ["gau", "--help"]
            },
            "naabu": {
                "name": "naabu",
                "description": "Fast port scanner",
                "category": "network",
                "expected_commands": ["naabu"],
                "version_flag": "--version",
                "check_command": ["naabu", "--help"]
            },
            "sqlmap": {
                "name": "sqlmap",
                "description": "Automatic SQL injection tool",
                "category": "web",
                "expected_commands": ["sqlmap"],
                "version_flag": "--version",
                "check_command": ["sqlmap", "--help"]
            },
            "ffuf": {
                "name": "ffuf",
                "description": "Fast web fuzzer",
                "category": "web",
                "expected_commands": ["ffuf"],
                "version_flag": "--version",
                "check_command": ["ffuf", "--help"]
            },
            "gobuster": {
                "name": "gobuster",
                "description": "Directory brute force tool",
                "category": "web",
                "expected_commands": ["gobuster"],
                "version_flag": "--version",
                "check_command": ["gobuster", "--help"]
            }
        }

    def _get_search_paths(self) -> List[str]:
        """Get system paths to search for tools"""
        paths = []

        # Standard PATH directories
        if os.environ.get('PATH'):
            paths.extend(os.environ['PATH'].split(os.pathsep))

        # Common installation directories
        home = Path.home()

        # Linux/Mac common locations
        common_paths = [
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            "/opt",
            str(home / ".local" / "bin"),
            str(home / "go" / "bin"),
            str(home / ".cargo" / "bin"),
        ]

        # Windows common locations
        if os.name == 'nt':
            program_files = os.environ.get('PROGRAMFILES', 'C:\\Program Files')
            program_files_x86 = os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)')

            common_paths.extend([
                str(Path(program_files) / "Git" / "usr" / "bin"),
                str(Path(program_files) / "Git" / "bin"),
                str(Path(program_files_x86) / "Git" / "usr" / "bin"),
                str(Path(program_files_x86) / "Git" / "bin"),
                str(home / "scoop" / "shims"),  # Scoop package manager
                str(home / "AppData" / "Local" / "Microsoft" / "WindowsApps"),  # Windows Store apps
            ])

        # Kali Linux specific
        common_paths.extend([
            "/usr/share/wordlists",  # Wordlists directory
            "/usr/share/seclists",    # SecLists
        ])

        # Add unique paths
        for path in common_paths:
            if path not in paths and os.path.exists(path):
                paths.append(path)

        return paths

    async def check_tool_availability(self, tool_name: str) -> Tuple[bool, Optional[str]]:
        """Check if a tool is available and get its path"""
        tool_def = self.tool_definitions.get(tool_name)
        if not tool_def:
            return False, None

        # First check if it's in PATH
        for cmd in tool_def["expected_commands"]:
            path = shutil.which(cmd)
            if path:
                return True, path

        # If not in PATH, search in common locations
        for search_path in self.search_paths:
            for cmd in tool_def["expected_commands"]:
                tool_path = Path(search_path) / cmd
                if os.name == 'nt':
                    # On Windows, also check .exe extension
                    tool_path = tool_path.with_suffix('.exe')

                if tool_path.exists() and os.access(tool_path, os.X_OK):
                    return True, str(tool_path)

        return False, None

    async def get_tool_version(self, tool_path: str, version_flag: str = "--version") -> Optional[str]:
        """Get version of a tool"""
        try:
            # Use asyncio.create_subprocess_exec for better async compatibility
            process = await asyncio.create_subprocess_exec(
                tool_path, version_flag,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Wait for completion with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=5.0
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return None

            if process.returncode == 0:
                version_output = stdout.decode('utf-8', errors='ignore').strip()
                # Extract version number using regex
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)*)', version_output)
                if version_match:
                    return version_match.group(1)

            return None
        except (FileNotFoundError, subprocess.SubprocessError):
            return None

    async def discover_tools(self) -> Dict[str, ToolInfo]:
        """Discover all available tools on the system"""
        discovered_tools = {}

        logger.info("Starting tool discovery...")

        for tool_name, tool_def in self.tool_definitions.items():
            logger.info(f"Checking tool: {tool_name}")

            # Check if tool is available
            available, tool_path = await self.check_tool_availability(tool_name)

            if available and tool_path:
                logger.info(f"Found {tool_name} at: {tool_path}")

                # Get version if possible
                version = await self.get_tool_version(tool_path, tool_def["version_flag"])

                # Create tool info
                tool_info = ToolInfo(
                    name=tool_def["name"],
                    description=tool_def["description"],
                    category=tool_def["category"],
                    command_template=tool_def["expected_commands"],
                    installed=True,
                    version=version,
                    path=tool_path,
                    last_check=datetime.utcnow().isoformat()
                )

                discovered_tools[tool_name] = tool_info
                logger.info(f"Successfully loaded {tool_name} v{version or 'unknown'}")
            else:
                logger.info(f"Tool {tool_name} not found")

                # Create placeholder for missing tools
                tool_info = ToolInfo(
                    name=tool_def["name"],
                    description=tool_def["description"],
                    category=tool_def["category"],
                    command_template=tool_def["expected_commands"],
                    installed=False,
                    last_check=datetime.utcnow().isoformat()
                )

                discovered_tools[tool_name] = tool_info

        logger.info(f"Tool discovery completed. Found {len([t for t in discovered_tools.values() if t.installed])} installed tools")
        return discovered_tools

class ToolRegistry:
    """Dynamic tool registry that loads tools from system"""

    def __init__(self):
        self.discovery_service = ToolDiscoveryService()
        self._tools: Dict[str, ToolInfo] = {}
        self._last_refresh: Optional[str] = None

    async def refresh_tools(self) -> Dict[str, ToolInfo]:
        """Refresh and reload all tools from system"""
        logger.info("Refreshing tool registry...")
        self._tools = await self.discovery_service.discover_tools()
        self._last_refresh = datetime.utcnow().isoformat()
        logger.info(f"Tool registry refreshed with {len(self._tools)} tools")
        return self._tools.copy()

    def get_tools(self) -> Dict[str, ToolInfo]:
        """Get current tool registry"""
        return self._tools.copy()

    def get_tool(self, tool_name: str) -> Optional[ToolInfo]:
        """Get specific tool info"""
        return self._tools.get(tool_name)

    def list_tools(self) -> List[Dict]:
        """List all tools as dictionaries"""
        return [tool.to_dict() for tool in self._tools.values()]

    async def check_tool_availability(self, tool_name: str) -> bool:
        """Check if a specific tool is available"""
        available, _ = await self.discovery_service.check_tool_availability(tool_name)
        return available

    def get_installed_tools(self) -> List[ToolInfo]:
        """Get only installed tools"""
        return [tool for tool in self._tools.values() if tool.installed]

    def get_tools_by_category(self, category: str) -> List[ToolInfo]:
        """Get tools by category"""
        return [tool for tool in self._tools.values() if tool.category == category]

# Global registry instance
tool_registry = ToolRegistry()

# Import datetime for the timestamp
from datetime import datetime
