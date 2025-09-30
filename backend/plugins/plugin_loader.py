"""
Plugin loader for AI Bug Bounty Scanner
Loads tool definitions and workflow templates from YAML files
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class ToolPlugin:
    """Represents a tool plugin definition"""
    name: str
    description: str
    category: str
    risk_level: str = "medium"
    command_template: List[str] = field(default_factory=list)
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    output_format: str = "text"
    timeout: int = 300
    dependencies: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ToolPlugin':
        """Create ToolPlugin from dictionary"""
        return cls(
            name=data.get('name', ''),
            description=data.get('description', ''),
            category=data.get('category', ''),
            risk_level=data.get('risk_level', 'medium'),
            command_template=data.get('command_template', []),
            parameters=data.get('parameters', []),
            output_format=data.get('output_format', 'text'),
            timeout=data.get('timeout', 300),
            dependencies=data.get('dependencies', []),
            tags=data.get('tags', [])
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'name': self.name,
            'description': self.description,
            'category': self.category,
            'risk_level': self.risk_level,
            'command_template': self.command_template,
            'parameters': self.parameters,
            'output_format': self.output_format,
            'timeout': self.timeout,
            'dependencies': self.dependencies,
            'tags': self.tags
        }

@dataclass
class WorkflowTemplate:
    """Represents a workflow template"""
    name: str
    description: str
    category: str
    steps: List[Dict[str, Any]] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WorkflowTemplate':
        """Create WorkflowTemplate from dictionary"""
        return cls(
            name=data.get('name', ''),
            description=data.get('description', ''),
            category=data.get('category', ''),
            steps=data.get('steps', []),
            parameters=data.get('parameters', {}),
            tags=data.get('tags', [])
        )

class PluginLoader:
    """Loads plugins from YAML files"""

    def __init__(self, plugin_dir: str = "backend/plugins"):
        self.plugin_dir = Path(plugin_dir)
        self.plugin_dir.mkdir(parents=True, exist_ok=True)
        self._loaded_tools: Dict[str, ToolPlugin] = {}
        self._loaded_workflows: Dict[str, WorkflowTemplate] = {}

    def load_tool_plugins(self) -> Dict[str, ToolPlugin]:
        """Load all tool plugins from YAML files"""
        self._loaded_tools.clear()

        if not self.plugin_dir.exists():
            logger.warning(f"Plugin directory {self.plugin_dir} does not exist")
            return self._loaded_tools

        # Load built-in tools first
        self._load_builtin_tools()

        # Load plugin files
        for yaml_file in self.plugin_dir.glob("*.yaml"):
            if yaml_file.name.startswith('_'):
                continue  # Skip template files

            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)

                if not data or not isinstance(data, dict):
                    logger.warning(f"Invalid plugin file: {yaml_file}")
                    continue

                # Check if this is a tool plugin
                if 'name' in data and 'command_template' in data:
                    tool = ToolPlugin.from_dict(data)
                    self._loaded_tools[tool.name] = tool
                    logger.info(f"Loaded tool plugin: {tool.name}")

            except Exception as e:
                logger.error(f"Error loading plugin {yaml_file}: {e}")

        logger.info(f"Loaded {len(self._loaded_tools)} tool plugins")
        return self._loaded_tools.copy()

    def load_workflow_templates(self) -> Dict[str, WorkflowTemplate]:
        """Load workflow templates from YAML files"""
        self._loaded_workflows.clear()

        if not self.plugin_dir.exists():
            logger.warning(f"Plugin directory {self.plugin_dir} does not exist")
            return self._loaded_workflows

        # Load workflow files
        for yaml_file in self.plugin_dir.glob("workflows/*.yaml"):
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)

                if not data or not isinstance(data, dict):
                    logger.warning(f"Invalid workflow file: {yaml_file}")
                    continue

                # Check if this is a workflow template
                if 'name' in data and 'steps' in data:
                    workflow = WorkflowTemplate.from_dict(data)
                    self._loaded_workflows[workflow.name] = workflow
                    logger.info(f"Loaded workflow template: {workflow.name}")

            except Exception as e:
                logger.error(f"Error loading workflow {yaml_file}: {e}")

        logger.info(f"Loaded {len(self._loaded_workflows)} workflow templates")
        return self._loaded_workflows.copy()

    def _load_builtin_tools(self):
        """Load built-in tool definitions"""
        builtin_tools = {
            "subfinder": {
                "name": "subfinder",
                "description": "Fast passive subdomain discovery tool",
                "category": "recon",
                "risk_level": "low",
                "command_template": ["subfinder", "-d", "{target}"],
                "parameters": [
                    {"name": "target", "type": "string", "required": True},
                    {"name": "output", "type": "file", "required": False}
                ],
                "output_format": "text",
                "timeout": 120,
                "tags": ["passive", "subdomain", "recon"]
            },
            "amass": {
                "name": "amass",
                "description": "Comprehensive network reconnaissance tool",
                "category": "recon",
                "risk_level": "low",
                "command_template": ["amass", "enum", "-passive", "-d", "{target}"],
                "parameters": [
                    {"name": "target", "type": "string", "required": True}
                ],
                "output_format": "text",
                "timeout": 300,
                "tags": ["passive", "recon", "dns"]
            },
            "nuclei": {
                "name": "nuclei",
                "description": "Fast and customizable vulnerability scanner",
                "category": "vulnerability",
                "risk_level": "medium",
                "command_template": ["nuclei", "-u", "{target}"],
                "parameters": [
                    {"name": "target", "type": "string", "required": True},
                    {"name": "templates", "type": "file", "required": False}
                ],
                "output_format": "json",
                "timeout": 600,
                "tags": ["vulnerability", "web", "active"]
            },
            "nmap": {
                "name": "nmap",
                "description": "Network discovery and security auditing tool",
                "category": "network",
                "risk_level": "medium",
                "command_template": ["nmap", "-sV", "-sC", "-O", "{target}"],
                "parameters": [
                    {"name": "target", "type": "string", "required": True}
                ],
                "output_format": "xml",
                "timeout": 900,
                "tags": ["network", "port-scan", "active"]
            }
        }

        for name, data in builtin_tools.items():
            tool = ToolPlugin.from_dict(data)
            self._loaded_tools[name] = tool

    def get_tool_plugin(self, tool_name: str) -> Optional[ToolPlugin]:
        """Get a specific tool plugin"""
        return self._loaded_tools.get(tool_name)

    def get_workflow_template(self, workflow_name: str) -> Optional[WorkflowTemplate]:
        """Get a specific workflow template"""
        return self._loaded_workflows.get(workflow_name)

    def list_tools_by_category(self, category: str) -> List[ToolPlugin]:
        """Get all tools in a specific category"""
        return [tool for tool in self._loaded_tools.values() if tool.category == category]

    def search_tools(self, query: str) -> List[ToolPlugin]:
        """Search tools by name, description, or tags"""
        query = query.lower()
        results = []

        for tool in self._loaded_tools.values():
            if (query in tool.name.lower() or
                query in tool.description.lower() or
                any(query in tag.lower() for tag in tool.tags)):
                results.append(tool)

        return results

# Global plugin loader instance
plugin_loader = PluginLoader()
