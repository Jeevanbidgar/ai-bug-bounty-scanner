"""
Base adapter class for security tool execution

Provides the foundation for running security tools in isolated environments
with proper resource limits, timeout handling, and output capture.
"""

import asyncio
import json
import os
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
import subprocess
import docker
import structlog

logger = structlog.get_logger()

@dataclass
class AdapterConfig:
    """Configuration for tool adapter execution"""
    timeout: int = 300  # seconds
    memory_limit: str = "512m"  # Docker memory limit
    cpu_limit: float = 1.0  # CPU cores
    network_mode: str = "none"  # Network isolation
    read_only: bool = True  # Read-only filesystem
    tmpfs: List[str] = None  # Temporary filesystems
    environment: Dict[str, str] = None
    volumes: Dict[str, Dict[str, str]] = None  # Mounts
    working_dir: str = "/app"
    user: str = "nobody"  # Non-root user

    def __post_init__(self):
        if self.tmpfs is None:
            self.tmpfs = ["/tmp", "/var/tmp"]
        if self.environment is None:
            self.environment = {}
        if self.volumes is None:
            self.volumes = {}

@dataclass
class AdapterResult:
    """Result from tool execution"""
    success: bool
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    execution_time: float = 0.0
    artifacts: List[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.artifacts is None:
            self.artifacts = []
        if self.metadata is None:
            self.metadata = {}

class BaseAdapter(ABC):
    """Base class for all security tool adapters"""

    def __init__(self, tool_name: str, config: Optional[AdapterConfig] = None):
        self.tool_name = tool_name
        self.config = config or AdapterConfig()
        self.docker_client = None

        # Try to initialize Docker client
        try:
            self.docker_client = docker.from_env()
            self.containerized = True
            logger.info(f"Initialized containerized adapter for {tool_name}")
        except Exception as e:
            logger.warning(f"Docker not available for {tool_name}, falling back to subprocess: {e}")
            self.containerized = False

    @abstractmethod
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Get the command to execute for the tool"""
        pass

    @abstractmethod
    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        """Parse tool output into structured data"""
        pass

    def _create_container_config(self, command: List[str], target: str) -> Dict[str, Any]:
        """Create Docker container configuration"""
        # Create temporary output directory
        temp_dir = tempfile.mkdtemp(prefix=f"{self.tool_name}_{target.replace('://', '_')}_")

        config = {
            'image': self.get_container_image(),
            'command': command,
            'detach': False,
            'remove': True,  # Auto-remove container after execution
            'environment': self.config.environment,
            'working_dir': self.config.working_dir,
            'user': self.config.user,
            'network_mode': self.config.network_mode,
            'read_only': self.config.read_only,
            'tmpfs': {path: 'rw,noexec,nosuid,size=100m' for path in self.config.tmpfs},
            'mem_limit': self.config.memory_limit,
            'cpu_quota': int(self.config.cpu_limit * 100000),  # Convert to microseconds
            'cpu_period': 100000,
            'volumes': {
                temp_dir: {'bind': '/output', 'mode': 'rw'},
                **self.config.volumes
            },
            'stdout': True,
            'stderr': True,
            'stdin_open': False
        }

        return config, temp_dir

    def get_container_image(self) -> str:
        """Get Docker image for this tool"""
        # Default image registry
        return f"security-tools/{self.tool_name}:latest"

    async def execute(self, target: str, **kwargs) -> AdapterResult:
        """Execute the tool with the given target"""
        start_time = time.time()

        try:
            # Get command
            command = self.get_command(target, **kwargs)

            if self.containerized and self.docker_client:
                # Run in Docker container
                result = await self._execute_containerized(command, target, **kwargs)
            else:
                # Fall back to subprocess
                result = await self._execute_subprocess(command, target, **kwargs)

            result.execution_time = time.time() - start_time
            return result

        except Exception as e:
            logger.error(f"Tool execution failed for {self.tool_name}", target=target, error=str(e))
            return AdapterResult(
                success=False,
                exit_code=-1,
                stderr=str(e),
                execution_time=time.time() - start_time
            )

    async def _execute_containerized(self, command: List[str], target: str, **kwargs) -> AdapterResult:
        """Execute tool in Docker container"""
        container_config, temp_dir = self._create_container_config(command, target)

        try:
            logger.info(f"Running {self.tool_name} in container", target=target)

            # Run container
            container = self.docker_client.containers.run(**container_config)

            # Get logs
            logs = container.decode('utf-8') if isinstance(container, bytes) else str(container)

            # Parse logs (simplified - in reality would need to handle Docker log format)
            stdout = logs
            stderr = ""

            # Check for output files
            artifacts = []
            output_dir = Path(temp_dir)
            if output_dir.exists():
                for file_path in output_dir.glob("*"):
                    if file_path.is_file():
                        artifacts.append(str(file_path))

            # Parse output
            parsed_data = self.parse_output(stdout, stderr, 0)

            return AdapterResult(
                success=True,
                exit_code=0,
                stdout=stdout,
                stderr=stderr,
                artifacts=artifacts,
                metadata=parsed_data
            )

        except Exception as e:
            logger.error(f"Container execution failed for {self.tool_name}", error=str(e))
            return AdapterResult(
                success=False,
                exit_code=-1,
                stderr=str(e)
            )
        finally:
            # Cleanup temp directory
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)

    async def _execute_subprocess(self, command: List[str], target: str, **kwargs) -> AdapterResult:
        """Execute tool using subprocess (fallback)"""
        try:
            logger.info(f"Running {self.tool_name} via subprocess", target=target, command=command)

            # Create temporary files for output
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as stdout_file, \
                 tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as stderr_file:

                # Run subprocess
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    cwd=kwargs.get('work_dir', '.'),
                    limit=1024*1024  # 1MB output limit
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=self.config.timeout
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    raise TimeoutError(f"Tool {self.tool_name} timed out after {self.config.timeout}s")

                # Read output files
                stdout_file.seek(0)
                stderr_file.seek(0)
                stdout_content = stdout_file.read()
                stderr_content = stderr_file.read()

                # Clean up temp files
                os.unlink(stdout_file.name)
                os.unlink(stderr_file.name)

                # Parse output
                parsed_data = self.parse_output(stdout_content, stderr_content, process.returncode)

                return AdapterResult(
                    success=process.returncode == 0,
                    exit_code=process.returncode,
                    stdout=stdout_content,
                    stderr=stderr_content,
                    artifacts=[stdout_file.name, stderr_file.name] if os.path.exists(stdout_file.name) else [],
                    metadata=parsed_data
                )

        except Exception as e:
            logger.error(f"Subprocess execution failed for {self.tool_name}", error=str(e))
            return AdapterResult(
                success=False,
                exit_code=-1,
                stderr=str(e)
            )

    def validate_target(self, target: str) -> bool:
        """Validate target before execution"""
        # Basic validation - can be overridden by subclasses
        if not target or not isinstance(target, str):
            return False

        # Check for obviously invalid targets
        invalid_patterns = [
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            'example.com',
            'test.com'
        ]

        if any(pattern in target.lower() for pattern in invalid_patterns):
            logger.warning(f"Potentially invalid target: {target}")
            return False

        return True

    def requires_authorization(self) -> bool:
        """Check if this tool requires special authorization"""
        return False  # Override in subclasses for high-risk tools

    def get_risk_level(self) -> str:
        """Get risk level for this tool"""
        return "low"  # Override in subclasses
