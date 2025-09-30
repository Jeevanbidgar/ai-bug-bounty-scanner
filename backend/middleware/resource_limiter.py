"""
Resource limiter for controlling tool execution resources.
Prevents resource exhaustion and ensures safe execution of security tools.
"""

import asyncio
import psutil
import structlog
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field

logger = structlog.get_logger(__name__)


@dataclass
class ResourceLimits:
    """Resource limits for tool execution"""
    max_memory_mb: int = 1024  # 1GB
    max_cpu_percent: float = 80.0
    max_execution_time: int = 600  # 10 minutes
    max_concurrent_tools: int = 3
    max_disk_io_mb: int = 500
    max_network_mb: int = 1000


@dataclass
class ResourceUsage:
    """Track resource usage for a process"""
    pid: int
    tool_name: str
    started_at: datetime
    memory_mb: float = 0.0
    cpu_percent: float = 0.0
    disk_io_mb: float = 0.0
    network_mb: float = 0.0
    status: str = "running"
    metadata: Dict[str, Any] = field(default_factory=dict)


class ResourceLimiter:
    """
    Manages resource limits for tool execution.
    Monitors and enforces CPU, memory, disk, and network limits.
    """
    
    def __init__(self, limits: Optional[ResourceLimits] = None):
        self.limits = limits or ResourceLimits()
        self.active_processes: Dict[int, ResourceUsage] = {}
        self._monitoring = False
        self._monitor_task: Optional[asyncio.Task] = None
        
    async def start_monitoring(self):
        """Start background monitoring of active processes"""
        if self._monitoring:
            return
            
        self._monitoring = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info(
            "resource_monitoring_started",
            limits={
                "max_memory_mb": self.limits.max_memory_mb,
                "max_cpu_percent": self.limits.max_cpu_percent,
                "max_execution_time": self.limits.max_execution_time,
                "max_concurrent_tools": self.limits.max_concurrent_tools
            }
        )
        
    async def stop_monitoring(self):
        """Stop background monitoring"""
        self._monitoring = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        logger.info("resource_monitoring_stopped")
        
    async def _monitor_loop(self):
        """Background loop to monitor active processes"""
        while self._monitoring:
            try:
                await self._check_active_processes()
                await asyncio.sleep(2)  # Check every 2 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("monitoring_error", error=str(e))
                
    async def _check_active_processes(self):
        """Check resource usage of active processes"""
        for pid, usage in list(self.active_processes.items()):
            try:
                if not psutil.pid_exists(pid):
                    self._cleanup_process(pid, "completed")
                    continue
                    
                process = psutil.Process(pid)
                
                # Update resource usage
                usage.memory_mb = process.memory_info().rss / (1024 * 1024)
                usage.cpu_percent = process.cpu_percent(interval=0.1)
                
                # Check memory limit
                if usage.memory_mb > self.limits.max_memory_mb:
                    logger.warning(
                        "memory_limit_exceeded",
                        pid=pid,
                        tool=usage.tool_name,
                        memory_mb=usage.memory_mb,
                        limit_mb=self.limits.max_memory_mb
                    )
                    await self.kill_process(pid, "memory_limit_exceeded")
                    continue
                    
                # Check CPU limit
                if usage.cpu_percent > self.limits.max_cpu_percent:
                    logger.warning(
                        "cpu_limit_exceeded",
                        pid=pid,
                        tool=usage.tool_name,
                        cpu_percent=usage.cpu_percent,
                        limit_percent=self.limits.max_cpu_percent
                    )
                    
                # Check execution time
                elapsed = (datetime.utcnow() - usage.started_at).total_seconds()
                if elapsed > self.limits.max_execution_time:
                    logger.warning(
                        "timeout_exceeded",
                        pid=pid,
                        tool=usage.tool_name,
                        elapsed_seconds=elapsed,
                        limit_seconds=self.limits.max_execution_time
                    )
                    await self.kill_process(pid, "timeout_exceeded")
                    
            except psutil.NoSuchProcess:
                self._cleanup_process(pid, "completed")
            except Exception as e:
                logger.error("process_check_error", pid=pid, error=str(e))
                
    def can_start_tool(self) -> tuple[bool, Optional[str]]:
        """Check if a new tool can be started"""
        active_count = len([p for p in self.active_processes.values() if p.status == "running"])
        
        if active_count >= self.limits.max_concurrent_tools:
            return False, f"Maximum concurrent tools limit reached ({self.limits.max_concurrent_tools})"
            
        # Check system resources
        try:
            system_memory = psutil.virtual_memory()
            if system_memory.percent > 90:
                return False, "System memory usage too high (>90%)"
                
            system_cpu = psutil.cpu_percent(interval=0.1)
            if system_cpu > 90:
                return False, "System CPU usage too high (>90%)"
                
        except Exception as e:
            logger.error("system_check_error", error=str(e))
            
        return True, None
        
    def register_process(self, pid: int, tool_name: str, metadata: Optional[Dict[str, Any]] = None) -> ResourceUsage:
        """Register a new process for monitoring"""
        usage = ResourceUsage(
            pid=pid,
            tool_name=tool_name,
            started_at=datetime.utcnow(),
            metadata=metadata or {}
        )
        self.active_processes[pid] = usage
        
        logger.info(
            "process_registered",
            pid=pid,
            tool=tool_name,
            active_count=len(self.active_processes)
        )
        
        return usage
        
    async def kill_process(self, pid: int, reason: str):
        """Kill a process and cleanup"""
        try:
            if psutil.pid_exists(pid):
                process = psutil.Process(pid)
                
                # Try graceful termination first
                process.terminate()
                try:
                    process.wait(timeout=5)
                except psutil.TimeoutExpired:
                    # Force kill if termination fails
                    process.kill()
                    
                logger.warning(
                    "process_killed",
                    pid=pid,
                    reason=reason,
                    tool=self.active_processes.get(pid, {}).tool_name if pid in self.active_processes else "unknown"
                )
                
        except psutil.NoSuchProcess:
            pass
        except Exception as e:
            logger.error("kill_process_error", pid=pid, error=str(e))
        finally:
            self._cleanup_process(pid, reason)
            
    def _cleanup_process(self, pid: int, reason: str):
        """Remove process from tracking"""
        if pid in self.active_processes:
            usage = self.active_processes[pid]
            usage.status = reason
            
            elapsed = (datetime.utcnow() - usage.started_at).total_seconds()
            
            logger.info(
                "process_cleanup",
                pid=pid,
                tool=usage.tool_name,
                reason=reason,
                duration_seconds=elapsed,
                peak_memory_mb=usage.memory_mb,
                peak_cpu_percent=usage.cpu_percent
            )
            
            del self.active_processes[pid]
            
    def get_active_processes(self) -> Dict[int, ResourceUsage]:
        """Get all active processes"""
        return self.active_processes.copy()
        
    def get_resource_stats(self) -> Dict[str, Any]:
        """Get current resource statistics"""
        active = [p for p in self.active_processes.values() if p.status == "running"]
        
        return {
            "active_processes": len(active),
            "max_concurrent": self.limits.max_concurrent_tools,
            "total_memory_mb": sum(p.memory_mb for p in active),
            "avg_cpu_percent": sum(p.cpu_percent for p in active) / len(active) if active else 0,
            "system_memory_percent": psutil.virtual_memory().percent,
            "system_cpu_percent": psutil.cpu_percent(interval=0.1),
            "limits": {
                "max_memory_mb": self.limits.max_memory_mb,
                "max_cpu_percent": self.limits.max_cpu_percent,
                "max_execution_time": self.limits.max_execution_time
            }
        }


# Global instance
_resource_limiter: Optional[ResourceLimiter] = None


def get_resource_limiter() -> ResourceLimiter:
    """Get or create the global resource limiter instance"""
    global _resource_limiter
    if _resource_limiter is None:
        _resource_limiter = ResourceLimiter()
    return _resource_limiter


async def init_resource_limiter(limits: Optional[ResourceLimits] = None):
    """Initialize and start resource monitoring"""
    global _resource_limiter
    _resource_limiter = ResourceLimiter(limits)
    await _resource_limiter.start_monitoring()
    return _resource_limiter


async def shutdown_resource_limiter():
    """Stop resource monitoring and cleanup"""
    global _resource_limiter
    if _resource_limiter:
        await _resource_limiter.stop_monitoring()
        _resource_limiter = None
