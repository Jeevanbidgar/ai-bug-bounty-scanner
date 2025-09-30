"""
Prometheus metrics for monitoring application performance.
Tracks requests, tool executions, errors, and resource usage.
"""

from prometheus_client import Counter, Histogram, Gauge, Info
from functools import wraps
import time
import structlog

logger = structlog.get_logger(__name__)

# Request metrics
http_requests_total = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

http_request_duration_seconds = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint']
)

http_requests_in_progress = Gauge(
    'http_requests_in_progress',
    'Number of HTTP requests in progress',
    ['method', 'endpoint']
)

# Tool execution metrics
tool_executions_total = Counter(
    'tool_executions_total',
    'Total tool executions',
    ['tool_name', 'status']
)

tool_execution_duration_seconds = Histogram(
    'tool_execution_duration_seconds',
    'Tool execution duration in seconds',
    ['tool_name']
)

tool_executions_active = Gauge(
    'tool_executions_active',
    'Number of active tool executions',
    ['tool_name']
)

tool_failures_total = Counter(
    'tool_failures_total',
    'Total tool execution failures',
    ['tool_name', 'error_type']
)

# Scan metrics
scans_total = Counter(
    'scans_total',
    'Total scans initiated',
    ['scan_type']
)

scans_active = Gauge(
    'scans_active',
    'Number of active scans'
)

scan_duration_seconds = Histogram(
    'scan_duration_seconds',
    'Scan duration in seconds',
    ['scan_type']
)

vulnerabilities_found = Counter(
    'vulnerabilities_found_total',
    'Total vulnerabilities found',
    ['severity', 'tool']
)

# Resource metrics
resource_memory_usage_mb = Gauge(
    'resource_memory_usage_mb',
    'Memory usage in MB',
    ['process_type']
)

resource_cpu_usage_percent = Gauge(
    'resource_cpu_usage_percent',
    'CPU usage percentage',
    ['process_type']
)

resource_disk_io_mb = Counter(
    'resource_disk_io_mb_total',
    'Total disk I/O in MB',
    ['operation']
)

# Database metrics
db_queries_total = Counter(
    'db_queries_total',
    'Total database queries',
    ['operation', 'table']
)

db_query_duration_seconds = Histogram(
    'db_query_duration_seconds',
    'Database query duration in seconds',
    ['operation', 'table']
)

db_connections_active = Gauge(
    'db_connections_active',
    'Number of active database connections'
)

# Error metrics
errors_total = Counter(
    'errors_total',
    'Total errors',
    ['error_type', 'severity']
)

# Rate limiting metrics
rate_limit_hits_total = Counter(
    'rate_limit_hits_total',
    'Total rate limit hits',
    ['endpoint']
)

# Application info
app_info = Info('app', 'Application information')


def track_request_metrics(method: str, endpoint: str, status_code: int, duration: float):
    """Track HTTP request metrics"""
    http_requests_total.labels(method=method, endpoint=endpoint, status=status_code).inc()
    http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)
    

def track_tool_execution(tool_name: str, status: str, duration: float, error_type: str = None):
    """Track tool execution metrics"""
    tool_executions_total.labels(tool_name=tool_name, status=status).inc()
    tool_execution_duration_seconds.labels(tool_name=tool_name).observe(duration)
    
    if error_type:
        tool_failures_total.labels(tool_name=tool_name, error_type=error_type).inc()


def track_scan_metrics(scan_type: str, duration: float = None):
    """Track scan metrics"""
    scans_total.labels(scan_type=scan_type).inc()
    
    if duration:
        scan_duration_seconds.labels(scan_type=scan_type).observe(duration)


def track_vulnerability(severity: str, tool: str, count: int = 1):
    """Track vulnerability findings"""
    vulnerabilities_found.labels(severity=severity, tool=tool).inc(count)


def track_error(error_type: str, severity: str = "error"):
    """Track application errors"""
    errors_total.labels(error_type=error_type, severity=severity).inc()


def track_rate_limit_hit(endpoint: str):
    """Track rate limit hits"""
    rate_limit_hits_total.labels(endpoint=endpoint).inc()


class MetricsContext:
    """Context manager for tracking metrics"""
    
    def __init__(self, metric_type: str, labels: dict):
        self.metric_type = metric_type
        self.labels = labels
        self.start_time = None
        
    def __enter__(self):
        self.start_time = time.time()
        
        if self.metric_type == "tool":
            tool_executions_active.labels(tool_name=self.labels["tool_name"]).inc()
        elif self.metric_type == "scan":
            scans_active.inc()
        elif self.metric_type == "request":
            http_requests_in_progress.labels(
                method=self.labels["method"],
                endpoint=self.labels["endpoint"]
            ).inc()
            
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        status = "failed" if exc_type else "success"
        
        if self.metric_type == "tool":
            tool_executions_active.labels(tool_name=self.labels["tool_name"]).dec()
            track_tool_execution(
                self.labels["tool_name"],
                status,
                duration,
                error_type=str(exc_type.__name__) if exc_type else None
            )
        elif self.metric_type == "scan":
            scans_active.dec()
            track_scan_metrics(self.labels["scan_type"], duration)
        elif self.metric_type == "request":
            http_requests_in_progress.labels(
                method=self.labels["method"],
                endpoint=self.labels["endpoint"]
            ).dec()
            track_request_metrics(
                self.labels["method"],
                self.labels["endpoint"],
                self.labels.get("status_code", 500 if exc_type else 200),
                duration
            )


def metrics_middleware(metric_type: str, **labels):
    """Decorator for tracking metrics"""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            with MetricsContext(metric_type, labels):
                return await func(*args, **kwargs)
                
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            with MetricsContext(metric_type, labels):
                return func(*args, **kwargs)
                
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator


def init_metrics():
    """Initialize metrics with application info"""
    try:
        from backend.config import settings
        
        app_info.info({
            'version': '1.0.0',
            'environment': settings.environment,
            'python_version': '3.13'
        })
        
        logger.info("metrics_initialized")
    except Exception as e:
        logger.error("metrics_init_error", error=str(e))


# Import asyncio for decorator
import asyncio
