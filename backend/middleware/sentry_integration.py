"""
Sentry integration for error tracking and performance monitoring.
Automatically captures errors, exceptions, and performance data.
"""

import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
from sentry_sdk.integrations.redis import RedisIntegration
from sentry_sdk.integrations.asyncio import AsyncioIntegration
import structlog

logger = structlog.get_logger(__name__)


def init_sentry(dsn: str = None, environment: str = "development", traces_sample_rate: float = 0.1):
    """
    Initialize Sentry for error tracking and performance monitoring.
    
    Args:
        dsn: Sentry DSN (Data Source Name) - get from Sentry.io project settings
        environment: Environment name (development, staging, production)
        traces_sample_rate: Percentage of transactions to sample (0.0 to 1.0)
    """
    
    if not dsn:
        logger.warning("sentry_not_configured", message="No DSN provided, skipping Sentry initialization")
        return
        
    try:
        sentry_sdk.init(
            dsn=dsn,
            environment=environment,
            
            # Integrations
            integrations=[
                FastApiIntegration(transaction_style="endpoint"),
                SqlalchemyIntegration(),
                RedisIntegration(),
                AsyncioIntegration(),
            ],
            
            # Performance monitoring
            traces_sample_rate=traces_sample_rate,
            
            # Error sampling
            sample_rate=1.0,  # Capture 100% of errors
            
            # Release tracking
            release="ai-bug-bounty-scanner@1.0.0",
            
            # PII (Personally Identifiable Information) filtering
            send_default_pii=False,  # Don't send PII by default
            
            # Before send hook for filtering/modifying events
            before_send=before_send_hook,
            
            # Before breadcrumb hook
            before_breadcrumb=before_breadcrumb_hook,
            
            # Additional options
            attach_stacktrace=True,  # Attach stack traces to messages
            max_breadcrumbs=50,  # Maximum number of breadcrumbs
            debug=False,  # Enable debug mode for troubleshooting
        )
        
        logger.info(
            "sentry_initialized",
            environment=environment,
            traces_sample_rate=traces_sample_rate
        )
        
    except Exception as e:
        logger.error("sentry_init_failed", error=str(e))


def before_send_hook(event, hint):
    """
    Hook to filter or modify events before sending to Sentry.
    Use this to:
    - Filter sensitive data
    - Ignore certain error types
    - Add custom tags/context
    """
    
    # Ignore specific exceptions
    if 'exc_info' in hint:
        exc_type, exc_value, tb = hint['exc_info']
        
        # Don't send rate limit errors
        if exc_type.__name__ == 'RateLimitExceeded':
            return None
            
        # Don't send validation errors (these are user errors, not app errors)
        if exc_type.__name__ == 'RequestValidationError':
            return None
            
    # Filter sensitive data from request
    if 'request' in event:
        request = event['request']
        
        # Remove authorization headers
        if 'headers' in request:
            headers = request['headers']
            if 'Authorization' in headers:
                headers['Authorization'] = '[Filtered]'
            if 'Cookie' in headers:
                headers['Cookie'] = '[Filtered]'
                
        # Remove sensitive query parameters
        if 'query_string' in request:
            # Filter API keys, tokens, etc.
            pass
            
    # Add custom tags
    event.setdefault('tags', {})
    event['tags']['component'] = 'backend'
    
    return event


def before_breadcrumb_hook(crumb, hint):
    """
    Hook to filter or modify breadcrumbs before adding them.
    Breadcrumbs are events that lead up to an error.
    """
    
    # Filter sensitive data from SQL queries
    if crumb.get('category') == 'query':
        # Sanitize SQL queries
        pass
        
    # Filter HTTP request data
    if crumb.get('category') == 'httplib':
        if 'data' in crumb:
            data = crumb['data']
            if 'Authorization' in data:
                data['Authorization'] = '[Filtered]'
                
    return crumb


def capture_exception(error: Exception, context: dict = None):
    """
    Manually capture an exception and send it to Sentry.
    
    Args:
        error: The exception to capture
        context: Additional context to attach to the error
    """
    
    with sentry_sdk.push_scope() as scope:
        # Add custom context
        if context:
            for key, value in context.items():
                scope.set_context(key, value)
                
        sentry_sdk.capture_exception(error)
        
    logger.error(
        "exception_captured",
        error_type=type(error).__name__,
        error_message=str(error),
        context=context
    )


def capture_message(message: str, level: str = "info", context: dict = None):
    """
    Manually capture a message and send it to Sentry.
    
    Args:
        message: The message to capture
        level: Severity level (debug, info, warning, error, fatal)
        context: Additional context
    """
    
    with sentry_sdk.push_scope() as scope:
        if context:
            for key, value in context.items():
                scope.set_context(key, value)
                
        sentry_sdk.capture_message(message, level=level)


def set_user_context(user_id: str, username: str = None, email: str = None):
    """
    Set user context for error tracking.
    
    Args:
        user_id: User identifier
        username: Username (optional)
        email: User email (optional)
    """
    
    sentry_sdk.set_user({
        "id": user_id,
        "username": username,
        "email": email
    })


def set_transaction_name(name: str):
    """Set the name of the current transaction for performance monitoring"""
    transaction = sentry_sdk.Hub.current.scope.transaction
    if transaction:
        transaction.name = name


def start_transaction(name: str, op: str = "task"):
    """
    Start a new transaction for performance monitoring.
    
    Args:
        name: Transaction name
        op: Operation type (http, task, db.query, etc.)
        
    Returns:
        Transaction context manager
    """
    return sentry_sdk.start_transaction(name=name, op=op)


def start_span(operation: str, description: str = None):
    """
    Start a new span within a transaction.
    
    Args:
        operation: Span operation name
        description: Span description
        
    Returns:
        Span context manager
    """
    return sentry_sdk.start_span(op=operation, description=description)


# Example usage decorators
def sentry_trace(func):
    """Decorator to automatically trace function execution"""
    from functools import wraps
    import asyncio
    
    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        with start_span(op="function", description=func.__name__):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                capture_exception(e, context={"function": func.__name__})
                raise
                
    @wraps(func)
    def sync_wrapper(*args, **kwargs):
        with start_span(op="function", description=func.__name__):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                capture_exception(e, context={"function": func.__name__})
                raise
                
    return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
