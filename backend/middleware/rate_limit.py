"""
Rate limiting middleware to protect API endpoints from abuse.
Uses slowapi for rate limiting based on client IP address.
"""

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import structlog

logger = structlog.get_logger(__name__)

# Create limiter instance
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["60/minute"],  # Global default: 60 requests per minute
    storage_uri="memory://",  # Use in-memory storage (can be changed to Redis)
    headers_enabled=True,  # Add rate limit headers to responses
)

# Custom rate limit configurations for different endpoint types
RATE_LIMITS = {
    "scan": "10/minute",        # Scan operations (resource intensive)
    "tool": "30/minute",         # Tool operations
    "report": "20/minute",       # Report generation
    "health": "300/minute",      # Health checks (allow more)
    "auth": "5/minute",          # Authentication attempts (strict)
    "api_general": "60/minute",  # General API calls
}

def get_rate_limit(endpoint_type: str = "api_general") -> str:
    """Get rate limit for specific endpoint type"""
    return RATE_LIMITS.get(endpoint_type, RATE_LIMITS["api_general"])


def setup_rate_limiting(app):
    """
    Setup rate limiting for the FastAPI application.
    Call this during application initialization.
    """
    # Add rate limiter to app state
    app.state.limiter = limiter
    
    # Add exception handler for rate limit exceeded
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    
    # Add middleware (optional, for automatic rate limiting)
    # app.add_middleware(SlowAPIMiddleware)
    
    logger.info(
        "rate_limiting_configured",
        default_limit="60/minute",
        storage="memory",
        endpoints=list(RATE_LIMITS.keys())
    )
    
    return limiter
