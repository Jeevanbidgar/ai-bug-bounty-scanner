"""
Request logging middleware to track all API requests and responses.
"""

import time
import uuid
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
import structlog

logger = structlog.get_logger(__name__)


class RequestLoggerMiddleware(BaseHTTPMiddleware):
    """
    Middleware to log all incoming requests and their responses.
    Tracks request timing, status codes, and client information.
    """
    
    async def dispatch(self, request: Request, call_next):
        # Generate unique request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        
        # Start timer
        start_time = time.time()
        
        # Log incoming request
        logger.info(
            "request_started",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            query_params=dict(request.query_params),
            client_host=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", "unknown")
        )
        
        # Process request
        try:
            response = await call_next(request)
            
            # Calculate processing time
            process_time = time.time() - start_time
            
            # Add custom headers
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Process-Time"] = str(process_time)
            
            # Log response
            logger.info(
                "request_completed",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                process_time_seconds=round(process_time, 3),
                client_host=request.client.host if request.client else "unknown"
            )
            
            return response
            
        except Exception as exc:
            # Log error
            process_time = time.time() - start_time
            logger.error(
                "request_failed",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                error=str(exc),
                process_time_seconds=round(process_time, 3),
                client_host=request.client.host if request.client else "unknown"
            )
            raise
