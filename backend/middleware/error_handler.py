"""
Comprehensive error handling middleware for the application.
Handles all types of exceptions and provides structured error responses.
"""

import traceback
from typing import Union
from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError, HTTPException
from sqlalchemy.exc import SQLAlchemyError, IntegrityError, OperationalError
from pydantic import ValidationError
import structlog

logger = structlog.get_logger(__name__)


class AppException(Exception):
    """Base exception for application-specific errors."""
    def __init__(self, message: str, status_code: int = 500, details: dict = None):
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)


class ToolExecutionError(AppException):
    """Raised when a security tool execution fails."""
    def __init__(self, tool_name: str, message: str, details: dict = None):
        super().__init__(
            message=f"Tool execution failed: {tool_name} - {message}",
            status_code=500,
            details={"tool_name": tool_name, **(details or {})}
        )


class ScanError(AppException):
    """Raised when a scan operation fails."""
    def __init__(self, scan_id: str, message: str, details: dict = None):
        super().__init__(
            message=f"Scan failed: {message}",
            status_code=500,
            details={"scan_id": scan_id, **(details or {})}
        )


class ResourceLimitError(AppException):
    """Raised when resource limits are exceeded."""
    def __init__(self, resource: str, limit: str, details: dict = None):
        super().__init__(
            message=f"Resource limit exceeded: {resource} (limit: {limit})",
            status_code=429,
            details={"resource": resource, "limit": limit, **(details or {})}
        )


async def validation_exception_handler(
    request: Request, 
    exc: RequestValidationError
) -> JSONResponse:
    """
    Handle Pydantic validation errors.
    Returns detailed validation error information.
    """
    logger.error(
        "validation_error",
        path=request.url.path,
        method=request.method,
        errors=exc.errors(),
        client_host=request.client.host if request.client else "unknown"
    )
    
    # Format errors in a user-friendly way
    formatted_errors = []
    for error in exc.errors():
        field = " -> ".join(str(loc) for loc in error["loc"])
        formatted_errors.append({
            "field": field,
            "message": error["msg"],
            "type": error["type"]
        })
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "message": "Invalid input data provided",
            "details": formatted_errors,
            "path": request.url.path
        }
    )


async def http_exception_handler(
    request: Request,
    exc: HTTPException
) -> JSONResponse:
    """
    Handle FastAPI HTTP exceptions.
    Provides structured error responses for HTTP errors.
    """
    logger.warning(
        "http_exception",
        path=request.url.path,
        method=request.method,
        status_code=exc.status_code,
        detail=exc.detail,
        client_host=request.client.host if request.client else "unknown"
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "HTTP Error",
            "message": exc.detail,
            "status_code": exc.status_code,
            "path": request.url.path
        }
    )


async def database_exception_handler(
    request: Request,
    exc: SQLAlchemyError
) -> JSONResponse:
    """
    Handle database-related errors.
    Provides sanitized error messages without exposing DB details.
    """
    error_type = type(exc).__name__
    
    # Log full error details
    logger.error(
        "database_error",
        path=request.url.path,
        method=request.method,
        error_type=error_type,
        error=str(exc),
        traceback=traceback.format_exc(),
        client_host=request.client.host if request.client else "unknown"
    )
    
    # Provide user-friendly messages based on error type
    if isinstance(exc, IntegrityError):
        message = "Data integrity constraint violated. The operation conflicts with existing data."
        status_code = status.HTTP_409_CONFLICT
    elif isinstance(exc, OperationalError):
        message = "Database operation failed. Please try again later."
        status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    else:
        message = "A database error occurred. Please try again later."
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    
    return JSONResponse(
        status_code=status_code,
        content={
            "error": "Database Error",
            "message": message,
            "error_type": error_type,
            "path": request.url.path
        }
    )


async def app_exception_handler(
    request: Request,
    exc: AppException
) -> JSONResponse:
    """
    Handle custom application exceptions.
    """
    logger.error(
        "app_exception",
        path=request.url.path,
        method=request.method,
        message=exc.message,
        status_code=exc.status_code,
        details=exc.details,
        client_host=request.client.host if request.client else "unknown"
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.__class__.__name__,
            "message": exc.message,
            "details": exc.details,
            "path": request.url.path
        }
    )


async def general_exception_handler(
    request: Request,
    exc: Exception
) -> JSONResponse:
    """
    Catch-all handler for unexpected exceptions.
    Logs full details but returns sanitized error to client.
    """
    logger.error(
        "unhandled_exception",
        path=request.url.path,
        method=request.method,
        exception_type=type(exc).__name__,
        exception=str(exc),
        traceback=traceback.format_exc(),
        client_host=request.client.host if request.client else "unknown"
    )
    
    # In development, return more details
    # In production, return generic message
    error_detail = str(exc) if hasattr(exc, '__str__') else "An unexpected error occurred"
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred. Our team has been notified.",
            "path": request.url.path,
            # Only include in development
            # "debug": error_detail
        }
    )


async def tool_execution_error_handler(
    request: Request,
    exc: ToolExecutionError
) -> JSONResponse:
    """
    Handle tool execution specific errors.
    """
    logger.error(
        "tool_execution_error",
        path=request.url.path,
        tool_name=exc.details.get("tool_name"),
        message=exc.message,
        details=exc.details
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "Tool Execution Error",
            "message": exc.message,
            "tool": exc.details.get("tool_name"),
            "details": exc.details,
            "path": request.url.path
        }
    )


async def scan_error_handler(
    request: Request,
    exc: ScanError
) -> JSONResponse:
    """
    Handle scan operation errors.
    """
    logger.error(
        "scan_error",
        path=request.url.path,
        scan_id=exc.details.get("scan_id"),
        message=exc.message,
        details=exc.details
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "Scan Error",
            "message": exc.message,
            "scan_id": exc.details.get("scan_id"),
            "details": exc.details,
            "path": request.url.path
        }
    )


async def resource_limit_error_handler(
    request: Request,
    exc: ResourceLimitError
) -> JSONResponse:
    """
    Handle resource limit errors.
    """
    logger.warning(
        "resource_limit_exceeded",
        path=request.url.path,
        resource=exc.details.get("resource"),
        limit=exc.details.get("limit"),
        client_host=request.client.host if request.client else "unknown"
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "Resource Limit Exceeded",
            "message": exc.message,
            "resource": exc.details.get("resource"),
            "limit": exc.details.get("limit"),
            "retry_after": "60",  # Suggest retry after 60 seconds
            "path": request.url.path
        }
    )


def register_exception_handlers(app):
    """
    Register all exception handlers with the FastAPI application.
    Call this during application initialization.
    """
    # Validation errors
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(ValidationError, validation_exception_handler)
    
    # HTTP exceptions
    app.add_exception_handler(HTTPException, http_exception_handler)
    
    # Database exceptions
    app.add_exception_handler(SQLAlchemyError, database_exception_handler)
    
    # Custom application exceptions
    app.add_exception_handler(AppException, app_exception_handler)
    app.add_exception_handler(ToolExecutionError, tool_execution_error_handler)
    app.add_exception_handler(ScanError, scan_error_handler)
    app.add_exception_handler(ResourceLimitError, resource_limit_error_handler)
    
    # Catch-all for unexpected exceptions
    app.add_exception_handler(Exception, general_exception_handler)
    
    logger.info("exception_handlers_registered", handlers=8)
