"""
AI Bug Bounty Scanner - FastAPI Backend

Main application entry point for the FastAPI backend service.
"""

import os
import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import structlog
from dotenv import load_dotenv
import time

# Load environment variables
load_dotenv()

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

# Import database and models
from .database import init_db, close_db
from .models import Scan, Vulnerability, Report, Tool, ReconPlan
from .plugins.plugin_loader import plugin_loader
from .workflow_engine import workflow_engine

# Database initialization will be done in the lifespan context

# Import routers
from .api.scans import router as scans_router
from .api.tools import router as tools_router
from .api.reports import router as reports_router
from .api.recon import router as recon_router
from .api.health import router as health_router
from .api.workflows import router as workflows_router
from .api.metrics import router as metrics_router

# Import error handlers and middleware
from .middleware.error_handler import register_exception_handlers
from .middleware.request_logger import RequestLoggerMiddleware
from .middleware.rate_limit import setup_rate_limiting
from .middleware.resource_limiter import init_resource_limiter, shutdown_resource_limiter
from .middleware.metrics import init_metrics
from .middleware.sentry_integration import init_sentry

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager"""
    logger.info("Starting AI Bug Bounty Scanner backend")

    # Initialize Sentry (if configured)
    sentry_dsn = os.getenv("SENTRY_DSN")
    environment = os.getenv("ENVIRONMENT", "development")
    if sentry_dsn:
        init_sentry(dsn=sentry_dsn, environment=environment, traces_sample_rate=0.1)
        logger.info("Sentry error tracking enabled")
    
    # Initialize metrics
    init_metrics()
    logger.info("Prometheus metrics initialized")
    
    # Initialize resource limiter
    await init_resource_limiter()
    logger.info("Resource limiter initialized")

    # Initialize database
    await init_db()

    # Initialize database tables and seed data
    from .database_init import init_database
    await init_database()

    # Load plugins and workflows
    logger.info("Loading plugins and workflows...")
    try:
        plugin_loader.load_tool_plugins()
        plugin_loader.load_workflow_templates()
        logger.info(f"Loaded {len(plugin_loader._loaded_tools)} tool plugins and {len(plugin_loader._loaded_workflows)} workflow templates")
    except Exception as e:
        logger.error(f"Plugin loading failed: {e}")

    yield

    # Cleanup
    logger.info("Shutting down AI Bug Bounty Scanner backend...")
    await shutdown_resource_limiter()
    await close_db()
    logger.info("AI Bug Bounty Scanner backend stopped")

# Create FastAPI application
app = FastAPI(
    title="AI Bug Bounty Scanner API",
    description="Professional security scanning and reconnaissance platform",
    version="2.0.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["tauri://localhost", "https://tauri.localhost", "http://localhost:3000", "http://localhost:5173", "http://localhost:1420"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure trusted hosts
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["tauri://localhost", "https://tauri.localhost", "localhost", "127.0.0.1"]
)

# Add request logging middleware
app.add_middleware(RequestLoggerMiddleware)
logger.info("Request logging middleware added")

# Setup rate limiting
setup_rate_limiting(app)
logger.info("Rate limiting configured")

# Register exception handlers - MUST be done after creating the app
register_exception_handlers(app)
logger.info("Error handlers registered")

# Include routers
app.include_router(health_router, prefix="/api/health", tags=["health"])
app.include_router(scans_router, prefix="/api/scans", tags=["scans"])
app.include_router(tools_router, prefix="/api/tools", tags=["tools"])
app.include_router(reports_router, prefix="/api/reports", tags=["reports"])
app.include_router(recon_router, prefix="/api/recon", tags=["recon"])
app.include_router(workflows_router, prefix="/api/workflows", tags=["workflows"])
app.include_router(metrics_router, tags=["metrics"])

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": "AI Bug Bounty Scanner API",
        "version": "2.0.0",
        "status": "running"
    }

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all HTTP requests"""
    start_time = time.time()

    # Log request
    logger.info(
        "Request started",
        method=request.method,
        url=str(request.url),
        client=request.client.host if request.client else None
    )

    response = await call_next(request)

    # Log response
    process_time = time.time() - start_time
    logger.info(
        "Request completed",
        method=request.method,
        url=str(request.url),
        status_code=response.status_code,
        process_time=f"{process_time:.3f}s"
    )

    return response

if __name__ == "__main__":
    import uvicorn

    logger.info("Starting development server")

    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )
