"""
Metrics API endpoint for Prometheus scraping.
"""

from fastapi import APIRouter, Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
import structlog

logger = structlog.get_logger(__name__)

router = APIRouter()


@router.get("/metrics")
async def metrics():
    """
    Prometheus metrics endpoint.
    Returns metrics in Prometheus text format for scraping.
    """
    try:
        metrics_data = generate_latest()
        return Response(content=metrics_data, media_type=CONTENT_TYPE_LATEST)
    except Exception as e:
        logger.error("metrics_endpoint_error", error=str(e))
        return Response(content="", media_type=CONTENT_TYPE_LATEST, status_code=500)
