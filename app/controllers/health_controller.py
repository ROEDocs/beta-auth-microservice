"""
FastAPI Google OAuth Example - Health Controller

This module provides health check endpoints for monitoring application status.
The health endpoint can be used by load balancers, monitoring tools, and
container orchestration systems to verify that the application is running
and responding to requests.

Author: James Fincher
Copyright: 2025
License: Private - All Rights Reserved
"""

from typing import Dict

from fastapi import APIRouter

router = APIRouter()


@router.get("/")
async def health_check() -> Dict[str, str]:
    """
    Health check endpoint for application monitoring.
    
    This endpoint provides a simple health status response that can be used
    by monitoring tools to verify that the application is running correctly.
    It doesn't perform any deep health checks on dependencies or databases.
    
    Returns:
        Dict[str, str]: A simple health status message indicating the service is healthy
    """
    return {"status": "healthy"}
