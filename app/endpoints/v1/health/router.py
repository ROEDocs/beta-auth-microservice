"""
FastAPI Google OAuth Example - Health Router

This module defines the health check routes for the API, providing:
- Server status monitoring endpoints
- Integration with the health controller

The router serves as a thin layer that delegates actual request handling
to the appropriate controller, following the MVC pattern.

Author: James Fincher
Copyright: 2025
License: Private - All Rights Reserved
"""

from fastapi import APIRouter

from app.controllers.health_controller import router as health_controller_router

router = APIRouter(prefix="/health", tags=["health"])
router.include_router(health_controller_router, prefix="", tags=["health"])
