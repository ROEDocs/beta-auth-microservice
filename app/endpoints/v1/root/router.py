"""
FastAPI Google OAuth Example - Root Router

This module defines the root routes for the API, including:
- Base URL endpoint routing
- Integration with the root controller

The router serves as a thin layer that delegates actual request handling
to the appropriate controller, following the MVC pattern.

Author: James Fincher
Copyright: 2025
License: Private - All Rights Reserved
"""

from fastapi import APIRouter

from app.controllers.root_controller import router as root_controller_router

router = APIRouter(
    prefix="",
    tags=["root"]
)

# Include root controller routes (defines GET "/")
router.include_router(root_controller_router)
