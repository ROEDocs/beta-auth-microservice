"""
FastAPI Google OAuth Example - Main Application

This module initializes and configures the FastAPI application with:
- OAuth authentication via Google
- JWT token handling
- CORS middleware configuration
- Logging middleware
- API routers for different endpoints

The application serves as a production-ready authentication server
that can be used as a template for secure API development.

Author: James Fincher
Copyright: 2025
License: Private - All Rights Reserved
"""

import typing

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from fastapi import FastAPI, Request, Depends, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.core.config import settings
from app.core.logging_config import logger
from app.endpoints.v1.auth.router import router as auth_router
from app.endpoints.v1.health.router import router as health_router
from app.endpoints.v1.root.router import router as root_router
from app.middlewares.logging import logging_middleware

# Security scheme
security = HTTPBearer()

# Create FastAPI app
app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
    swagger_ui_parameters={"tryItOutEnabled": True, "persistAuthorization": True},
    openapi_tags=[
        {"name": "auth", "description": "Authentication operations"},
        {"name": "health", "description": "Health check endpoints"},
        {"name": "root", "description": "Root endpoints"}
    ]
)

# Add session middleware for OAuth
app.add_middleware(SessionMiddleware, secret_key=settings.SESSION_SECRET)

# CORS for frontend
if settings.CORS_ORIGIN:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.CORS_ORIGIN],  # Allows specific origin
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    # Allow all origins if CORS_ORIGIN is not set (less secure, for specific use cases)
    logger.warning("CORS_ORIGIN not set, allowing all origins.")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Add logging middleware
app.middleware("http")(logging_middleware)

# Configure Jinja2 templates
templates = Jinja2Templates(directory="templates")

# Root path with login UI
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """
    Serve the root endpoint with a simple HTML login page using Jinja2.
    
    This endpoint provides a basic UI for testing the authentication flow,
    including a Google sign-in button and a token refresh test function.
    The page includes JavaScript to handle the OAuth callback redirect,
    extracting the access token from the URL fragment or displaying errors
    from query parameters.
    
    Args:
        request: The FastAPI request object.
    """
    # Render the template, passing the request object
    return templates.TemplateResponse("login.html", {"request": request})


# Register versioned endpoint routers
app.include_router(root_router, prefix=settings.API_V1_STR)
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(health_router, prefix=settings.API_V1_STR)

# Include test router if in debug mode
if settings.DEBUG:
    from app.endpoints.v1.test.router import router as test_router
    logger.warning("DEBUG mode enabled. Including test routes.")
    app.include_router(test_router, prefix=settings.API_V1_STR)
