"""
FastAPI Google OAuth Example - Application Runner

This module provides a convenient way to run the FastAPI application
using Uvicorn with appropriate configuration settings.

It configures the server to run on all network interfaces (0.0.0.0)
and enables hot reload during development when DEBUG mode is enabled.

Author: James Fincher
Copyright: 2025
License: Private - All Rights Reserved
"""

import uvicorn
from app.core.config import settings

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="localhost",
        port=8000,  # Changed port from 8001 to 8002
        reload=settings.DEBUG,  # Enable reload only in debug mode
        log_level="info"  # Use Uvicorn's logger, can be configured further
    )
