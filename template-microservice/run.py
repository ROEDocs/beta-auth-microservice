"""
Development server runner using Uvicorn.

This script allows running the FastAPI application with auto-reload enabled
for easier development.

Usage:
    python run.py
    # or using uv:
    uv run run.py
"""

import uvicorn

# TODO: Consider loading host/port/log_level from environment variables/settings
HOST = "localhost"
PORT = 8000
LOG_LEVEL = "info"
RELOAD = True

if __name__ == "__main__":
    print(f"Starting Uvicorn development server on http://{HOST}:{PORT}")
    uvicorn.run(
        "main:app", # Points to the 'app' instance in 'main.py'
        host=HOST,
        port=PORT,
        log_level=LOG_LEVEL,
        reload=RELOAD,
        # Use reload_dirs to specify directories if needed, defaults work well often
        # reload_dirs=["app"]
    ) 