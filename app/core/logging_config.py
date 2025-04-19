"""
FastAPI Google OAuth Example - Logging Configuration

This module configures the application's logging system with multiple handlers:
1. Console logging for development visibility
2. File logging for all information level and above messages
3. Separate error logging for easier troubleshooting

The logging levels are automatically adjusted based on the application's
DEBUG setting, providing more verbose output during development.

Author: James Fincher
Copyright: 2025
License: Private - All Rights Reserved
"""

import logging
import os
import sys
from logging import FileHandler, Formatter, Logger, StreamHandler

from app.core.config import settings

# Create logs directory if it doesn't exist
os.makedirs("logs", exist_ok=True)

# Configure root logger
root_logger: Logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)

# Clear any existing handlers
if root_logger.handlers:
    root_logger.handlers.clear()

# Console handler
console_handler: StreamHandler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
console_formatter: Formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
console_handler.setFormatter(console_formatter)
root_logger.addHandler(console_handler)

# File handler for all logs (info and above)
file_handler: FileHandler = logging.FileHandler("logs/auth_server.log")
file_handler.setLevel(logging.INFO)
file_formatter: Formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
file_handler.setFormatter(file_formatter)
root_logger.addHandler(file_handler)

# File handler for errors only
error_file_handler: FileHandler = logging.FileHandler("logs/error.log")
error_file_handler.setLevel(logging.ERROR)
error_file_handler.setFormatter(file_formatter)
root_logger.addHandler(error_file_handler)

# Get a logger instance for the application
logger: Logger = logging.getLogger("auth_server")
logger.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)

# Log startup information
logger.info("Logging initialized. Debug mode: %s", settings.DEBUG)
if settings.DEBUG:
    logger.debug("Debug logging enabled")
