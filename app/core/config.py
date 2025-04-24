"""
FastAPI Google OAuth Example - Application Configuration

This module defines the configuration settings for the application using Pydantic.
It loads environment variables from a .env file and provides type validation.
All application settings are centralized here for easy management and access.

Author: James Fincher
Copyright: 2025
License: Private - All Rights Reserved
"""

from pydantic_settings import BaseSettings
from pydantic import model_validator
import logging

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """
    Application configuration settings.
    
    This class uses Pydantic's BaseSettings to load and validate
    configuration values from environment variables. Required values
    will raise an error if not provided in the environment or .env file.
    
    Attributes:
        GOOGLE_CLIENT_ID: Google OAuth client ID for authentication
        GOOGLE_CLIENT_SECRET: Google OAuth client secret for authentication
        SESSION_SECRET: Secret key for session encryption and security
        JWT_SECRET: Secret key for JWT token signing and verification
        CORS_ORIGIN: Allowed origin for CORS requests (default: http://localhost:3000)
        ACCESS_TOKEN_EXPIRE_MINUTES: Validity period for access tokens in minutes (default: 60)
        REFRESH_TOKEN_EXPIRE_DAYS: Validity period for refresh tokens in days (default: 7)
        ALLOWED_FRONTEND_ORIGINS: Allowed Frontend Origins for Dynamic Redirects
        API_V1_STR: URL prefix for API version 1 endpoints (default: /api/v1)
        PROJECT_NAME: Name of the project displayed in API docs (default: FastAPI Auth Server)
        DEBUG: Flag to enable debug features and additional logging (default: False)
    """
    # Google OAuth
    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str

    # Secrets
    SESSION_SECRET: str
    JWT_SECRET: str

    # CORS
    CORS_ORIGIN: str = "http://localhost:3000"

    # Token Expiry
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Frontend Redirect
    # DEPRECATED: Use ALLOWED_FRONTEND_ORIGINS instead for dynamic redirects
    # FRONTEND_CALLBACK_URL_BASE: str = "/"  # Base URL for frontend callback

    # NEW: Allowed Frontend Origins for Dynamic Redirects
    # Comma-separated list of base URLs (scheme + host + port) that are allowed
    # to initiate login and receive the post-login redirect.
    # Example: ALLOWED_FRONTEND_ORIGINS="http://localhost:5173,https://your-prod-app.com"
    ALLOWED_FRONTEND_ORIGINS: str = "http://localhost:3000" # Default for safety

    # App Config
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "FastAPI Auth Server"
    DEBUG: bool = False  # Set to True for development features

    # Add a property to easily get the list of allowed origins
    @property
    def allowed_frontend_origins_list(self) -> list[str]:
        if not self.ALLOWED_FRONTEND_ORIGINS:
            return []
        return [origin.strip().rstrip('/') for origin in self.ALLOWED_FRONTEND_ORIGINS.split(",") if origin.strip()]

    # Validate that CORS_ORIGIN is within ALLOWED_FRONTEND_ORIGINS if both are set
    @model_validator(mode='after')
    def check_origins(cls, values):
        cors_origin = values.get('CORS_ORIGIN')
        allowed_origins_list = values.get('allowed_frontend_origins_list')

        if cors_origin and allowed_origins_list:
            # Ensure CORS_ORIGIN is just one for this check, or iterate if it's multi-valued
            first_cors_origin = cors_origin.split(",")[0].strip().rstrip('/')
            if first_cors_origin not in allowed_origins_list:
                # Optionally raise an error or log a strong warning
                logger.warning(
                    f"CORS_ORIGIN '{first_cors_origin}' is not listed in ALLOWED_FRONTEND_ORIGINS. "
                    f"This might cause issues if CORS_ORIGIN is used elsewhere. "
                    f"Allowed: {allowed_origins_list}"
                )
        elif not allowed_origins_list:
             logger.warning("ALLOWED_FRONTEND_ORIGINS is not set or empty. Dynamic redirects will likely fail.")

        return values

    class Config:
        """
        Pydantic configuration class for Settings.
        
        Specifies the .env file to load environment variables from.
        """
        env_file = ".env"


# Create a global instance of the settings
settings = Settings()
