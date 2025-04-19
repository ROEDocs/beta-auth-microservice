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
        FRONTEND_CALLBACK_URL_BASE: Base URL for frontend callback
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
    FRONTEND_CALLBACK_URL_BASE: str = "/"  # Base URL for frontend callback

    # App Config
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "FastAPI Auth Server"
    DEBUG: bool = False  # Set to True for development features

    class Config:
        """
        Pydantic configuration class for Settings.
        
        Specifies the .env file to load environment variables from.
        """
        env_file = ".env"


# Create a global instance of the settings
settings = Settings()
