"""
Application Configuration using Pydantic Settings.

Loads configuration from environment variables and/or a .env file.
Provides a centralized settings object for the application.
"""

from functools import lru_cache
from typing import List, Optional

from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings model."""

    # --- Core Application Settings ---
    PROJECT_NAME: str = "FastAPI Microservice Template"
    API_V1_STR: str = "/api/v1"
    # Set DEBUG=True in .env for development features (like auth bypass if enabled)
    DEBUG: bool = False

    # --- CORS Settings ---
    # List of allowed origins for Cross-Origin Resource Sharing (CORS).
    # Crucial for frontend interactions.
    # Example: CORS_ORIGIN="http://localhost:3000,http://localhost:3001"
    CORS_ORIGIN: str = "http://localhost:3000" # Comma-separated string for multiple origins

    # --- Authentication Settings (Crucial - Secrets!) ---
    # The secret key used to sign and verify JWTs. REQUIRED.
    # Generate using: openssl rand -hex 32
    JWT_SECRET: str = Field(..., validation_alias="JWT_SECRET")

    # --- Authentication Dev Mode Bypass ---
    # !! DANGER !! Set to True ONLY for local development to bypass auth.
    # Requires AUTH_DEV_MODE_ENABLED=True in .env file.
    # MUST BE False in any deployed environment.
    AUTH_DEV_MODE_ENABLED: bool = False

    # Optional: Define a default user ID/email when auth bypass is active.
    # Can be overridden via DEV_MODE_USER_ID/DEV_MODE_USER_EMAIL in .env
    DEV_MODE_USER_ID: Optional[str] = "dev-user-001"
    DEV_MODE_USER_EMAIL: Optional[str] = "dev@example.com"

    @property
    def cors_origins_list(self) -> List[AnyHttpUrl]:
        """Parses the comma-separated CORS_ORIGIN string into a list."""
        return [origin.strip() for origin in self.CORS_ORIGIN.split(",") if origin]

    # Configure Pydantic settings
    model_config = SettingsConfigDict(
        env_file=".env",          # Load from .env file
        env_file_encoding="utf-8",
        case_sensitive=True,    # Match environment variable names exactly
        extra="ignore",         # Ignore extra fields from environment
    )


# Use lru_cache to create a singleton instance of the settings
# This ensures settings are loaded only once
@lru_cache()
def get_settings() -> Settings:
    """Returns the cached settings instance."""
    # Consider adding logging here if settings loading fails
    return Settings()


# Make the settings instance easily accessible
settings = get_settings() 