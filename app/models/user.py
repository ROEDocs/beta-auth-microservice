"""
FastAPI Google OAuth Example - User Models

This module defines Pydantic models for user-related data structures including:
- User information from OAuth providers
- JWT token payloads
- Token response structures for API endpoints

These models provide type validation, serialization/deserialization,
and automatic documentation in the OpenAPI schema.

Author: James Fincher
Copyright: 2025
License: Private - All Rights Reserved
"""

from typing import Dict, Optional, Any

from pydantic import BaseModel, EmailStr


class UserInfo(BaseModel):
    """
    User information model representing authenticated user data.
    
    This model contains the essential user information retrieved from
    the OAuth provider (Google) and is used for user identification
    and profile data throughout the application.
    
    Attributes:
        email: The user's email address (validated format)
        name: The user's display name (optional)
        picture: URL to the user's profile picture (optional)
    """
    email: EmailStr
    name: Optional[str] = None
    picture: Optional[str] = None


class TokenPayload(BaseModel):
    """
    Token payload model representing the contents of a JWT token.
    
    This model defines the structure of the data stored in JWT tokens,
    including subject (user identifier), expiration time, token type,
    and optional user information.
    
    Attributes:
        sub: Subject identifier (typically user email)
        exp: Expiration timestamp (Unix time)
        type: Token type ("access" or "refresh")
        user_info: Additional user information (for access tokens)
    """
    sub: str
    exp: int
    type: str
    user_info: Optional[Dict[str, Any]] = None


class TokenResponse(BaseModel):
    """
    Token response model for API responses containing tokens.
    
    This model defines the structure of responses from token-issuing
    endpoints like /auth/refresh, following OAuth 2.0 conventions.
    
    Attributes:
        access_token: The JWT access token string
        token_type: The token type (always "bearer" for this application)
    """
    access_token: str
    token_type: str = "bearer"
