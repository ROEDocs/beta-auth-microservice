"""
FastAPI Google OAuth Example - Authentication Controller

This module provides the core authentication business logic for the application, including:
- Google OAuth client configuration and integration
- JWT token creation, validation, and management
- Authentication error handling
- Token cookie management

The controller follows a service-layer pattern, providing reusable authentication
functions that can be called from various endpoints.

Author: James Fincher
Copyright: 2025
License: Private - All Rights Reserved
"""

import traceback
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from authlib.integrations.starlette_client import OAuth
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from jose import JWTError, jwt

from app.core.config import settings
from app.core.logging_config import logger

# Algorithm used for JWT token signing and verification
ALGORITHM = "HS256"

# Initialize OAuth client
oauth = OAuth()
oauth.register(
    name="google",
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


def create_access_token(user_info: Dict[str, Any]) -> str:
    """
    Create a JWT access token for the authenticated user.
    
    This function generates a short-lived access token containing user information
    and an expiration time based on the ACCESS_TOKEN_EXPIRE_MINUTES setting.
    The token is signed using the application's JWT_SECRET.
    
    Args:
        user_info: Dictionary containing user information including email and name
                  Must contain at least 'email' and 'name' keys
    
    Returns:
        str: Encoded JWT access token as a string
    """
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_info["email"],
        "name": user_info["name"],
        "exp": expire,
        "type": "access",
        "user_info": user_info
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGORITHM)


def create_refresh_token(user_info: Dict[str, Any]) -> str:
    """
    Create a JWT refresh token for the authenticated user.
    
    This function generates a long-lived refresh token containing minimal user
    information and an expiration time based on the REFRESH_TOKEN_EXPIRE_DAYS setting.
    The token is signed using the application's JWT_SECRET.
    
    Args:
        user_info: Dictionary containing user information
                  Must contain at least an 'email' key
    
    Returns:
        str: Encoded JWT refresh token as a string
    """
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": user_info["email"],
        "exp": expire,
        "type": "refresh",
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode and validate a JWT token, returning its payload.
    
    This function attempts to decode the provided JWT token using the application's
    JWT_SECRET and the HS256 algorithm. It handles various JWT-related exceptions
    and returns None if the token is invalid or expired.
    
    Args:
        token: JWT token string to decode and validate
    
    Returns:
        Optional[Dict[str, Any]]: Dictionary containing the decoded token payload
                                 or None if decoding fails for any reason
    """
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        # Specific handling for expired tokens
        return None
    except jwt.JWTClaimsError:
        # Specific handling for invalid claims
        return None
    except JWTError:
        # Generic JWT error handling
        return None


def create_tokens(user_info: Dict[str, Any]) -> Tuple[str, str]:
    """
    Create access and refresh tokens for a user.
    
    This function generates a pair of JWT tokens for the authenticated user:
    - An access token containing user information with a short expiry
    - A refresh token with minimal information and longer expiry
    
    Args:
        user_info: Dictionary containing user information from OAuth provider
    
    Returns:
        Tuple[str, str]: A tuple containing (access_token, refresh_token)
    """
    access_token = create_access_token(user_info)
    refresh_token = create_refresh_token(user_info)
    return access_token, refresh_token


def set_refresh_token_cookie(response: JSONResponse, refresh_token: str) -> None:
    """
    Set refresh token in an HttpOnly cookie with secure settings.
    
    This function adds the refresh token to the response as an HttpOnly cookie
    with appropriate security settings to prevent XSS attacks.
    
    Args:
        response: The JSONResponse object to set the cookie on
        refresh_token: The refresh token to set in the cookie
    """
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,  # Set to False for local HTTP development
        samesite="strict",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60  # Expires in days
    )


def create_auth_error_response(
    error_type: str,
    error_message: str,
    status_code: int = 401
) -> HTTPException:
    """
    Create a standardized authentication error response.
    
    This function logs the error and returns a consistent HTTPException
    with standardized error format for authentication failures.
    
    Args:
        error_type: The type of authentication error (e.g., "invalid_token")
        error_message: The detailed error message for the client
        status_code: The HTTP status code to return (default: 401)
        
    Returns:
        HTTPException: Exception with appropriate status code and detail
    """
    logger.warning("Auth error: %s - %s", error_type, error_message)
    return HTTPException(
        status_code=status_code,
        detail={"error_type": error_type, "message": error_message}
    )


def validate_refresh_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Validate a refresh token and return the payload if valid.
    
    This function decodes the JWT refresh token and performs validation checks
    to ensure it's a valid refresh token.
    
    Args:
        token: The refresh token string to validate
        
    Returns:
        Optional[Dict[str, Any]]: The token payload if valid, None otherwise
    """
    payload = decode_token(token)
    if not payload:
        logger.warning("Invalid refresh token: Token could not be decoded")
        return None
    if payload.get("type") != "refresh":
        logger.warning("Invalid refresh token: Token type is not 'refresh'")
        return None
    return payload


def validate_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Validate an access token and return the payload if valid.
    
    This function decodes the JWT access token and performs validation checks
    to ensure it's a valid access token.
    
    Args:
        token: The access token string to validate
        
    Returns:
        Optional[Dict[str, Any]]: The token payload if valid, None otherwise
    """
    payload = decode_token(token)
    if not payload:
        logger.warning("Invalid access token: Token could not be decoded")
        return None
    if payload.get("type") != "access":
        logger.warning("Invalid access token: Token type is not 'access'")
        return None
    return payload


async def handle_oauth_callback(request: Request) -> Tuple[Dict[str, Any], Optional[str]]:
    """
    Handle the OAuth callback from Google.
    
    This function processes the authorization code received from Google,
    exchanges it for user information, and handles any errors that may occur.
    
    Args:
        request: The FastAPI request object containing the authorization code
        
    Returns:
        Tuple[Dict[str, Any], Optional[str]]: A tuple containing user information and error message 
        (if any)
    """
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = await oauth.google.userinfo(token=token)
        return user_info, None
    except Exception as e:
        tb = traceback.format_exc()
        error_message = str(e)

        # Provide more specific error messages based on exception type
        if "invalid_grant" in error_message.lower():
            error_message = "Authentication failed: Invalid or expired authorization code"
            logger.error("AUTH CALLBACK ERROR: Invalid grant. %s\nTraceback:\n%s", e, tb)
        elif "access_denied" in error_message.lower():
            error_message = "Authentication failed: Access denied by user or Google"
            logger.error("AUTH CALLBACK ERROR: Access denied. %s\nTraceback:\n%s", e, tb)
        elif "invalid_client" in error_message.lower():
            error_message = "Authentication failed: Invalid client configuration"
            logger.error("AUTH CALLBACK ERROR: Invalid client. %s\nTraceback:\n%s", e, tb)
        else:
            logger.error("AUTH CALLBACK ERROR: %s\nTraceback:\n%s", e, tb)

        return {}, error_message
