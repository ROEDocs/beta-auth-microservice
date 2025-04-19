"""
FastAPI Google OAuth Example - Authentication Router

This module defines the authentication endpoints for the API, including:
- Google OAuth login flow
- OAuth callback handling
- JWT token issuance and validation
- Token refresh functionality
- User information retrieval
- Logout functionality

The module follows a layered architecture with service functions for business logic
and route handlers for HTTP request/response handling.

Author: James Fincher
Copyright: 2025
License: Private - All Rights Reserved
"""

from typing import Optional

from fastapi import APIRouter, Cookie, Header, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from urllib.parse import urlencode

from app.controllers.auth_controller import (
    create_auth_error_response,
    create_tokens,
    handle_oauth_callback,
    oauth,
    set_refresh_token_cookie,
    validate_access_token,
    validate_refresh_token,
)
from app.core.logging_config import logger
from app.models.user import TokenResponse, UserInfo
from app.core.config import settings

# Router definition
router = APIRouter(prefix="/auth", tags=["auth"])

@router.get("/login")
async def login(request: Request) -> RedirectResponse:
    """
    Initiate the Google OAuth login flow.
    
    This endpoint redirects the user to Google's authentication page.
    After successful authentication, Google will redirect back to the callback endpoint.
    
    Args:
        request: The FastAPI request object containing URL information
        
    Returns:
        RedirectResponse: Redirect to Google's OAuth consent screen
    """
    redirect_uri = request.url_for("auth_callback")
    return await oauth.google.authorize_redirect(request, redirect_uri)

@router.get("/callback")
async def auth_callback(request: Request) -> RedirectResponse:
    """
    Handle Google OAuth callback, issue JWT tokens, and redirect to the frontend.

    This endpoint receives the authorization code from Google, exchanges it
    for user information, issues JWT tokens, sets the refresh token in a cookie,
    and redirects the user back to the frontend application, passing the
    access token in the URL fragment on success, or error details in query
    parameters on failure.

    Args:
        request: The FastAPI request object containing the authorization code

    Returns:
        RedirectResponse: Redirects the user to the frontend URL with
                        access token in fragment or error in query parameters.
    """
    user_info, error_message = await handle_oauth_callback(request)

    redirect_url_base = settings.FRONTEND_CALLBACK_URL_BASE

    if error_message:
        # Redirect back to frontend with error info in query parameters
        query_params = urlencode({"error": "callback_failed", "message": error_message})
        return RedirectResponse(url=f"{redirect_url_base}?{query_params}")

    # Create access and refresh tokens
    access_token, refresh_token = create_tokens(user_info)

    # Construct redirect URL with access token in fragment
    redirect_url = f"{redirect_url_base}#access_token={access_token}"

    # Create redirect response and set the refresh token cookie
    response = RedirectResponse(url=redirect_url)
    set_refresh_token_cookie(response, refresh_token)

    return response

@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    request: Request,
    response: Response,
    refresh_token: Optional[str] = Cookie(None)
) -> JSONResponse:
    """
    Refresh the access token using a refresh token.
    
    This endpoint validates the refresh token provided in the cookie and
    issues a new access token and refresh token (token rotation).
    
    Args:
        request: The FastAPI request object
        response: The FastAPI response object
        refresh_token: The refresh token from the cookie
        
    Returns:
        JSONResponse: Response containing the new access token
        
    Raises:
        HTTPException: If the refresh token is missing, invalid, or expired
    """
    if not refresh_token:
        logger.warning("Refresh token missing in request")
        raise create_auth_error_response(
            "missing_token",
            "Missing refresh token"
        )

    payload = validate_refresh_token(refresh_token)
    if not payload:
        logger.warning("Invalid refresh token provided")
        raise create_auth_error_response(
            "invalid_token",
            "Invalid or expired refresh token"
        )

    # Token is valid, issue new tokens (rotation)
    # For this example, we'll construct minimal user_info from the refresh token's sub
    user_info = {"email": payload["sub"], "name": "Unknown"}  # Placeholder name

    try:
        new_access_token, new_refresh_token = create_tokens(user_info)
        
        # Create JSON response with new access token (View)
        json_response = JSONResponse({"access_token": new_access_token, "token_type": "bearer"})
        
        # Set the new refresh token in HttpOnly cookie
        set_refresh_token_cookie(json_response, new_refresh_token)
        
        return json_response
    except Exception as e:
        logger.error("Error creating new tokens: %s", str(e))
        raise create_auth_error_response(
            "token_creation_failed",
            "Failed to create new tokens",
            status.HTTP_500_INTERNAL_SERVER_ERROR
        ) from e

@router.get("/me", response_model=UserInfo)
async def me(authorization: str = Header(...)) -> UserInfo:
    """
    Get the current user's information from their access token.
    
    This endpoint extracts and validates the access token from the Authorization
    header and returns the user information embedded in the token.
    
    Args:
        authorization: The Authorization header containing the Bearer token
        
    Returns:
        UserInfo: The user information from the token
        
    Raises:
        HTTPException: If the token is invalid, expired, or improperly formatted
    """
    # Check if Authorization header is in the correct format
    if not authorization.startswith("Bearer "):
        logger.warning("Invalid authorization header format: %s", authorization)
        raise create_auth_error_response(
            "invalid_header_format",
            "Invalid authorization header format. Expected 'Bearer {token}'"
        )

    token = authorization.split(" ")[1]
    payload = validate_access_token(token)

    if not payload:
        logger.warning("Invalid or expired access token")
        raise create_auth_error_response(
            "invalid_token",
            "Invalid or expired access token"
        )
    
    # Check if user_info is present in the token
    if "user_info" not in payload:
        logger.error("Access token missing user_info field")
        raise create_auth_error_response(
            "invalid_token_format",
            "Invalid token format: missing user information"
        )

    return payload["user_info"]

@router.get("/logout")
async def logout(response: Response) -> JSONResponse:
    """
    Logout user by clearing the refresh token cookie.
    
    This endpoint clears the refresh token cookie, effectively logging the user out.
    
    Args:
        response: The FastAPI response object
        
    Returns:
        JSONResponse: A success message indicating logout was successful
    """
    response = JSONResponse({"message": "Logout successful"})
    response.delete_cookie(key="refresh_token", httponly=True, secure=True, samesite="strict")
    return response
