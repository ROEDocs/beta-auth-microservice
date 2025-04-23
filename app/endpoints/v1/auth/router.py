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

from fastapi import APIRouter, Cookie, Header, Request, Response, status, Depends
from fastapi.responses import JSONResponse, RedirectResponse
from urllib.parse import urlencode, urlparse, urlunparse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import secrets # Import secrets for state generation

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

# Security scheme
security = HTTPBearer(auto_error=True, scheme_name="JWT")

# Router definition
router = APIRouter(prefix="/auth", tags=["auth"])

@router.get("/login")
async def login(request: Request, next_url: str = "/") -> RedirectResponse:
    """
    Initiate the Google OAuth login flow.

    This endpoint redirects the user to Google's authentication page.
    It stores the desired final redirect URL (`next_url`) and a CSRF token (`state`)
    in the session before redirecting. After successful authentication,
    Google will redirect back to the callback endpoint.

    Args:
        request: The FastAPI request object containing URL information and session
        next_url: The relative path on the frontend to redirect to after login.
                  Defaults to "/". Must be a relative path.

    Returns:
        RedirectResponse: Redirect to Google's OAuth consent screen
    """
    # Basic validation for next_url to prevent open redirect vulnerabilities
    parsed_next_url = urlparse(next_url)
    if parsed_next_url.scheme or parsed_next_url.netloc:
        logger.warning("Invalid next_url provided: %s. Defaulting to '/'", next_url)
        final_next_url = "/" # Default to root if it looks like an absolute URL
    else:
        # Ensure it starts with a slash if it's not empty
        final_next_url = next_url if next_url.startswith('/') else f"/{next_url}"
        if not final_next_url:
            final_next_url = "/"

    # Generate secure state for CSRF protection
    state = secrets.token_urlsafe(32)
    request.session['oauth_state'] = state
    request.session['oauth_next_url'] = final_next_url
    logger.debug("Generated state: %s, Stored next_url: %s", state, final_next_url)

    redirect_uri = request.url_for("auth_callback")
    # Pass the generated state to Google
    return await oauth.google.authorize_redirect(request, redirect_uri, state=state)

@router.get("/callback")
async def auth_callback(request: Request) -> RedirectResponse:
    """
    Handle Google OAuth callback, issue JWT tokens, and redirect to the frontend.

    This endpoint receives the authorization code and state from Google,
    validates the state against the session, exchanges the code
    for user information, issues JWT tokens, sets the refresh token in a cookie,
    and redirects the user back to the frontend application path stored in the session,
    passing the access token in the URL fragment on success, or error details in query
    parameters on failure.

    Args:
        request: The FastAPI request object containing the authorization code and state

    Returns:
        RedirectResponse: Redirects the user to the original frontend URL with
                        access token in fragment or error in query parameters.
    """
    # Retrieve state and next_url from session FIRST
    stored_state = request.session.pop('oauth_state', None)
    final_redirect_url_path = request.session.pop('oauth_next_url', '/')
    logger.debug(
        "Callback received. Stored state: %s, Stored next_url path: %s",
        stored_state,
        final_redirect_url_path
    )

    # Get state from Google's redirect query parameters
    state_from_google = request.query_params.get('state')

    # Validate state FIRST for security
    if not state_from_google or not stored_state or state_from_google != stored_state:
        logger.error(
            "State mismatch error. Google State: %s, Session State: %s",
            state_from_google,
            stored_state
        )
        # Redirect to a generic frontend error page or root, indicating state error
        error_params = urlencode({
            "error": "state_mismatch",
            "message": "Invalid state parameter. Potential CSRF attack."
        })
        # Use FRONTEND_CALLBACK_URL_BASE as a fallback for the host/scheme part
        # Or construct a safe default error path
        base_url = settings.FRONTEND_CALLBACK_URL_BASE.rstrip('/')
        # Ensure final_redirect_url_path starts with / but avoid //
        safe_error_path = f"/{final_redirect_url_path.lstrip('/')}"
        if safe_error_path == "//": safe_error_path = "/"
        error_redirect_url = f"{base_url}{safe_error_path}?{error_params}"
        return RedirectResponse(error_redirect_url)

    # State is valid, proceed with handling the callback via the controller
    user_info, error_message = await handle_oauth_callback(request)

    # Use the stored final_redirect_url_path for the redirect base
    # Combine with the configured CORS origin (or a base URL setting) to get full URL
    # This assumes the frontend runs on the CORS_ORIGIN
    # Be cautious if frontend and backend origins differ significantly beyond hostname/port
    frontend_base_url = settings.CORS_ORIGIN.split(",")[0].strip() # Use first CORS origin

    # Ensure path starts with a single / (handle cases like "/" and "path")
    safe_path = f"/{final_redirect_url_path.lstrip('/')}"
    if safe_path == "//": safe_path = "/"

    final_redirect_base = f"{frontend_base_url}{safe_path}"

    if error_message:
        # Redirect back to the originally intended frontend path with error info
        logger.error("OAuth callback error: %s", error_message)
        query_params = urlencode({"error": "callback_failed", "message": error_message})
        return RedirectResponse(url=f"{final_redirect_base}?{query_params}")

    # Create access and refresh tokens
    access_token, refresh_token = create_tokens(user_info)

    # Construct redirect URL with access token in fragment to the originally intended path
    redirect_url_with_token = f"{final_redirect_base}#access_token={access_token}"
    logger.debug("Callback success. Redirecting to: %s", redirect_url_with_token)

    # Create redirect response and set the refresh token cookie
    response = RedirectResponse(url=redirect_url_with_token)
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
async def me(credentials: HTTPAuthorizationCredentials = Depends(security)) -> UserInfo:
    """
    Get the current user's information from their access token.
    
    This endpoint extracts and validates the access token from the Authorization
    header and returns the user information embedded in the token.
    
    Args:
        credentials: The Authorization credentials containing the Bearer token
        
    Returns:
        UserInfo: The user information from the token
        
    Raises:
        HTTPException: If the token is invalid, expired, or improperly formatted
    """
    # Get token from credentials
    token = credentials.credentials
    
    # Handle case where token might start with "Bearer " due to duplicate prefix
    if token.startswith("Bearer "):
        token = token[7:]  # Remove the duplicate "Bearer " prefix
        
    # Validate the token
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
