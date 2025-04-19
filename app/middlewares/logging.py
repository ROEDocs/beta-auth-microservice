"""
FastAPI Google OAuth Example - Logging Middleware

This module provides middleware for comprehensive request and response logging.
It captures detailed information about each request including:
- Client information (IP, headers, method, URL)
- Request body (with sanitization of sensitive data)
- Response status and timing
- Error details for failed requests

The middleware automatically adjusts log levels based on response status codes
and application debug settings to provide appropriate verbosity.

Author: James Fincher
Copyright: 2025
License: Private - All Rights Reserved
"""

import json
import time
import traceback
from typing import Any, Awaitable, Callable, Dict, Optional

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers

from app.core.config import settings
from app.core.logging_config import logger


def _sanitize_headers(headers: Headers) -> Dict[str, str]:
    """
    Sanitize request headers to remove sensitive information.
    
    This function creates a copy of the headers dictionary and replaces
    values of sensitive headers with "[REDACTED]" to prevent logging
    of authentication tokens, cookies, and API keys.
    
    Args:
        headers: The request headers to sanitize
        
    Returns:
        Dict[str, str]: A sanitized copy of the headers dictionary
    """
    sanitized = dict(headers)
    sensitive_headers = ['authorization', 'cookie', 'x-api-key']
    
    for header in sensitive_headers:
        if header in sanitized:
            sanitized[header] = "[REDACTED]"
    
    return sanitized


def _get_client_info(request: Request) -> Dict[str, Any]:
    """
    Extract client information from the request.
    
    This function extracts and organizes relevant client information
    from the request object, including IP address, HTTP method, URL,
    path parameters, query parameters, and sanitized headers.
    
    Args:
        request: The FastAPI request object
        
    Returns:
        Dict[str, Any]: A dictionary containing client information
    """
    client = {
        "host": request.client.host if request.client else "unknown",
        "method": request.method,
        "url": str(request.url),
        "path": request.url.path,
        "path_params": dict(request.path_params),
        "query_params": dict(request.query_params),
        "headers": _sanitize_headers(request.headers),
    }
    return client


async def _get_body_text(request: Request) -> Optional[str]:
    """
    Get request body as text, with size limits and sanitization.
    
    This function reads the request body, applies size limits to prevent
    excessive logging, and sanitizes sensitive information. It attempts
    to parse JSON bodies for better formatting and field-level sanitization.
    
    Args:
        request: The FastAPI request object
        
    Returns:
        Optional[str]: The sanitized body text, or None if no body is present
    """
    body = await request.body()
    if not body:
        return None
    
    # Don't log bodies in production unless in debug mode
    if not settings.DEBUG and len(body) > 200:
        return "[BODY NOT LOGGED IN PRODUCTION]"
    
    # Truncate large bodies
    if len(body) > 1024:
        return "[BODY TOO LARGE TO LOG]"
    
    try:
        # Try to parse as JSON for better formatting
        body_json = json.loads(body)
        # Sanitize potential sensitive fields
        if isinstance(body_json, dict):
            for sensitive_field in ['password', 'token', 'secret', 'key']:
                if sensitive_field in body_json:
                    body_json[sensitive_field] = "[REDACTED]"
        return json.dumps(body_json)
    except json.JSONDecodeError:
        # If not JSON, return as string with limited length
        return body.decode('utf-8', errors='replace')


async def logging_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """
    Middleware for logging request and response details with appropriate log levels.
    
    This middleware function wraps the request handling process to log information
    before and after processing. It captures timing information, request details,
    response status, and any exceptions that occur during processing.
    
    The log level is automatically adjusted based on the response status code:
    - 2xx/3xx responses: INFO level
    - 4xx responses: WARNING level
    - 5xx responses: ERROR level
    
    Args:
        request: The incoming FastAPI request
        call_next: The next middleware or route handler in the chain
        
    Returns:
        Response: The response from the next handler
        
    Raises:
        Exception: Re-raises any exception that occurs during request processing
    """
    request_id = f"{time.time():.6f}"
    start_time = time.time()
    
    # Prepare request logging
    client_info = _get_client_info(request)
    
    # Log basic request info at INFO level
    logger.info(
        "Request %s started: %s %s from %s",
        request_id, request.method, request.url.path, client_info["host"]
    )
    
    # Log detailed request info at DEBUG level
    if settings.DEBUG:
        body_text = await _get_body_text(request)
        logger.debug(
            "Request %s details: %s",
            request_id, json.dumps({
                "client": client_info,
                "body": body_text
            })
        )
    
    try:
        # Process the request
        response: Response = await call_next(request)
        
        # Calculate processing time
        process_time = (time.time() - start_time) * 1000
        
        # Log response info based on status code
        status_code = response.status_code
        log_method = logger.info
        
        if status_code >= 500:
            log_method = logger.error
        elif status_code >= 400:
            log_method = logger.warning
        
        # Log response with appropriate level
        log_method(
            "Request %s completed: %s %s - Status: %d - Duration: %.2fms",
            request_id, request.method, request.url.path, status_code, process_time
        )
        
        # Log response details at DEBUG level
        if settings.DEBUG and isinstance(response, JSONResponse):
            try:
                response_body = response.body.decode('utf-8')
                if len(response_body) < 1024:
                    logger.debug("Response %s body: %s", request_id, response_body)
                else:
                    logger.debug("Response %s body too large to log", request_id)
            except UnicodeDecodeError:
                logger.debug("Response %s body could not be decoded", request_id)
        
        return response
    except Exception as exc:
        # Calculate processing time until exception
        process_time = (time.time() - start_time) * 1000
        
        # Get traceback
        tb = traceback.format_exc()
        
        # Log exception with detailed information
        logger.error(
            "Request %s failed: %s %s - Exception: %s - Duration: %.2fms\nTraceback:\n%s",
            request_id, request.method, request.url.path, str(exc), process_time, tb
        )
        
        # Re-raise the exception to be handled by FastAPI's exception handlers
        raise
