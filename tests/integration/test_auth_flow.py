#!/usr/bin/env python
"""
Test script for the FastAPI Google OAuth authentication flow.

This script tests the authentication flow by making requests to the auth endpoints
and validating the responses. It's a simple integration test that helps verify
the basic functionality of the authentication system.

Usage:
    python test_auth_flow.py

Note: This requires the server to be running locally on port 8000.

Author: James Fincher
Copyright: 2025
License: Private - All Rights Reserved
"""

import json
import sys
import webbrowser
from typing import Dict, Optional
from urllib.parse import urlparse

import requests

# Configuration
BASE_URL = "http://localhost:8000"
AUTH_BASE_URL = f"{BASE_URL}/api/v1/auth"
ENDPOINTS: Dict[str, str] = {
    "login": f"{AUTH_BASE_URL}/login",
    "callback": f"{AUTH_BASE_URL}/callback",
    "refresh": f"{AUTH_BASE_URL}/refresh",
    "me": f"{AUTH_BASE_URL}/me",
    "logout": f"{AUTH_BASE_URL}/logout",
}


def print_header(message: str) -> None:
    """
    Print a formatted header message.
    
    Args:
        message: The message to display in the header
    """
    print("\n" + "=" * 80)
    print(f" {message}")
    print("=" * 80)


def print_response(response: requests.Response) -> None:
    """
    Print a formatted response.
    
    Displays the status code, headers, and body of the HTTP response
    in a readable format. Attempts to parse JSON responses.
    
    Args:
        response: The HTTP response object to display
    """
    print(f"Status Code: {response.status_code}")
    print("Headers:")
    for key, value in response.headers.items():
        print(f"  {key}: {value}")
    
    print("Body:")
    try:
        print(json.dumps(response.json(), indent=2))
    except json.JSONDecodeError:
        print(response.text)


def test_server_health() -> bool:
    """
    Test that the server is running and healthy.
    
    Makes a request to the health endpoint and verifies that
    the server is responding with a 200 status code.
    
    Returns:
        bool: True if the server is healthy, False otherwise
    """
    print_header("Testing Server Health")
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=10)
        print_response(response)
        assert response.status_code == 200, "Server is not healthy"
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False


def manual_oauth_flow() -> Optional[str]:
    """
    Test the OAuth flow manually with user interaction.
    
    Opens the login URL in the default browser and guides the user
    through the authentication process. The user needs to paste
    the callback URL after successful authentication.
    
    Returns:
        Optional[str]: The access token if successful, None otherwise
    """
    print_header("Testing OAuth Flow (Manual)")
    print("This test requires manual interaction.")
    print("1. Opening the login URL in your browser")
    print("2. Complete the Google OAuth flow")
    print("3. After successful authentication, you'll be redirected to a page "
          "with the access token")
    print("4. Copy the entire URL from your browser address bar and paste it here")
    
    # Open the login URL in the default browser
    webbrowser.open(ENDPOINTS["login"])
    
    # Wait for user to complete the flow and paste the callback URL
    callback_url = input("\nPaste the callback URL here: ")
    
    # Parse the URL to extract the access token
    parsed_url = urlparse(callback_url)
    
    # If we got redirected to the callback endpoint, the response will be in JSON format in the page
    if "/callback" in parsed_url.path:
        print("\nCallback URL detected. Please copy and paste the JSON response from the page:")
        json_response = input("Paste the JSON response here: ")
        try:
            data = json.loads(json_response)
            access_token = data.get("access_token")
            if access_token:
                print(f"Successfully extracted access token: {access_token[:10]}...")
                return access_token
            else:
                print("No access token found in the response")
                return None
        except json.JSONDecodeError:
            print("Failed to parse JSON response")
            return None
    else:
        print("Invalid callback URL")
        return None


def test_me_endpoint(access_token: Optional[str]) -> None:
    """
    Test the /me endpoint with the provided access token.
    
    Makes an authenticated request to the /me endpoint to retrieve
    user information using the provided access token.
    
    Args:
        access_token: The OAuth access token to use for authentication
    """
    print_header("Testing /me Endpoint")
    
    if not access_token:
        print("No access token available. Skipping test.")
        return
    
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    
    try:
        response = requests.get(ENDPOINTS["me"], headers=headers, timeout=10)
        print_response(response)
        
        if response.status_code == 200:
            print("✅ Successfully retrieved user information")
        else:
            print("❌ Failed to retrieve user information")
    except Exception as e:
        print(f"Error: {e}")


def test_logout() -> None:
    """
    Test the logout endpoint.
    
    Makes a request to the logout endpoint to verify that
    the user can be successfully logged out.
    """
    print_header("Testing Logout Endpoint")
    
    try:
        response = requests.get(ENDPOINTS["logout"], timeout=10)
        print_response(response)
        
        if response.status_code == 200:
            print("✅ Successfully logged out")
        else:
            print("❌ Failed to logout")
    except Exception as e:
        print(f"Error: {e}")


def main() -> None:
    """
    Main test function.
    
    Orchestrates the execution of all test functions in the correct order.
    Exits with an error code if the server is not running.
    """
    print_header("FastAPI Google OAuth Authentication Flow Test")

    # Check if the server is running
    if not test_server_health():
        print("Server is not running or not healthy. Exiting.")
        sys.exit(1)

    # Test the OAuth flow
    access_token = manual_oauth_flow()

    # Test the /me endpoint
    if access_token:
        test_me_endpoint(access_token)

    # Test the logout endpoint
    test_logout()

    print_header("Test Completed")


if __name__ == "__main__":
    main()
