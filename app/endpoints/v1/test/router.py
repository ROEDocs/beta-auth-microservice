"""
FastAPI Google OAuth Example - Test Router

This module defines test routes that are only available in debug mode.
These endpoints provide utilities for testing authentication flows and
other functionality during development.

Author: James Fincher
Copyright: 2025
License: Private - All Rights Reserved
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

# HTML template service (View)
def get_test_page_html() -> str:
    """
    Generate HTML for the test login page.
    
    This function returns a simple HTML page with:
    - A Google sign-in button
    - A token refresh test function
    - Basic styling for development testing
    
    Returns:
        str: HTML content for the test page
    """
    return """<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Test Login</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 400px; margin: 40px auto; padding: 2em; background: #f9f9f9; border-radius: 8px; box-shadow: 0 2px 8px #0001; }
            h1 { font-size: 1.5em; }
            .btn { display: inline-block; padding: 10px 20px; background: #4285F4; color: #fff; border-radius: 4px; text-decoration: none; font-weight: bold; }
            pre { background: #eee; padding: 1em; border-radius: 4px; overflow-x: auto; }
        </style>
    </head>
    <body>
        <h1>FastAPI Auth Server Test Login</h1>
        <a href="/api/v1/auth/login" class="btn">Sign in with Google</a>
        <hr>
        <p>Test refresh (requires refresh_token cookie to be set after login):</p>
        <button onclick="testRefresh()">Refresh Token</button>
        <pre id="result">Click refresh to test...</pre>
        <script>
            async function testRefresh() {
                const resultEl = document.getElementById("result");
                resultEl.textContent = "Refreshing...";
                try {
                    const response = await fetch("/api/v1/auth/refresh", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                    });
                    const data = await response.json();
                    if (!response.ok) {
                        throw new Error(data.detail || "Refresh failed");
                    }
                    
                    // Display the access token
                    let tokenDisplay = `New Access Token:\\n${JSON.stringify(data, null, 2)}`;
                    
                    // If there's an access_token in the response, try to decode and display it
                    if (data.access_token) {
                        try {
                            // Split the token into parts
                            const tokenParts = data.access_token.split(".");
                            if (tokenParts.length === 3) {
                                // Decode the payload (middle part)
                                const payload = JSON.parse(atob(tokenParts[1]));
                                
                                // Add decoded token information to the display
                                tokenDisplay = tokenDisplay + `\\n\\nDecoded Token Payload:\\n${JSON.stringify(payload, null, 2)}`;
                            }
                        } catch (e) {
                            console.error("Error parsing token:", e);
                        }
                    }
                    
                    resultEl.textContent = tokenDisplay;
                } catch (error) {
                    console.error("Refresh error:", error);
                    resultEl.textContent = `Error: ${error.message}`;
                }
            }
        </script>
    </body>
    </html>"""

# Router definition
router = APIRouter(prefix="/test", tags=["test"])

@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def root_test_login() -> HTMLResponse:
    """
    Serve a simple HTML page for testing the login flow in development.
    
    This endpoint provides a basic UI for testing the authentication flow,
    including a Google sign-in button and a token refresh test function.
    
    Returns:
        HTMLResponse: A HTML page with login UI and token refresh functionality
    """
    return HTMLResponse(content=get_test_page_html())
