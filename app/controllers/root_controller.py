"""
FastAPI Google OAuth Example - Root Controller

This module provides root-level endpoints for the application, including
the main landing page that users see when accessing the API's base URL.
The root endpoint serves a simple HTML page with information about the API
and links to documentation.

Author: James Fincher
Copyright: 2025
License: Private - All Rights Reserved
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def root() -> HTMLResponse:
    """
    Root endpoint that displays a simple HTML welcome page.
    
    This endpoint serves as the main landing page for the API,
    providing basic information about the service and links to
    the API documentation. It also includes JavaScript to handle
    the OAuth callback and display user information when authenticated.
    
    Returns:
        HTMLResponse: A simple HTML welcome page with API information
    """
    html_content = """<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>FastAPI Auth Server</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 2em; }
            h1 { color: #4285F4; }
            .info { background: #f5f5f5; padding: 1em; border-radius: 4px; margin-bottom: 1em; }
            .auth-section { margin-top: 2em; }
            .user-info { background: #e8f5e9; padding: 1em; border-radius: 4px; display: none; }
            .error-info { background: #ffebee; padding: 1em; border-radius: 4px; display: none; }
            .debug-info { background: #e3f2fd; padding: 1em; border-radius: 4px; margin-top: 1em; font-family: monospace; white-space: pre-wrap; }
            button { background: #4285F4; color: white; border: none; padding: 10px 15px; border-radius: 4px; cursor: pointer; }
            button:hover { background: #3367d6; }
            .logout-btn { background: #f44336; }
            .logout-btn:hover { background: #d32f2f; }
            .user-image { width: 50px; height: 50px; border-radius: 50%; margin-right: 10px; }
            .user-header { display: flex; align-items: center; }
            pre { background: #f5f5f5; padding: 1em; border-radius: 4px; overflow-x: auto; max-height: 300px; overflow-y: auto; }
        </style>
    </head>
    <body>
        <h1>FastAPI Auth Server API</h1>
        <div class="info">
            <p>Welcome to the FastAPI Auth Server API.</p>
            <p>This API provides authentication endpoints using Google OAuth.</p>
            <p>Visit <a href="/api/v1/docs">/api/v1/docs</a> to see the API documentation.</p>
        </div>
        
        <div class="auth-section">
            <div id="login-section">
                <h2>Authentication Test</h2>
                <p>Click the button below to test the Google OAuth authentication flow:</p>
                <button id="login-btn" onclick="login()">Login with Google</button>
            </div>
            
            <div id="user-info" class="user-info">
                <div class="user-header">
                    <img id="user-image" class="user-image" src="" alt="User profile">
                    <h2>Welcome, <span id="user-name">User</span>!</h2>
                </div>
                <p>Email: <span id="user-email"></span></p>
                <p>Authentication Status: <strong>Authenticated</strong></p>
                <p>Access Token: <span id="access-token-preview"></span></p>
                <button class="logout-btn" onclick="logout()">Logout</button>
                <div>
                    <h3>Token Details:</h3>
                    <pre id="token-details"></pre>
                </div>
            </div>
            
            <div id="error-info" class="error-info">
                <h2>Authentication Error</h2>
                <p id="error-message"></p>
                <button onclick="login()">Try Again</button>
            </div>
            
            <div id="debug-info" class="debug-info">
                <h3>Debug Information:</h3>
                <div id="debug-content"></div>
            </div>
        </div>
        
        <script>
            // Debug function to log information
            function debugLog(message, data) {
                const debugContent = document.getElementById("debug-content");
                const timestamp = new Date().toISOString();
                let logMessage = `[${timestamp}] ${message}\\n`;
                
                if (data) {
                    if (typeof data === "object") {
                        logMessage += JSON.stringify(data, null, 2) + "\\n";
                    } else {
                        logMessage += data + "\\n";
                    }
                }
                
                debugContent.innerHTML += logMessage + "\\n";
                console.log(message, data);
            }
            
            // Function to decode JWT token
            function decodeJWT(token) {
                try {
                    const parts = token.split(".");
                    if (parts.length !== 3) {
                        return null;
                    }
                    
                    // Base64 decode and parse JSON
                    const payload = JSON.parse(atob(parts[1]));
                    return payload;
                } catch (e) {
                    debugLog("Error decoding JWT:", e.message);
                    return null;
                }
            }
            
            // Check for access token in URL fragment or error in query parameters
            document.addEventListener("DOMContentLoaded", function() {
                debugLog("Page loaded, checking for authentication data");
                
                // Parse URL fragment for access token
                const hash = window.location.hash.substring(1);
                debugLog("URL hash:", hash);
                
                const params = new URLSearchParams(hash);
                const accessToken = params.get("access_token");
                debugLog("Access token from hash:", accessToken ? "Found (truncated): " + accessToken.substring(0, 10) + "..." : "Not found");
                
                // Parse query parameters for error
                const queryParams = new URLSearchParams(window.location.search);
                const error = queryParams.get("error");
                const errorMessage = queryParams.get("message");
                debugLog("Error from query:", error);
                debugLog("Error message:", errorMessage);
                
                if (accessToken) {
                    debugLog("Access token found, storing in sessionStorage");
                    // Store token in sessionStorage
                    sessionStorage.setItem("access_token", accessToken);
                    
                    // Clean up URL without reloading the page
                    history.replaceState(null, null, window.location.pathname);
                    debugLog("URL cleaned up");
                    
                    // Show user info
                    fetchUserInfo(accessToken);
                } else if (error) {
                    debugLog("Error found in query parameters");
                    // Show error message
                    document.getElementById("login-section").style.display = "none";
                    document.getElementById("error-info").style.display = "block";
                    document.getElementById("error-message").textContent = errorMessage || "Authentication failed";
                    
                    // Clean up URL without reloading the page
                    history.replaceState(null, null, window.location.pathname);
                    debugLog("URL cleaned up");
                } else {
                    debugLog("No token or error found, checking sessionStorage");
                    // Check if we have a stored token
                    const storedToken = sessionStorage.getItem("access_token");
                    debugLog("Stored token:", storedToken ? "Found (truncated): " + storedToken.substring(0, 10) + "..." : "Not found");
                    
                    if (storedToken) {
                        fetchUserInfo(storedToken);
                    } else {
                        debugLog("No stored token found, showing login section");
                    }
                }
            });
            
            // Function to fetch user info using the access token
            function fetchUserInfo(token) {
                debugLog("Fetching user info with token");
                fetch("/api/v1/auth/me", {
                    headers: {
                        "Authorization": `Bearer ${token}`
                    }
                })
                .then(response => {
                    debugLog("User info response status:", response.status);
                    if (!response.ok) {
                        throw new Error("Failed to fetch user info");
                    }
                    return response.json();
                })
                .then(data => {
                    debugLog("User info received:", data);
                    
                    // Display user info
                    document.getElementById("user-name").textContent = data.name || "User";
                    document.getElementById("user-email").textContent = data.email;
                    
                    if (data.picture) {
                        document.getElementById("user-image").src = data.picture;
                    } else {
                        document.getElementById("user-image").src = "https://ui-avatars.com/api/?name=" + encodeURIComponent(data.name || data.email);
                    }
                    
                    // Show token preview (first 10 chars)
                    const tokenPreview = token.substring(0, 10) + "...";
                    document.getElementById("access-token-preview").textContent = tokenPreview;
                    
                    // Decode and display token details
                    const decodedToken = decodeJWT(token);
                    if (decodedToken) {
                        document.getElementById("token-details").textContent = JSON.stringify(decodedToken, null, 2);
                    } else {
                        document.getElementById("token-details").textContent = "Could not decode token";
                    }
                    
                    // Show user info section, hide login section
                    document.getElementById("login-section").style.display = "none";
                    document.getElementById("user-info").style.display = "block";
                    debugLog("User info displayed");
                })
                .catch(error => {
                    debugLog("Error fetching user info:", error.message);
                    // Token might be invalid, clear it
                    sessionStorage.removeItem("access_token");
                    debugLog("Token cleared from sessionStorage");
                    
                    // Show login section
                    document.getElementById("login-section").style.display = "block";
                    document.getElementById("user-info").style.display = "none";
                    
                    // Show error
                    document.getElementById("error-info").style.display = "block";
                    document.getElementById("error-message").textContent = "Authentication failed: " + error.message;
                });
            }
            
            // Function to initiate login
            function login() {
                debugLog("Initiating login");
                window.location.href = "/api/v1/auth/login";
            }
            
            // Function to logout
            function logout() {
                debugLog("Logging out");
                // Clear token from sessionStorage
                sessionStorage.removeItem("access_token");
                debugLog("Token cleared from sessionStorage");
                
                // Call logout endpoint to clear refresh token cookie
                fetch("/api/v1/auth/logout")
                .then(response => {
                    debugLog("Logout response status:", response.status);
                    // Show login section, hide user info
                    document.getElementById("login-section").style.display = "block";
                    document.getElementById("user-info").style.display = "none";
                    document.getElementById("error-info").style.display = "none";
                })
                .catch(error => {
                    debugLog("Error during logout:", error.message);
                });
            }
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)
