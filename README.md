# FastAPI Google OAuth & JWT Authentication Server

A production-ready, secure, and performant API-only authentication server built with FastAPI. It provides a robust solution for adding "Sign in with Google" functionality to your applications, utilizing JWT for stateless session management with access and refresh tokens.

## Key Features

*   **Google OAuth 2.0 Login:** Securely authenticate users via their Google accounts.
*   **JWT Authentication:** Issues short-lived JWT Access Tokens and long-lived JWT Refresh Tokens.
*   **Stateless Sessions:** Uses JWT, requiring no server-side session storage for user authentication status.
*   **Refresh Token Rotation:** Enhances security by issuing a new refresh token each time one is used.
*   **HttpOnly Cookie Security:** Refresh tokens are stored securely in `HttpOnly`, `Secure` (in prod), `SameSite=Strict` cookies, mitigating XSS risks.
*   **CORS Configuration:** Properly configured CORS middleware to allow requests from your specified frontend origin.
*   **Configuration via Environment:** All settings managed through environment variables (`.env` file) using Pydantic Settings for validation.
*   **Structured Logging:** Middleware provides detailed request/response logging, with configurable levels via `DEBUG` flag. Log output directed to console and rotating files (`logs/`).
*   **Modular Design:** Clear separation of concerns using Controllers (business logic) and API Routers (endpoints).
*   **Type Hinting & Async:** Leverages Python type hints and FastAPI's async capabilities for performance and maintainability.
*   **Health Check Endpoint:** `/health` endpoint for monitoring.
*   **Conditional Test Endpoint:** `/api/v1/test` endpoint available only when `DEBUG=True`.
*   **Production Ready:** Includes considerations for security, configuration, and deployment.
*   **Modern Tooling:** Uses `uv` or `pip` for dependency management, `ruff`, `pylint`, `yapf` for code quality, and `pytest` for testing.

## Technology Stack

*   **Framework:** FastAPI
*   **Authentication:** Authlib (for Google OAuth), Python-JOSE (for JWT handling)
*   **Configuration:** Pydantic Settings, python-dotenv
*   **Web Server (Dev):** Uvicorn
*   **Password Hashing (if extended):** Passlib, bcrypt
*   **Code Quality:** Ruff, Pylint, YAPF, MyPy
*   **Testing:** Pytest
*   **Dependency Management:** uv / pip

## Project Structure

```
/
├── app/
│   ├── __init__.py
│   ├── controllers/           # Business logic (auth, health, root)
│   │   └── ...
│   ├── core/                  # Core configuration (settings, logging)
│   │   └── ...
│   ├── endpoints/             # API endpoints (v1 -> auth, health, root, test)
│   │   └── ...
│   ├── middlewares/           # Middleware components (logging)
│   │   └── ...
│   └── models/                # Pydantic data models (user, token)
│       └── ...
├── tests/
│   ├── __init__.py
│   ├── integration/
│   │   └── test_auth_flow.py  # Integration test script
│   └── unit/                  # (Placeholder for unit tests)
├── templates/
│   └── login.html             # HTML template for the root test page
├── logs/                      # Log files (created automatically)
│   └── ...
├── .env                       # Local environment variables (DO NOT COMMIT)
├── sample.env                 # Example environment variables template (gitignored by default)
├── main.py                    # FastAPI app creation and middleware setup
├── run.py                     # Server startup script
├── setup.py                   # Package setup (optional, for distribution)
├── pyproject.toml             # Project config (dependencies, linting tools)
├── uv.lock                    # Dependency lock file (if using uv)
├── .gitignore                 # Git ignore configuration
├── .pylintrc                  # Pylint configuration file
├── .style.yapf                # YAPF configuration file
├── .pre-commit-config.yaml    # Pre-commit hook configuration
├── .python-version            # Python version specifier
├── README.md                  # This file
└── ... (Other project/checklist files)
```

## Core Concepts Explained

*   **OAuth 2.0 (Authorization Code Flow):** This server uses the standard flow where the user is redirected to Google to approve access. Google then redirects back with an authorization `code`. The server exchanges this `code` (along with its client secret) for Google's tokens and user info.
*   **JWT (JSON Web Tokens):** Compact, URL-safe tokens used to represent claims between parties. This server uses them for:
    *   **Access Tokens:** Short-lived, contain user info, grant access to protected API resources. Sent in `Authorization: Bearer <token>` header.
    *   **Refresh Tokens:** Long-lived, contain minimal info, used solely to obtain new access tokens without requiring re-login. Stored securely.
*   **HttpOnly Cookies:** The refresh token is stored in a cookie flagged `HttpOnly`. This prevents client-side JavaScript from accessing it, significantly reducing the risk of token theft via Cross-Site Scripting (XSS).
*   **Secure Cookies:** In production (non-debug, HTTPS), the cookie should also be flagged `Secure`, ensuring it's only sent over HTTPS connections. (*Note: This requires a code modification to enable based on environment*).
*   **SameSite=Strict Cookies:** This flag prevents the browser from sending the cookie along with cross-site requests, providing strong protection against Cross-Site Request Forgery (CSRF) attacks targeting the refresh token endpoint.
*   **Refresh Token Rotation:** Each time a refresh token is successfully used, the server invalidates it (implicitly, by not storing it) and issues both a new access token *and* a new refresh token. This limits the time window an exposed refresh token can be used.
*   **CORS (Cross-Origin Resource Sharing):** A browser security feature. This server uses FastAPI's `CORSMiddleware` configured via the `CORS_ORIGIN` environment variable to explicitly allow requests from your frontend's specific origin, including requests that need to send credentials (like the refresh token cookie).

## API Endpoints (v1 - Default Prefix: `/api/v1`)

| Method | Path              | Requires Auth | Description                                                                                                                                                              | Response                                                                 |
| :----- | :---------------- | :------------ | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------- |
| `GET`  | `/health`         | No            | Simple health check endpoint.                                                                                                                                            | `{"status": "healthy"}`                                                  |
| `GET`  | `/auth/login`     | No            | Initiates the Google OAuth login flow by redirecting the user to Google's consent screen.                                                                                  | `307 Temporary Redirect` to Google                                       |
| `GET`  | `/auth/callback`  | No            | Handles the redirect back from Google. Exchanges code for user info, generates tokens, sets refresh token cookie, redirects to `FRONTEND_CALLBACK_URL_BASE`.              | `307 Temporary Redirect` to Frontend (`#access_token=` or `?error=`) |
| `POST` | `/auth/refresh`   | No (Cookie)   | Expects `refresh_token` via `HttpOnly` cookie. Validates it, issues a new access token (JSON) and a new rotated refresh token (cookie). Requires correct `CORS_ORIGIN`. | `{ "access_token": "...", "token_type": "bearer" }` or `401` Error     |
| `GET`  | `/auth/me`        | Access Token  | Requires `Authorization: Bearer <access_token>`. Validates token and returns the user information embedded within it.                                                    | `{ "email": "...", "name": "...", ... }` or `401` Error                   |
| `GET`  | `/auth/logout`    | No (Cookie)   | Clears the `refresh_token` cookie by setting its expiry to the past. Requires `credentials: 'include'` from frontend.                                                    | `200 OK` (typically with no body)                                        |
| `GET`  | `/` (Root)        | No            | Serves a simple HTML test login page (`templates/login.html`) via Jinja2. Includes JS to handle callback redirect.                                                        | `text/html`                                                              |
| `GET`  | `/test/`          | No            | **(Only if `DEBUG=True`)** Serves a different, minimal HTML test page with login/refresh buttons.                                                                        | `text/html`                                                              |
| `GET`  | `/docs`           | No            | Serves Swagger UI documentation for the API.                                                                                                                              | `text/html`                                                              |
| `GET`  | `/redoc`          | No            | Serves ReDoc documentation for the API.                                                                                                                                  | `text/html`                                                              |
| `GET`  | `/openapi.json`   | No            | Serves the OpenAPI schema definition in JSON format.                                                                                                                     | `application/json`                                                       |

*(Note: Endpoint paths are prefixed with `/api/v1` by default, configured via `API_V1_STR`)*

## Environment Variables

Configuration is loaded from environment variables, typically defined in a `.env` file in the project root (see `sample.env` for a template).

| Variable                     | Required | Default (`config.py`)     | Description                                                                                                                                                              | Example (`.env`)                                            |
| :--------------------------- | :------- | :------------------------ | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------------------------------------------- |
| `GOOGLE_CLIENT_ID`           | Yes      | -                         | Your Google Cloud OAuth 2.0 Client ID.                                                                                                                                   | `your-id.apps.googleusercontent.com`                        |
| `GOOGLE_CLIENT_SECRET`       | Yes      | -                         | Your Google Cloud OAuth 2.0 Client Secret.                                                                                                                               | `GOCSPX-YourSecretValue`                                    |
| `SESSION_SECRET`             | Yes      | -                         | Strong random string (e.g., `openssl rand -hex 32`) used to sign/encrypt the OAuth state session cookie. **Keep Private!**                                               | `a_very_long_random_hex_string_for_session`                 |
| `JWT_SECRET`                 | Yes      | -                         | Strong random string (e.g., `openssl rand -hex 32`) used to sign/verify JWT access and refresh tokens. **Keep Private!**                                                  | `another_very_long_random_hex_string_for_jwt`               |
| `CORS_ORIGIN`                | Yes      | `"http://localhost:3000"` | The **exact** origin of your frontend application (scheme + hostname + port). Crucial for allowing frontend requests (especially refresh) and cookie handling by the browser. | `https://www.yourfrontend.com`                              |
| `FRONTEND_CALLBACK_URL_BASE` | Yes      | `"/"`                     | The **exact** URL in your frontend where users are redirected after login/callback processing. Backend appends `#access_token=...` or `?error=...`.                  | `https://www.yourfrontend.com/auth/callback`                |
| `DEBUG`                      | No       | `False`                   | Set to `True` to enable the `/api/v1/test` endpoint and set logging level to DEBUG. **Should be `False` in production.**                                                | `True`                                                      |
| `ACCESS_TOKEN_EXPIRE_MINUTES`| No       | `60`                      | Lifetime of JWT access tokens in minutes.                                                                                                                                | `30`                                                        |
| `REFRESH_TOKEN_EXPIRE_DAYS`  | No       | `7`                       | Lifetime of JWT refresh tokens (and their cookie) in days.                                                                                                               | `30`                                                        |
| `API_V1_STR`                 | No       | `"/api/v1"`               | Base path prefix for all version 1 API endpoints.                                                                                                                        | `"/api/v1"`                                                 |
| `PROJECT_NAME`               | No       | `"FastAPI Auth Server"`   | Name displayed in the title of the OpenAPI documentation pages.                                                                                                          | `"My App Auth Service"`                                     |

## Setup and Installation

### Prerequisites

*   Python 3.11+ (as defined in `pyproject.toml`)
*   `pip` or `uv` (for dependency installation)
*   Google Cloud Project with OAuth 2.0 Credentials configured

### Setting Up Google OAuth Credentials

1.  Go to the [Google Cloud Console](https://console.cloud.google.com/).
2.  Create a new project or select an existing one.
3.  Navigate to "APIs & Services" > "Credentials".
4.  Click "Create Credentials" > "OAuth client ID".
5.  Set the application type to "Web application".
6.  Add **Authorized JavaScript origins**: Enter the origin(s) of your frontend application (e.g., `http://localhost:3000` for local development, `https://www.yourfrontend.com` for production).
7.  Add **Authorized redirect URIs**: Enter the callback URL for *this backend API*. This should be `http://<your-backend-host-and-port>/api/v1/auth/callback` (e.g., `http://localhost:8000/api/v1/auth/callback` for local development, `https://api.yourapp.com/api/v1/auth/callback` for production).
8.  Click "Create". Note your **Client ID** and **Client Secret**.

### Local Installation Steps

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/yourusername/fastapi-google-oauth-example.git # Replace with your repo URL
    cd fastapi-google-oauth-example
    ```
2.  **Create and activate a virtual environment:**
    ```sh
    python -m venv .venv
    source .venv/bin/activate  # On Windows: .venv\Scripts\activate
    ```
3.  **Install dependencies:**
    *   **Using `uv` (Recommended & Faster):**
        ```sh
        pip install uv
        uv pip install -e . # Installs in editable mode based on pyproject.toml
        # Or, if uv.lock is up-to-date: uv pip sync
        ```
    *   **Using `pip`:**
        ```sh
        pip install -e . # Installs in editable mode based on pyproject.toml
        ```
4.  **Configure Environment:**
    *   Copy `sample.env` to `.env`: `cp sample.env .env`
    *   Edit the `.env` file and fill in your actual `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and generate strong unique values for `SESSION_SECRET` and `JWT_SECRET`.
    *   Adjust `CORS_ORIGIN` and `FRONTEND_CALLBACK_URL_BASE` according to your frontend setup (even for local development).
    *   Set `DEBUG=True` for local development.
5.  **Run the Application:**
    *   **With auto-reload (recommended for development):**
        ```sh
        uvicorn main:app --reload --host 0.0.0.0 --port 8000
        ```
    *   **Using the run script:**
        ```sh
        python run.py
        ```
6.  **Access:**
    *   **Root Test Page:** http://localhost:8000/ (if `FRONTEND_CALLBACK_URL_BASE` points here or is the default `/`)
    *   **API Docs (Swagger):** http://localhost:8000/api/v1/docs
    *   **API Docs (ReDoc):** http://localhost:8000/api/v1/redoc

## Authentication Flow Deep Dive

This describes the interaction between the User, Frontend, Backend (this API), and Google:

1.  **User Action:** User clicks a "Login with Google" button in the Frontend.
2.  **Frontend Action:** Redirects the user's browser to the Backend's `GET /api/v1/auth/login` endpoint.
3.  **Backend (`/login`):** Generates a unique `state` parameter (stored in the session cookie), constructs the Google OAuth authorization URL, and redirects the User's browser to Google.
4.  **Google Interaction:** User logs into Google (if not already) and approves the application's request for access (scopes: `openid email profile`).
5.  **Google Action:** Redirects the User's browser back to the Backend's `GET /api/v1/auth/callback` URI (specified during Google credential setup), including an authorization `code` and the original `state` parameter.
6.  **Backend (`/callback`):
    *   Receives the request from the browser.
    *   Validates the received `state` against the one in the session cookie (CSRF protection).
    *   Exchanges the `code` with Google (using its `client_id` and `client_secret`) for Google's access/ID tokens and user information.
    *   Extracts user details (email, name, picture, etc.).
    *   Generates a short-lived JWT **Access Token** containing user info.
    *   Generates a long-lived JWT **Refresh Token** containing minimal info.
    *   Sets the **Refresh Token** in an `HttpOnly`, `Secure` (if applicable), `SameSite=Strict` cookie in the response headers.
    *   Redirects the User's browser to the `FRONTEND_CALLBACK_URL_BASE` specified in the environment, appending the **Access Token** in the URL fragment (`#access_token=...`).
7.  **Frontend Action (at Callback URL):
    *   The page loads. Client-side JavaScript checks `window.location.hash`.
    *   Extracts the `access_token` from the hash.
    *   Stores the `access_token` securely (e.g., in memory).
    *   Clears the hash from the URL bar (`history.replaceState`).
    *   Redirects the user to the main authenticated part of the application.
8.  **User Action (Authenticated):** User navigates the Frontend application.
9.  **Frontend Action (API Call):** Makes a request to a protected Backend endpoint (e.g., `GET /api/v1/auth/me`), including the stored `access_token` in the `Authorization: Bearer <token>` header.
10. **Backend (Protected Endpoint):** Validates the `Authorization` header, decodes the access token, verifies its signature and expiry, and processes the request if valid. Returns `401 Unauthorized` if the token is missing, invalid, or expired.

*(See "Handling Token Expiry & Refreshing Tokens" section in the Frontend Integration Guide below for the refresh flow)*

## Frontend Integration Guide

Follow these steps to connect your separate frontend application:

1.  **Configure Backend `.env`:** Ensure the backend administrator sets:
    *   `CORS_ORIGIN` to your frontend's exact origin (e.g., `https://your-app.com`).
    *   `FRONTEND_CALLBACK_URL_BASE` to your frontend's specific callback route (e.g., `https://your-app.com/auth/callback`).
2.  **Initiate Login:** Add a button/link that redirects the user to `GET <your-backend-url>/api/v1/auth/login`.
3.  **Handle Callback Route:** Create the route specified in `FRONTEND_CALLBACK_URL_BASE`. In its client-side code:
    *   On load, check `window.location.hash` for `#access_token=...`.
    *   If found: Store the token (in-memory recommended), clear the hash (`history.replaceState`), redirect to authenticated area.
    *   If not found: Check `window.location.search` for `?error=...&message=...`. Display the error, clear query params.
4.  **Make Authenticated API Calls:** Include the stored access token in the `Authorization: Bearer <token>` header for requests to protected backend endpoints.
5.  **Handle Token Expiry & Refresh:**
    *   Wrap your API calls or use an interceptor to detect `401 Unauthorized` responses.
    *   On 401, attempt to refresh by making a `POST` request to `<your-backend-url>/api/v1/auth/refresh`.
    *   **Crucially:** This refresh request *must* include `credentials: 'include'` (in `fetch` or `axios` config) for the browser to send the `HttpOnly` refresh token cookie.
    *   **If refresh succeeds (200 OK):** Parse the JSON response (`{ "access_token": "..." }`), store the new access token, and automatically retry the original failed API request.
    *   **If refresh fails (e.g., 401):** The refresh token is likely invalid/expired. Clear any stored access token and redirect the user to the login page.
6.  **Implement Logout:**
    *   Call `GET <your-backend-url>/api/v1/auth/logout`, ensuring you include `credentials: 'include'`.
    *   Clear the locally stored access token in your frontend state.
    *   Redirect the user to a public page (e.g., login screen).

## Security Considerations

*   **HTTPS Enforcement:** **ALWAYS** run this server behind HTTPS in production. Configure your reverse proxy (Nginx, Traefik, etc.) to handle TLS termination. This protects tokens and user data in transit.
*   **Secret Management:** Generate strong, unique secrets for `SESSION_SECRET` and `JWT_SECRET`. Store them securely using environment variables or a secrets management system. **NEVER** commit secrets to Git.
*   **Cookie Security:**
    *   `HttpOnly` prevents JavaScript access (XSS mitigation).
    *   `SameSite=Strict` provides strong CSRF protection for the refresh token.
    *   `Secure` flag (should be enabled for production via code change) ensures the cookie is only sent over HTTPS.
*   **CORS Configuration:** **NEVER** use wildcard (`*`) for `CORS_ORIGIN` in production. Always specify the exact origin of your trusted frontend application.
*   **Token Lifetimes:** Keep `ACCESS_TOKEN_EXPIRE_MINUTES` relatively short (e.g., 15-60 minutes). `REFRESH_TOKEN_EXPIRE_DAYS` can be longer (e.g., 7-30 days) but consider the security implications. Shorter lifetimes reduce the impact of token theft.
*   **Refresh Token Revocation:** (Recommended Future Work) Implement a server-side revocation list for refresh tokens (e.g., using Redis) to allow immediate invalidation upon logout or suspected compromise.
*   **Input Validation:** Rely on FastAPI's Pydantic integration for automatic request validation.
*   **Dependency Updates:** Keep dependencies updated to patch security vulnerabilities. Regularly run `uv pip list --outdated` or `pip list --outdated` and update cautiously.
*   **Rate Limiting:** Consider adding rate limiting middleware (e.g., `slowapi`) to protect against brute-force attacks on login or refresh endpoints, especially if extending with password auth.
*   **`DEBUG=False`:** Ensure `DEBUG` is set to `False` in production environments.

## Testing

*   **Integration Tests:** Run the existing integration tests using `pytest`:
    ```sh
    # Ensure the server is running locally and .env is configured
    pytest tests/integration/test_auth_flow.py
    ```
*   **Unit Tests:** (Recommended Future Work) Add unit tests for controllers and utility functions using `pytest` and `unittest.mock`.

## Code Quality

This project uses the following tools configured in `pyproject.toml`, `.pylintrc`, and `.style.yapf`:

*   **Ruff:** Fast linting and formatting.
    *   Check: `ruff check .`
    *   Format: `ruff format .`
*   **Pylint:** Static code analysis.
    *   Run: `pylint app/**/*.py main.py run.py` (adjust paths as needed)
*   **YAPF:** Code formatting (alternative/complementary to Ruff).
    *   Run: `yapf --recursive --in-place .`
*   **MyPy:** Static type checking.
    *   Run: `mypy .`

Pre-commit hooks are configured in `.pre-commit-config.yaml` to run these checks automatically before commits. Install with `pre-commit install`.

## Deployment

Follow these steps for a production deployment:

1.  **Prepare Environment:**
    *   Ensure Python 3.11+ is available.
    *   Create a `.env` file on the server with **production values**:
        *   `DEBUG=False`
        *   Correct Google Credentials.
        *   **Strong, unique production secrets.**
        *   Correct production `CORS_ORIGIN` and `FRONTEND_CALLBACK_URL_BASE`.
2.  **Install Dependencies:** Use the lock file for deterministic installs:
    ```sh
    uv pip sync # Or pip install -r requirements.txt --no-deps if using pip
    ```
3.  **Run with Production ASGI Server:** Use Uvicorn or Hypercorn with multiple workers.
    ```sh
    uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4 # Adjust workers based on CPU cores
    ```
    Consider running this as a systemd service or using a process manager.
4.  **Reverse Proxy (Required):** Place the application behind a reverse proxy like Nginx or Traefik. Configure the proxy to:
    *   Handle **HTTPS termination** (manage SSL/TLS certificates, e.g., via Let's Encrypt).
    *   Forward requests to the Uvicorn process (e.g., `proxy_pass http://127.0.0.1:8000;`).
    *   Set necessary headers like `X-Forwarded-For` and `X-Forwarded-Proto`.
5.  **Logging:** Ensure log rotation is handled by the system (e.g., `logrotate`) or the deployment platform to prevent log files from consuming excessive disk space.
6.  **Monitoring:** Monitor the `/health` endpoint and application logs for errors and performance.

*(Consider containerizing with Docker for easier deployment consistency - See Future Work)*

## Future Work / Improvements

*   Implement Refresh Token Revocation List.
*   Add Persistent User Storage (Database).
*   Add comprehensive Unit Tests.
*   Containerize with Docker/Docker Compose.
*   Implement `secure=True` for cookies in production.
*   Add more robust security headers.
*   Consider adding other OAuth providers.
*   Consider adding password-based authentication alongside OAuth.
