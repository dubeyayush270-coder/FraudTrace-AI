"""
FraudTrace AI — Backend Entry Point
====================================
This is the main FastAPI application file.

FastAPI is a modern Python web framework that lets you build APIs quickly.
You define Python functions and "decorate" them with @app.get() or @app.post()
to turn them into HTTP endpoints that the frontend can call.

Run the server with:
    uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

Then visit:
    http://127.0.0.1:8000/health    → health check response
    http://127.0.0.1:8000/docs      → interactive API documentation (auto-generated)
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# ---------------------------------------------------------------------------
# Application instance
# ---------------------------------------------------------------------------
# FastAPI() creates the core application object.
# The title, version, and description appear in the auto-generated /docs page.

app = FastAPI(
    title="FraudTrace AI",
    version="0.1.0",
    description="Explainable fraud intelligence platform.",
)

# ---------------------------------------------------------------------------
# CORS — Cross-Origin Resource Sharing
# ---------------------------------------------------------------------------
# Browsers block JavaScript from calling APIs on a different origin (port)
# unless the server explicitly allows it. Our React frontend runs on
# http://localhost:5173 (Vite's default port) and this backend runs on
# http://localhost:8000 — these are considered different origins.
#
# CORSMiddleware adds the right HTTP headers to tell the browser:
# "It is safe for http://localhost:5173 to read my responses."
#
# We use an explicit origin list (not "*") so we never accidentally
# allow unknown origins in production.

ALLOWED_ORIGINS: list[str] = [
    "http://localhost:5173",  # Vite React development server
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,       # Allow cookies and auth headers
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Accept"],
)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health_check() -> dict[str, str]:
    """
    Health Check

    Returns a simple OK response to confirm the server is running and reachable.

    This endpoint is used by:
    - The frontend to verify the backend is online before making real requests.
    - Monitoring tools to check server availability.

    Returns:
        dict: A dictionary with a single key "status" set to "ok".
    """
    return {"status": "ok"}
