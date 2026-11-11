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
    http://127.0.0.1:8000/health                  → core health check response
    http://127.0.0.1:8000/health/database         → database connectivity health check
    http://127.0.0.1:8000/api/v1/transactions     → transaction risk intelligence APIs
    http://127.0.0.1:8000/api/v1/network          → fraud network intelligence APIs
    http://127.0.0.1:8000/docs                    → interactive API documentation (auto-generated)
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database import get_db, init_db
from app.routes.invoices import router as invoices_router
from app.routes.network import router as network_router
from app.routes.transactions import router as transactions_router


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    """
    FastAPI Lifespan Context Manager.
    Runs startup tasks before the application accepts requests,
    and runs shutdown tasks when the application stops.
    """
    # Startup: Safely create database tables if they do not exist yet.
    init_db()
    yield
    # Shutdown: Clean up any standing resources if needed.


# ---------------------------------------------------------------------------
# Application instance
# ---------------------------------------------------------------------------
# FastAPI() creates the core application object.
# The title, version, and description appear in the auto-generated /docs page.

app = FastAPI(
    title="FraudTrace AI",
    version="0.1.0",
    description="Explainable fraud intelligence platform.",
    lifespan=lifespan,
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
# API Routers
# ---------------------------------------------------------------------------
app.include_router(transactions_router)
app.include_router(network_router)
app.include_router(invoices_router)


# ---------------------------------------------------------------------------
# Health Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health_check() -> dict[str, str]:
    """
    Health Check

    Returns a simple OK response to confirm the server is running and reachable.
    Preserved for frontend connection check compatibility.

    Returns:
        dict: A dictionary with a single key "status" set to "ok".
    """
    return {"status": "ok"}


@app.get("/health/database")
def database_health_check(db: Session = Depends(get_db)) -> dict[str, str]:
    """
    Database Health Check

    Verifies active connection to the SQLite database by running a lightweight query.

    Returns:
        dict: {"status": "ok", "database": "connected"} on success.
        HTTP 503 with {"detail": "Database service unavailable"} on failure.
    """
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok", "database": "connected"}
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable",
        )
