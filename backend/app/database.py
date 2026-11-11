"""
FraudTrace AI — Database Configuration
=======================================
This module configures the database connection using SQLAlchemy 2.x.

Features:
- Resolves the SQLite database path independently of the current working directory.
- Enables SQLite foreign-key constraint enforcement (PRAGMA foreign_keys = ON)
  on every connection via a SQLAlchemy event listener.
- Allows overriding via the `DATABASE_URL` environment variable.
- Provides `SessionLocal` for transactional database sessions.
- Provides `get_db()` FastAPI dependency with guaranteed session closure.
- Provides `init_db()` to safely create tables without wiping existing data.
"""

import os
from collections.abc import Generator
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# Load environment variables from .env if present
load_dotenv()

# Anchor all paths to the `backend/` directory so CWD never causes path errors
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_DB_FILE = DATA_DIR / "fraudtrace.db"
# Use forward slashes for SQLite URI path compatibility across OSes
DEFAULT_DATABASE_URL = f"sqlite:///{DEFAULT_DB_FILE.as_posix()}"

# Read DATABASE_URL or fall back to local SQLite file
raw_db_url = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)

# Normalize relative SQLite URLs so they always resolve against BASE_DIR
if (
    raw_db_url.startswith("sqlite:///")
    and not raw_db_url.startswith("sqlite:////")
    and not (len(raw_db_url) > 11 and raw_db_url[10] == ":")
):
    # Relative path like sqlite:///./data/fraudtrace.db
    rel_path = raw_db_url[len("sqlite:///") :]
    resolved_path = (BASE_DIR / rel_path).resolve()
    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    DATABASE_URL = f"sqlite:///{resolved_path.as_posix()}"
else:
    DATABASE_URL = raw_db_url

# SQLite multi-thread safety setting (FastAPI handles concurrent requests across threads)
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

# Create SQLAlchemy engine
engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    echo=False,  # Set to True for verbose SQL logging during debug
)


# SQLite Foreign Key Enforcement:
# SQLite does NOT enforce foreign keys by default.
# The PRAGMA foreign_keys = ON must be issued for each database connection.
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):  # noqa: ANN001
    """Ensure SQLite foreign key enforcement is turned on for every new connection."""
    if DATABASE_URL.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


# Create sessionmaker for spawning independent database sessions
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


class Base(DeclarativeBase):
    """
    SQLAlchemy 2.x Declarative Base class.
    All ORM models inherit from this base class.
    """
    pass


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields an active database session
    and ensures it is properly closed when the request finishes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """
    Safely creates all tables defined in Base.metadata.
    Does NOT overwrite or drop existing tables or data.
    """
    # Import models here so that Base.metadata has registered them
    import app.models  # noqa: F401

    Base.metadata.create_all(bind=engine)
