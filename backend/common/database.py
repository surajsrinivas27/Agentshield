"""
Shared Database Infrastructure for AgentShield
Modular Monolith: Shared across Person 1, Person 2, Person 3, and Person 4.

Provides:
- Stable SQLite database location anchored at project root (data/agentshield.db)
- Automatic creation of data directory
- SQLite engine configured with Write-Ahead Logging (WAL) and foreign keys
- BEGIN IMMEDIATE transaction context manager for deadlock-free write concurrency
- Declarative Base for ORM models
- SessionLocal and get_db FastAPI session dependency
"""

import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, Optional, Set
from dotenv import load_dotenv
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
import sqlalchemy.types as types

# Load environment variables if present
load_dotenv()

# Project root resolution: backend/common/database.py -> backend/common -> backend -> root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DEFAULT_DB_FILE = DATA_DIR / "agentshield.db"


def resolve_database_url(raw_url: Optional[str] = None) -> str:
    """
    Resolves the SQLite database URL to an absolute path anchored at the project root.
    Guarantees a stable database location across modules regardless of process working directory.
    Creates the target data directory if it does not exist.
    """
    url = raw_url or os.getenv("DATABASE_URL")
    if not url:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{DEFAULT_DB_FILE.as_posix()}"

    if url.startswith("sqlite:///"):
        path_part = url[len("sqlite:///"):]
        if path_part == ":memory:":
            return url
        # If relative path, resolve against PROJECT_ROOT
        raw_path = Path(path_part)
        if not raw_path.is_absolute():
            resolved = (PROJECT_ROOT / raw_path).resolve()
        else:
            resolved = raw_path.resolve()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{resolved.as_posix()}"

    return url


# Active database URL
DATABASE_URL = resolve_database_url()

# SQLite specific connect arguments
connect_args: Dict[str, Any] = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

# Create the shared engine
engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    future=True,
    pool_pre_ping=True,
)

# Tracks database file paths where WAL mode has been configured once to prevent repeated disk writes
_wal_configured_databases: Set[str] = set()


@event.listens_for(Engine, "connect")
def configure_sqlite_pragmas(dbapi_connection: Any, connection_record: Any) -> None:
    """
    Enforces SQLite WAL mode, foreign keys, synchronous normal, and busy timeout.
    Scoped strictly to SQLite connections.
    Avoids redundant WAL mode PRAGMA executions on every connection.
    """
    module_name = getattr(dbapi_connection.__class__, "__module__", "")
    type_name = getattr(dbapi_connection.__class__, "__name__", "")
    if "sqlite" not in module_name.lower() and "sqlite" not in type_name.lower():
        return

    cursor = dbapi_connection.cursor()
    try:
        # Per-connection requirements: foreign keys, busy timeout, synchronous
        cursor.execute("PRAGMA foreign_keys = ON;")
        cursor.execute("PRAGMA busy_timeout = 30000;")
        cursor.execute("PRAGMA synchronous = NORMAL;")

        # WAL mode is a persistent database header property.
        # Set it once per database file to avoid redundant disk writes on every pooled connection.
        cursor.execute("PRAGMA database_list;")
        rows = cursor.fetchall()
        main_db_path = rows[0][2] if rows else ""
        if main_db_path and main_db_path not in _wal_configured_databases:
            cursor.execute("PRAGMA journal_mode = WAL;")
            _wal_configured_databases.add(main_db_path)
    finally:
        cursor.close()


# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    future=True,
)

# Declarative base for all SQLAlchemy ORM models
Base = declarative_base()


class UTCDateTime(types.TypeDecorator):
    """
    SQLAlchemy TypeDecorator that enforces timezone-aware UTC datetimes.

    Invariants:
    - Rejects naive datetime inputs on bind (raises ValueError).
    - Rejects non-datetime inputs on bind (raises TypeError).
    - Normalizes timezone-aware datetimes to UTC before storing.
    - Restores timezone.utc on retrieved datetimes, countering SQLite's
      default behavior of returning offset-naive datetimes.
    """
    impl = types.DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: Optional[Any], dialect: Any) -> Optional[datetime]:
        if value is None:
            return None
        if not isinstance(value, datetime):
            raise TypeError(f"UTCDateTime expected a datetime object, got {type(value).__name__}")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(
                "UTCDateTime requires a timezone-aware datetime object with a valid UTC offset; "
                "got an offset-naive datetime."
            )
        return value.astimezone(timezone.utc)

    def process_result_value(self, value: Optional[Any], dialect: Any) -> Optional[datetime]:
        if value is None:
            return None
        if isinstance(value, str):
            value = datetime.fromisoformat(value)
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a database session per request
    and guarantees proper closure.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def begin_immediate(session: Session) -> Generator[Session, None, None]:
    """
    Explicit SQLite transaction context manager.
    Executes 'BEGIN IMMEDIATE' to acquire a reserved write lock immediately,
    preventing SQLITE_BUSY deadlocks caused by upgrading read locks mid-transaction.

    Invariants:
    - Explicitly rejects already-active transactions to prevent corrupted nested states.
    - Handles failure of BEGIN IMMEDIATE safely without attempting an invalid rollback.
    - Commits on clean exit, rolls back on exception within the context block.
    """
    if session.in_transaction():
        raise RuntimeError(
            "Cannot execute begin_immediate: an active transaction is already in progress on this session."
        )

    # Attempt to start the immediate transaction
    try:
        session.execute(text("BEGIN IMMEDIATE"))
    except Exception:
        # If BEGIN IMMEDIATE failed, check whether SQLAlchemy has opened a session transaction.
        # If it has, call session.rollback() before re-raising the original exception so the session is reusable.
        if session.in_transaction():
            try:
                session.rollback()
            except Exception:
                pass
        raise

    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise


def get_sqlite_pragmas(session_or_engine: Any) -> Dict[str, Any]:
    """
    Utility helper to inspect and verify active SQLite PRAGMA settings.
    Accepts either an active Session or an Engine.
    """
    def _inspect_conn(conn: Any) -> Dict[str, Any]:
        fk = conn.execute(text("PRAGMA foreign_keys;")).scalar()
        jm = conn.execute(text("PRAGMA journal_mode;")).scalar()
        bt = conn.execute(text("PRAGMA busy_timeout;")).scalar()
        sync = conn.execute(text("PRAGMA synchronous;")).scalar()
        return {
            "foreign_keys": int(fk) if fk is not None else 0,
            "journal_mode": str(jm).lower() if jm is not None else "",
            "busy_timeout": int(bt) if bt is not None else 0,
            "synchronous": int(sync) if sync is not None else 0,
        }

    if isinstance(session_or_engine, Session):
        return _inspect_conn(session_or_engine)
    else:
        with session_or_engine.connect() as conn:
            return _inspect_conn(conn)


def init_db(target_engine: Engine = engine) -> None:
    """Creates all registered tables in the SQLite database."""
    Base.metadata.create_all(bind=target_engine)
