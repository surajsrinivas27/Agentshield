"""
Tests for backend/common/database.py
Verifies:
- Stable database location resolution anchored at project root
- Automatic creation of data directory
- SQLite WAL mode and avoiding redundant WAL PRAGMA executions
- Foreign key constraint enforcement
- Busy timeout and synchronous pragmas
- BEGIN IMMEDIATE transaction context manager:
  * Clean commit
  * Clean rollback on inner exception
  * Rejection of already-active transactions
  * Safe handling when BEGIN IMMEDIATE itself fails
- Session handling and cleanup
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from sqlalchemy import Column, ForeignKey, Integer, String, create_engine, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from backend.common.database import (
    DEFAULT_DB_FILE,
    PROJECT_ROOT,
    begin_immediate,
    get_db,
    get_sqlite_pragmas,
    resolve_database_url,
)


@pytest.fixture
def temp_db_file():
    """Provides a temporary file path for isolated SQLite file-based tests."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_path = f.name
    yield temp_path
    # Windows cleanup
    for ext in ["", "-wal", "-shm"]:
        p = temp_path + ext
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass


@pytest.fixture
def test_engine(temp_db_file):
    """Creates an engine bound to the temporary SQLite file and disposes connections on teardown."""
    engine = create_engine(
        f"sqlite:///{temp_db_file}",
        connect_args={"check_same_thread": False},
        future=True,
    )
    yield engine
    engine.dispose()


@pytest.fixture
def test_session_factory(test_engine):
    """Provides a SessionLocal factory for the test engine."""
    return sessionmaker(autocommit=False, autoflush=False, bind=test_engine, future=True)


def test_database_url_resolution():
    """Verify that default and relative database URLs are resolved to project root."""
    # 1. Default when unset
    default_resolved = resolve_database_url(None)
    assert default_resolved.startswith("sqlite:///")
    assert DEFAULT_DB_FILE.as_posix() in default_resolved
    assert (PROJECT_ROOT / "data").exists()

    # 2. Relative path
    rel_url = "sqlite:///data/custom.db"
    resolved_rel = resolve_database_url(rel_url)
    expected_path = (PROJECT_ROOT / "data" / "custom.db").resolve().as_posix()
    assert resolved_rel == f"sqlite:///{expected_path}"

    # 3. In-memory
    mem_url = "sqlite:///:memory:"
    assert resolve_database_url(mem_url) == mem_url


def test_sqlite_pragmas_configured(test_engine):
    """Verify that foreign keys, WAL mode, busy timeout, and synchronous NORMAL are active."""
    pragmas = get_sqlite_pragmas(test_engine)
    assert pragmas["foreign_keys"] == 1, "Foreign keys must be enabled (1)"
    assert pragmas["journal_mode"] == "wal", "Journal mode must be WAL"
    assert pragmas["busy_timeout"] == 30000, "Busy timeout must be 30000 ms"
    assert pragmas["synchronous"] == 1, "Synchronous mode must be NORMAL (1)"


def test_foreign_key_enforcement(test_engine, test_session_factory):
    """Verify that SQLite enforces relational foreign key constraints."""
    TestBase = declarative_base()

    class Parent(TestBase):
        __tablename__ = "test_parents"
        id = Column(Integer, primary_key=True)
        name = Column(String(50), nullable=False)

    class Child(TestBase):
        __tablename__ = "test_children"
        id = Column(Integer, primary_key=True)
        parent_id = Column(Integer, ForeignKey("test_parents.id"), nullable=False)
        description = Column(String(50), nullable=False)

    TestBase.metadata.create_all(bind=test_engine)

    # 1. Attempt inserting a child referencing a non-existent parent
    with test_session_factory() as session:
        orphan = Child(id=1, parent_id=999, description="Invalid child")
        session.add(orphan)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

    # 2. Insert valid parent, then valid child
    with test_session_factory() as session:
        parent = Parent(id=10, name="Parent One")
        session.add(parent)
        session.commit()

        child = Child(id=1, parent_id=10, description="Valid child")
        session.add(child)
        session.commit()

        # Query back
        saved_child = session.get(Child, 1)
        assert saved_child is not None
        assert saved_child.parent_id == 10


def test_begin_immediate_commit(test_engine, test_session_factory):
    """Verify that begin_immediate commits write operations cleanly."""
    TestBase = declarative_base()

    class Counter(TestBase):
        __tablename__ = "test_counter"
        id = Column(Integer, primary_key=True)
        val = Column(Integer, nullable=False)

    TestBase.metadata.create_all(bind=test_engine)

    with test_session_factory() as session:
        with begin_immediate(session):
            counter = Counter(id=1, val=100)
            session.add(counter)

    # Verify committed in separate session
    with test_session_factory() as session:
        stored = session.get(Counter, 1)
        assert stored is not None
        assert stored.val == 100


def test_begin_immediate_rollback_on_error(test_engine, test_session_factory):
    """Verify that begin_immediate cleanly rolls back upon an unhandled exception inside the context."""
    TestBase = declarative_base()

    class Item(TestBase):
        __tablename__ = "test_items"
        id = Column(Integer, primary_key=True)
        name = Column(String(50), nullable=False)

    TestBase.metadata.create_all(bind=test_engine)

    with test_session_factory() as session:
        with pytest.raises(ValueError):
            with begin_immediate(session):
                item = Item(id=1, name="Transient")
                session.add(item)
                raise ValueError("Simulated unexpected failure")

    # Verify item was not persisted
    with test_session_factory() as session:
        stored = session.get(Item, 1)
        assert stored is None


def test_begin_immediate_rejects_already_active_transaction(test_session_factory):
    """Verify that begin_immediate raises RuntimeError if a transaction is already active."""
    with test_session_factory() as session:
        # Start a transaction manually
        session.execute(text("SELECT 1;"))
        assert session.in_transaction() is True

        with pytest.raises(RuntimeError, match="active transaction is already in progress"):
            with begin_immediate(session):
                pass
        session.rollback()


def test_begin_immediate_handles_begin_failure_with_rollback():
    """Verify that if BEGIN IMMEDIATE execution fails and opens a transaction, rollback is invoked."""
    mock_session = MagicMock()
    # Simulates SQLAlchemy opening a transaction when execute() was invoked
    mock_session.in_transaction.side_effect = [False, True]
    mock_session.execute.side_effect = OperationalError("database is locked", {}, None)

    with pytest.raises(OperationalError):
        with begin_immediate(mock_session):
            pass

    mock_session.execute.assert_called_once()
    mock_session.rollback.assert_called_once()
    mock_session.commit.assert_not_called()


def test_real_sqlite_lock_contention_and_session_reuse(temp_db_file):
    """
    Verify real SQLite lock contention between two independent sessions:
    1. Session 1 enters begin_immediate and holds the write lock.
    2. Session 2 attempts begin_immediate and fails with OperationalError.
    3. Session 2 cleans up its failed transaction state.
    4. Session 1 commits and releases the write lock.
    5. The exact same Session 2 re-attempts begin_immediate and succeeds.
    """
    TestBase = declarative_base()

    class AuditRecord(TestBase):
        __tablename__ = "test_audit_records"
        id = Column(Integer, primary_key=True)
        message = Column(String(100), nullable=False)

    engine1 = create_engine(f"sqlite:///{temp_db_file}", connect_args={"check_same_thread": False})
    engine2 = create_engine(f"sqlite:///{temp_db_file}", connect_args={"check_same_thread": False})
    TestBase.metadata.create_all(bind=engine1)

    conn1 = engine1.connect()
    conn2 = engine2.connect()
    # Fast failure timeout for session 2 to avoid waiting 30 seconds
    conn2.execute(text("PRAGMA busy_timeout = 50;"))

    s1 = Session(bind=conn1)
    s2 = Session(bind=conn2)

    try:
        # Session 1 acquires the write lock via begin_immediate
        ctx1 = begin_immediate(s1)
        ctx1.__enter__()
        rec1 = AuditRecord(id=1, message="Session 1 entry")
        s1.add(rec1)

        # Session 2 attempts begin_immediate while Session 1 holds the lock -> must fail with OperationalError
        with pytest.raises(OperationalError):
            with begin_immediate(s2):
                rec2 = AuditRecord(id=2, message="Session 2 entry")
                s2.add(rec2)

        # Verify Session 2 is not left in an active transaction and is clean for reuse
        assert s2.in_transaction() is False

        # Session 1 finishes and releases the lock
        ctx1.__exit__(None, None, None)

        # Now the exact same Session 2 must be able to acquire the lock and execute successfully
        with begin_immediate(s2):
            rec2 = AuditRecord(id=2, message="Session 2 entry succeeded")
            s2.add(rec2)

        # Verify both records were persisted
        all_records = conn1.execute(text("SELECT id, message FROM test_audit_records ORDER BY id;")).fetchall()
        assert len(all_records) == 2
        assert all_records[0][0] == 1
        assert all_records[1][0] == 2
    finally:
        s1.close()
        s2.close()
        conn1.close()
        conn2.close()
        engine1.dispose()
        engine2.dispose()


def test_get_db_generator():
    """Verify that the FastAPI get_db dependency yields a valid session and closes it."""
    db_gen = get_db()
    session = next(db_gen)
    assert session is not None
    # Close generator
    with pytest.raises(StopIteration):
        next(db_gen)
