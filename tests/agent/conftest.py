"""
Shared Fixtures for Agent Subsystem Tests
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Tuple

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

import backend.model_registry  # noqa: F401
from backend.common.database import Base
from backend.authorization.models import User, ROLE_EMPLOYEE, ROLE_MANAGER
from backend.common.security import sign_capability_manifest


@pytest.fixture(scope="module")
def agent_test_engine():
    """In-memory SQLite engine with PRAGMA foreign_keys = ON and StaticPool."""
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )

    @event.listens_for(eng, "connect")
    def _fk_on(dbapi_conn, _rec):
        dbapi_conn.execute("PRAGMA foreign_keys = ON;")

    Base.metadata.create_all(bind=eng)
    yield eng
    eng.dispose()


@pytest.fixture
def session(agent_test_engine):
    """Provides an isolated database session per test with automatic rollback."""
    sf = sessionmaker(
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
        bind=agent_test_engine,
        future=True,
    )
    db = sf()
    yield db
    db.rollback()
    db.close()


@pytest.fixture
def test_user(session) -> User:
    """Create a persistent active test user."""
    uid = str(uuid.uuid4())
    user = User(
        id=uid,
        username=f"agent_user_{uid[:8]}",
        password_hash="$argon2id$placeholder",
        role=ROLE_EMPLOYEE,
        is_active=True,
    )
    session.add(user)
    session.commit()
    return user


@pytest.fixture
def other_user(session) -> User:
    """Create a secondary active test user for isolation tests."""
    uid = str(uuid.uuid4())
    user = User(
        id=uid,
        username=f"other_user_{uid[:8]}",
        password_hash="$argon2id$placeholder",
        role=ROLE_MANAGER,
        is_active=True,
    )
    session.add(user)
    session.commit()
    return user


def create_signed_manifest(
    task_id: str,
    user_id: str,
    task_type: str = "summarize_email",
    allowed_operations: Tuple[str, ...] = ("read", "summarize"),
    allowed_resource_ids: Tuple[str, ...] = ("EMAIL_001", "EMAIL_002"),
    permitted_recipients: Tuple[str, ...] = ("auditor@example.com",),
    expires_at: datetime = None,
) -> dict:
    """Helper to generate a cryptographically valid capability manifest."""
    if expires_at is None:
        expires_at = datetime.now(timezone.utc) + timedelta(hours=2)

    payload = {
        "task_id": task_id,
        "user_id": user_id,
        "task_type": task_type,
        "allowed_operations": list(allowed_operations),
        "allowed_resource_ids": list(allowed_resource_ids),
        "permitted_recipients": list(permitted_recipients),
        "expires_at": expires_at.astimezone(timezone.utc).isoformat(),
    }
    sig = sign_capability_manifest(payload)
    payload["manifest_signature"] = sig
    return payload
