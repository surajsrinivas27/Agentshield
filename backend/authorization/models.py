"""
Authorization Domain Models — AgentShield

Table: users

Provides the User ORM model representing an authenticated principal.
All authorization decisions reference the User record as the source of
identity; JWT claims are informational only and must not be trusted in
place of the database record.

No authentication behavior is implemented here.
Authentication utilities (hash_password, verify_password, create_access_token)
are in backend.common.security and will be wired in Stage 2.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, String

from backend.common.database import Base, UTCDateTime


# ---------------------------------------------------------------------------
# Supported roles — informational constants; enforcement lives in the gateway
# ---------------------------------------------------------------------------

ROLE_EMPLOYEE = "Employee"
ROLE_MANAGER = "Manager"
ROLE_ADMINISTRATOR = "Administrator"

SUPPORTED_ROLES = {ROLE_EMPLOYEE, ROLE_MANAGER, ROLE_ADMINISTRATOR}


def _utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    """Generate a new UUID4 string suitable for a primary key."""
    return str(uuid.uuid4())


class User(Base):
    """
    Authenticated principal record.

    Columns
    -------
    id                  UUID string (36 chars) primary key; generated externally.
    username            Unique display name used for login.
    password_hash       Argon2id hash produced by security.hash_password().
                        NEVER store plaintext passwords.
    role                One of: Employee, Manager, Administrator.
    department          Optional organisational unit.
    is_active           False means the account is suspended; the gateway
                        must reject tokens for inactive users.
    token_valid_after   UTC datetime; JWTs with iat < token_valid_after are
                        treated as revoked (supports forced logout / rotation).
                        Stored as timezone-aware UTC.
    created_at          UTC datetime when the record was first created.
    """

    __tablename__ = "users"

    id = Column(
        String(36),
        primary_key=True,
        default=_new_uuid,
        nullable=False,
        comment="UUID4 primary key",
    )
    username = Column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique login username",
    )
    password_hash = Column(
        String(255),
        nullable=False,
        comment="Argon2id hash — never store plaintext",
    )
    role = Column(
        String(20),
        nullable=False,
        comment="Employee | Manager | Administrator",
    )
    department = Column(
        String(64),
        nullable=True,
        comment="Optional organisational unit",
    )
    is_active = Column(
        Boolean,
        default=True,
        nullable=False,
        comment="False suspends all access for this principal",
    )
    token_valid_after = Column(
        UTCDateTime,
        nullable=True,
        comment="JWTs with iat before this timestamp are revoked",
    )
    created_at = Column(
        UTCDateTime,
        default=_utcnow,
        nullable=False,
        comment="UTC creation timestamp",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<User id={self.id!r} username={self.username!r} "
            f"role={self.role!r} is_active={self.is_active!r}>"
        )
