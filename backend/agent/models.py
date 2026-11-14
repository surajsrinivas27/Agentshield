"""
Agent Domain Models — AgentShield

Tables: tasks, provenance_records

Task
----
Represents a single user-initiated workflow request.  Every Task is
owned by one authenticated principal (tasks.principal_id → users.id).
The signed capability manifest (produced by security.sign_capability_manifest)
is stored alongside the task so the authorization gateway can re-verify it
without re-signing.

ProvenanceRecord
----------------
Tracks the origin and trust level of every content source consumed during
a Task.  One Task may have many ProvenanceRecords.

Field Semantics (ProvenanceRecord)
------------------------------------
source_id     — UUID of this provenance database record (PK).
origin        — Original source locator, e.g. "EMAIL_001", "DOC_42".
source_type   — Structural category of the source: "email" | "document" |
                "api_response" | "user_input" | …
source_origin — Provenance class: "USER_PROVIDED" | "EXTERNAL".
trust_level   — Runtime trust: "TRUSTED" | "UNTRUSTED".
content_hash  — SHA-256 hex digest of the sanitized content that was read.
                Raw source text is never stored.
taint_labels  — JSON list of active canonical taint labels (UNTRUSTED_DATA,
                UNTRUSTED_INSTRUCTIONS). Granular runtime categories from
                TaintTracker are mapped to these canonical boundary labels.

Foreign-key string references are used throughout to avoid circular Python
imports between backend.agent and backend.authorization.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, List

from sqlalchemy import Column, ForeignKey, JSON, String
from sqlalchemy.orm import relationship, validates

from backend.common.database import Base, UTCDateTime


# ---------------------------------------------------------------------------
# Task status constants
# ---------------------------------------------------------------------------

TASK_STATUS_ACTIVE = "ACTIVE"
TASK_STATUS_COMPLETED = "COMPLETED"
TASK_STATUS_CANCELLED = "CANCELLED"
TASK_STATUS_FAILED = "FAILED"

TASK_STATUSES = {
    TASK_STATUS_ACTIVE,
    TASK_STATUS_COMPLETED,
    TASK_STATUS_CANCELLED,
    TASK_STATUS_FAILED,
}

# ---------------------------------------------------------------------------
# ProvenanceRecord trust constants
# ---------------------------------------------------------------------------

TRUST_TRUSTED = "TRUSTED"
TRUST_UNTRUSTED = "UNTRUSTED"
TRUST_LEVELS = {TRUST_TRUSTED, TRUST_UNTRUSTED}

ORIGIN_USER_PROVIDED = "USER_PROVIDED"
ORIGIN_EXTERNAL = "EXTERNAL"
SOURCE_ORIGINS = {ORIGIN_USER_PROVIDED, ORIGIN_EXTERNAL}

# ---------------------------------------------------------------------------
# Canonical Taint Labels for Persisted Provenance
# ---------------------------------------------------------------------------
# Boundary labels persisted in ProvenanceRecord.taint_labels and evaluated
# by authorization policies.
#
# Boundary Mapping:
# Runtime components (e.g. Person 3's TaintTracker) maintain granular,
# in-memory classifications (e.g. EMAIL_BODY, UNTRUSTED_SOURCE,
# INDIRECT_PROMPT_INJECTION, PII_MASKED). Before persisting to the database,
# runtime taint categories MUST be mapped to one or both of these canonical
# coarse-grained boundary labels:
#   - TAINT_UNTRUSTED_DATA: Marks external/untrusted content data payloads.
#   - TAINT_UNTRUSTED_INSTRUCTIONS: Marks untrusted content containing potential
#     or explicit instructions, preventing indirect prompt injection from being
#     treated as authenticated user authorization.

TAINT_UNTRUSTED_DATA = "UNTRUSTED_DATA"
TAINT_UNTRUSTED_INSTRUCTIONS = "UNTRUSTED_INSTRUCTIONS"

VALID_TAINT_LABELS = {
    TAINT_UNTRUSTED_DATA,
    TAINT_UNTRUSTED_INSTRUCTIONS,
}


def _utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    """Generate a new UUID4 string suitable for a primary key."""
    return str(uuid.uuid4())


def _empty_list() -> List[str]:
    """Callable default for JSON list columns — avoids shared mutable default."""
    return []


# ---------------------------------------------------------------------------
# Task
# ---------------------------------------------------------------------------

class Task(Base):
    """
    A single user-initiated workflow task.

    Columns
    -------
    task_id             UUID4 primary key (String 36).
    principal_id        FK → users.id; the authenticated user who initiated
                        this task.  Named principal_id — never user_id.
    task_type           Workflow category, e.g. "summarize_email".
    resource_ids        JSON list of resource identifiers the task may access.
    allowed_operations  JSON list of permitted operation names.
    permitted_recipients JSON list of authorised recipient identifiers.
    created_at          UTC creation timestamp (timezone-aware).
    expires_at          UTC expiry of the task's capability (timezone-aware).
    status              ACTIVE | COMPLETED | CANCELLED | FAILED.
    capability_manifest JSON blob containing the full signed manifest dict
                        (all manifest fields + manifest_signature).
                        The gateway re-verifies this without re-signing.
    """

    __tablename__ = "tasks"

    task_id = Column(
        String(36),
        primary_key=True,
        default=_new_uuid,
        nullable=False,
        comment="UUID4 primary key",
    )
    # CRITICAL: FK references users.id — string-based to avoid circular import
    # CRITICAL: column is named principal_id — never user_id
    principal_id = Column(
        String(36),
        # CRITICAL: string FK — resolved by SQLAlchemy at metadata.create_all() time,
        # so no Python import of the User class is required here.
        ForeignKey("users.id"),
        nullable=False,
        index=True,
        comment="FK → users.id (string-based to avoid circular import)",
    )
    task_type = Column(
        String(64),
        nullable=False,
        comment="Workflow category identifier",
    )
    resource_ids = Column(
        JSON,
        nullable=False,
        default=_empty_list,
        comment="JSON list of resource identifiers",
    )
    allowed_operations = Column(
        JSON,
        nullable=False,
        default=_empty_list,
        comment="JSON list of permitted operation names",
    )
    permitted_recipients = Column(
        JSON,
        nullable=False,
        default=_empty_list,
        comment="JSON list of authorised recipient identifiers",
    )
    created_at = Column(
        UTCDateTime,
        default=_utcnow,
        nullable=False,
        comment="UTC creation timestamp",
    )
    expires_at = Column(
        UTCDateTime,
        nullable=False,
        comment="UTC expiry of the task capability (timezone-aware)",
    )
    status = Column(
        String(20),
        nullable=False,
        default=TASK_STATUS_ACTIVE,
        comment="ACTIVE | COMPLETED | CANCELLED | FAILED",
    )
    capability_manifest = Column(
        JSON(none_as_null=True),
        nullable=False,
        comment=(
            "Complete signed capability manifest dict, including manifest_signature. "
            "Stored so the gateway can re-verify without re-signing."
        ),
    )

    # Relationship to ProvenanceRecord — string reference avoids forward-import issues.
    # NOTE: Never cascade delete or delete-orphan on provenance records.
    # Provenance records are an immutable forensic audit log and must be retained.
    provenance_records = relationship(
        "ProvenanceRecord",
        back_populates="task",
        cascade="save-update, merge",
        lazy="select",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Task task_id={self.task_id!r} principal_id={self.principal_id!r} "
            f"task_type={self.task_type!r} status={self.status!r}>"
        )


# ---------------------------------------------------------------------------
# ProvenanceRecord
# ---------------------------------------------------------------------------

class ProvenanceRecord(Base):
    """
    Provenance and taint record for a content source consumed by a Task.

    Field semantics
    ---------------
    source_id     UUID of this provenance database record (PK).
    task_id       FK → tasks.task_id; the task that consumed this source.
    origin        Original source locator / identifier, e.g. "EMAIL_001".
    source_type   Structural category: "email" | "document" | "api_response"
                  | "user_input" | …
    source_origin Provenance class: "USER_PROVIDED" | "EXTERNAL".
    trust_level   Runtime trust assignment: "TRUSTED" | "UNTRUSTED".
    content_hash  SHA-256 hex digest of the sanitized content read.
                  Raw source text is NEVER stored here.
    taint_labels  JSON list of active canonical taint labels:
                  UNTRUSTED_DATA, UNTRUSTED_INSTRUCTIONS.  Empty by default.
    created_at    UTC timestamp when the record was inserted.

    Backward-compatibility note
    ---------------------------
    Earlier design sketches used the name ``provenance_id`` for this record's
    PK and ``source_identifier`` for the locator field.  Stage 2 service
    adapters will expose those aliases at the schema (Pydantic) layer so that
    the ORM column names remain stable.
    """

    __tablename__ = "provenance_records"

    source_id = Column(
        String(36),
        primary_key=True,
        default=_new_uuid,
        nullable=False,
        comment="UUID4 primary key of this provenance record",
    )
    # CRITICAL: FK references tasks.task_id — not tasks.id
    # CRITICAL: ondelete="RESTRICT" guarantees that deleting a Task cannot delete
    # or orphan its provenance records.
    task_id = Column(
        String(36),
        ForeignKey("tasks.task_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="FK → tasks.task_id",
    )
    origin = Column(
        String,
        nullable=False,
        comment="Original source locator, e.g. EMAIL_001",
    )
    source_type = Column(
        String(32),
        nullable=False,
        comment="email | document | api_response | user_input | …",
    )
    source_origin = Column(
        String(20),
        nullable=False,
        comment="USER_PROVIDED | EXTERNAL",
    )
    trust_level = Column(
        String(16),
        nullable=False,
        default=TRUST_UNTRUSTED,
        comment="TRUSTED | UNTRUSTED",
    )
    content_hash = Column(
        String(64),
        nullable=False,
        comment="SHA-256 hex digest of sanitized content — raw text is never stored",
    )
    taint_labels = Column(
        JSON,
        nullable=False,
        default=_empty_list,
        comment="JSON list of active canonical taint labels: UNTRUSTED_DATA, UNTRUSTED_INSTRUCTIONS",
    )
    created_at = Column(
        UTCDateTime,
        default=_utcnow,
        nullable=False,
        comment="UTC timestamp when this record was inserted",
    )

    @validates("taint_labels")
    def validate_taint_labels(self, key: str, labels: Any) -> List[str]:
        """
        Validate that all persisted taint labels belong to VALID_TAINT_LABELS.
        Fails fast if runtime categories have not been normalized to canonical
        persisted boundary labels.
        """
        if labels is None:
            return []
        if not isinstance(labels, (list, tuple, set)):
            raise TypeError(
                f"taint_labels must be a list or collection of strings, got {type(labels).__name__}"
            )
        validated: List[str] = []
        for label in labels:
            if not isinstance(label, str):
                raise TypeError(f"Each taint label must be a string, got {type(label).__name__}")
            if label not in VALID_TAINT_LABELS:
                raise ValueError(
                    f"Invalid taint label {label!r}. Persisted labels must be members of "
                    f"VALID_TAINT_LABELS {sorted(VALID_TAINT_LABELS)}. Runtime TaintTracker "
                    f"categories must be mapped to canonical boundary labels prior to persistence."
                )
            validated.append(label)
        return validated

    # Relationship back to Task — string reference
    task = relationship(
        "Task",
        back_populates="provenance_records",
        lazy="select",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<ProvenanceRecord source_id={self.source_id!r} "
            f"task_id={self.task_id!r} trust_level={self.trust_level!r}>"
        )
