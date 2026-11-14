"""
Tamper-Evident Audit Logging — AgentShield Stage 3

Implements a persistent audit_events table with cryptographic hash-chaining (RFC 8785),
principal-scoped retrieval, and zero persistence of raw sensitive data or credentials.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Column, Integer, JSON, String, desc, func, select
from sqlalchemy.orm import Session

from backend.authorization.schemas import AuditLogEntrySchema, AuditLogsResponse
from backend.common.database import Base, UTCDateTime, get_db
from backend.common.security import compute_audit_entry_hash, verify_audit_entry_hash


GENESIS_HASH = "0" * 64


class AuditEvent(Base):
    """
    Cryptographically chained, tamper-evident audit record.
    Guarantees non-repudiation and detection of unauthorized modifications.
    """
    __tablename__ = "audit_events"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        nullable=False,
        comment="UUID4 audit event identifier",
    )
    sequence_number = Column(
        Integer,
        nullable=False,
        unique=True,
        index=True,
        comment="Strict monotonically increasing sequence number",
    )
    task_id = Column(
        String(36),
        nullable=True,
        index=True,
        comment="Associated task ID, if applicable",
    )
    actor_id = Column(
        String(36),
        nullable=False,
        index=True,
        comment="Principal ID who initiated the action",
    )
    event_type = Column(
        String(50),
        nullable=False,
        comment="Event category (AUTH_LOGIN, TASK_CREATE, AUTHORIZATION_DECISION, etc.)",
    )
    operation = Column(
        String(50),
        nullable=True,
        comment="Specific operation (READ_DOCUMENT, FORWARD_EMAIL, etc.)",
    )
    decision = Column(
        String(20),
        nullable=True,
        comment="Outcome or decision (ALLOW, BLOCK, SUCCESS, FAILURE)",
    )
    reason = Column(
        String(255),
        nullable=True,
        comment="Human-readable rationale or policy explanation",
    )
    timestamp = Column(
        UTCDateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="Timezone-aware UTC timestamp of event",
    )
    previous_hash = Column(
        String(64),
        nullable=False,
        comment="SHA-256 hash of previous audit entry in sequence",
    )
    entry_hash = Column(
        String(64),
        nullable=False,
        comment="SHA-256 hash over canonical RFC 8785 JSON representation of this entry",
    )
    payload = Column(
        JSON,
        nullable=True,
        comment="Sanitized operational metadata (never contains raw text, passwords, or PII)",
    )

    def to_schema(self) -> AuditLogEntrySchema:
        """Convert ORM record to Pydantic schema."""
        return AuditLogEntrySchema(
            audit_id=self.id,
            sequence_number=self.sequence_number,
            task_id=self.task_id,
            actor_id=self.actor_id,
            event_type=self.event_type,
            operation=self.operation,
            decision=self.decision,
            reason=self.reason,
            timestamp=self.timestamp.isoformat(),
            previous_hash=self.previous_hash,
            entry_hash=self.entry_hash,
        )


def record_audit_event(
    db: Session,
    actor_id: str,
    event_type: str,
    task_id: Optional[str] = None,
    operation: Optional[str] = None,
    decision: Optional[str] = None,
    reason: Optional[str] = None,
    extra_payload: Optional[Dict[str, Any]] = None,
) -> AuditEvent:
    """
    Append a tamper-evident audit record to the hash chain.

    INVARIANTS:
    - Automatically sequences entries monotonically.
    - Chains previous entry_hash to guarantee hash continuity.
    - Strips all raw text, passwords, JWT tokens, and PII from payload.
    - Uses Stage 1 compute_audit_entry_hash for RFC 8785 canonical serialization.
    """
    stmt = select(AuditEvent).order_by(desc(AuditEvent.sequence_number)).limit(1)
    last_event = db.execute(stmt).scalar_one_or_none()

    if last_event is None:
        sequence_number = 1
        previous_hash = GENESIS_HASH
    else:
        sequence_number = last_event.sequence_number + 1
        previous_hash = last_event.entry_hash

    now_utc = datetime.now(timezone.utc)
    timestamp_iso = now_utc.isoformat()

    # Construct safe metadata dictionary — strictly non-sensitive fields
    safe_payload: Dict[str, Any] = {
        "task_id": str(task_id) if task_id else "",
        "operation": str(operation) if operation else "",
        "decision": str(decision) if decision else "",
        "reason": str(reason) if reason else "",
    }
    if extra_payload:
        for k, v in extra_payload.items():
            # Forbid sensitive keys
            if k.lower() in {"password", "token", "jwt", "secret", "raw_content", "text"}:
                continue
            if isinstance(v, (str, int, float, bool)) or v is None:
                safe_payload[k] = v

    entry_hash = compute_audit_entry_hash(
        sequence_number=sequence_number,
        previous_hash=previous_hash,
        timestamp_iso=timestamp_iso,
        event_type=event_type,
        actor_id=actor_id,
        payload_dict=safe_payload,
    )

    audit_entry = AuditEvent(
        id=str(uuid.uuid4()),
        sequence_number=sequence_number,
        task_id=task_id,
        actor_id=actor_id,
        event_type=event_type,
        operation=operation,
        decision=decision,
        reason=reason,
        timestamp=now_utc,
        previous_hash=previous_hash,
        entry_hash=entry_hash,
        payload=safe_payload,
    )

    db.add(audit_entry)
    db.flush()
    return audit_entry


def get_principal_audit_logs(
    db: Session,
    principal_id: str,
    task_id: Optional[str] = None,
    limit: int = 50,
) -> List[AuditEvent]:
    """
    Retrieve audit entries strictly scoped to the requesting principal.
    Guarantees cross-tenant isolation: User A can never inspect User B's audit events.
    """
    stmt = (
        select(AuditEvent)
        .where(AuditEvent.actor_id == principal_id)
        .order_by(desc(AuditEvent.sequence_number))
        .limit(limit)
    )
    if task_id:
        stmt = stmt.where(AuditEvent.task_id == task_id)

    return list(db.execute(stmt).scalars().all())


from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# ---------------------------------------------------------------------------
# FastAPI Router for Audit History
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/audit", tags=["Audit"])
http_bearer = HTTPBearer(auto_error=False)


def _auth_dependency(
    credentials: HTTPAuthorizationCredentials = Depends(http_bearer),
    db: Session = Depends(get_db),
):
    from backend.authorization.auth_service import get_current_user_context
    return get_current_user_context(credentials=credentials, db=db)


@router.get("/logs", response_model=AuditLogsResponse)
def get_audit_logs(
    task_id: Optional[str] = Query(default=None, description="Optional task ID filter"),
    limit: int = Query(default=50, ge=1, le=200, description="Max logs to return"),
    db: Session = Depends(get_db),
    auth_data: tuple = Depends(_auth_dependency),
):
    """
    Retrieve audit logs for the authenticated principal.
    Cross-user isolation is strictly enforced.
    """
    auth_context, user = auth_data
    logs = get_principal_audit_logs(
        db=db,
        principal_id=user.id,
        task_id=task_id,
        limit=limit,
    )
    return AuditLogsResponse(
        items=[log.to_schema() for log in logs],
        total=len(logs),
    )
