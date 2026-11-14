"""
Capability Manifest & Task Creation Service — AgentShield Stage 3

Binds task capabilities deterministically to the user's live database role,
signs capability manifests server-side with HMAC-SHA256, and creates Task entities.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.agent.dtos import TaskContext
from backend.agent.exceptions import (
    ManifestVerificationError,
    TaskNotFoundError,
    TaskOwnershipError,
)
from backend.agent.task_repository import TaskRepository
from backend.authorization.audit import record_audit_event
from backend.authorization.auth_service import get_current_user_context
from backend.authorization.models import ROLE_ADMINISTRATOR, ROLE_EMPLOYEE, ROLE_MANAGER, User
from backend.authorization.schemas import CreateTaskRequest, CreateTaskResponse
from backend.common.database import get_db
from backend.common.security import sign_capability_manifest


# ---------------------------------------------------------------------------
# Demo Permission Policy & Simulated Resources
# ---------------------------------------------------------------------------

ROLE_CAPABILITIES: Dict[str, Tuple[str, ...]] = {
    ROLE_EMPLOYEE: ("READ_DOCUMENT", "SUMMARIZE_DOCUMENT"),
    ROLE_MANAGER: ("READ_DOCUMENT", "SUMMARIZE_DOCUMENT", "FORWARD_EMAIL"),
    ROLE_ADMINISTRATOR: ("READ_DOCUMENT", "SUMMARIZE_DOCUMENT", "FORWARD_EMAIL"),
}

DEMO_RESOURCES: Tuple[str, ...] = (
    "demo-document-001",
    "demo-email-001",
)

DEMO_RECIPIENT = "demo-recipient@agentshield.local"

# Default capability duration: 1 hour
DEFAULT_TASK_DURATION = timedelta(hours=1)


def get_role_capabilities(role: str) -> Tuple[str, ...]:
    """Retrieve allowed operations permitted for a given database role."""
    return ROLE_CAPABILITIES.get(role, ("READ_DOCUMENT",))


def get_permitted_recipients_for_role(role: str) -> Tuple[str, ...]:
    """Only roles with FORWARD_EMAIL are granted recipient permissions."""
    allowed_ops = get_role_capabilities(role)
    if "FORWARD_EMAIL" in allowed_ops:
        return (DEMO_RECIPIENT,)
    return ()


def create_task_with_capabilities(
    db: Session,
    user: User,
    task_type: str = "document_processing",
    duration: timedelta = DEFAULT_TASK_DURATION,
) -> TaskContext:
    """
    Core business logic for creating a task bound to the authenticated user's role.

    INVARIANTS:
    - Capabilities derived exclusively from current user.role in the database.
    - Browser callers cannot expand operations, resource IDs, or recipient lists.
    - Task ID generated server-side (UUID4).
    - Expiration timestamp strictly timezone-aware UTC.
    - Cryptographically signed with Stage 1 sign_capability_manifest (HMAC-SHA256).
    - Persisted via TaskRepository.create_task and audited.
    """
    task_id = str(uuid.uuid4())
    now_utc = datetime.now(timezone.utc)
    expires_at = now_utc + duration

    allowed_ops = get_role_capabilities(user.role)
    allowed_resources = DEMO_RESOURCES
    permitted_recipients = get_permitted_recipients_for_role(user.role)

    # 1. Build canonical payload dictionary for HMAC-SHA256 signing
    manifest_payload = {
        "task_id": task_id,
        "user_id": user.id,
        "task_type": task_type,
        "allowed_operations": list(allowed_ops),
        "allowed_resource_ids": list(allowed_resources),
        "permitted_recipients": list(permitted_recipients),
        "expires_at": expires_at.isoformat(),
    }

    # 2. Cryptographically sign manifest using Stage 1 secret
    signature = sign_capability_manifest(manifest_payload)
    manifest_payload["manifest_signature"] = signature

    # 3. Persist Task via TaskRepository
    task_context = TaskRepository.create_task(
        db=db,
        principal_id=user.id,
        task_type=task_type,
        capability_manifest=manifest_payload,
        resource_ids=allowed_resources,
        allowed_operations=allowed_ops,
        permitted_recipients=permitted_recipients,
        expires_at=expires_at,
        task_id=task_id,
    )

    # 4. Record audit event
    record_audit_event(
        db=db,
        actor_id=user.id,
        event_type="TASK_CREATE",
        task_id=task_id,
        operation="CREATE_TASK",
        decision="SUCCESS",
        reason=f"Task created for role {user.role} with {len(allowed_ops)} operations",
        extra_payload={"task_type": task_type, "role": user.role},
    )

    db.commit()
    return task_context


# ---------------------------------------------------------------------------
# FastAPI Router for Tasks
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/tasks", tags=["Tasks"])


@router.post("", response_model=CreateTaskResponse, status_code=status.HTTP_201_CREATED)
def create_task_endpoint(
    request: CreateTaskRequest,
    auth_data: tuple = Depends(get_current_user_context),
    db: Session = Depends(get_db),
):
    """
    Create a new Task with server-bound capability manifest.
    Permissions are determined strictly by the authenticated principal's database role.
    """
    auth_context, user = auth_data

    try:
        task_ctx = create_task_with_capabilities(
            db=db,
            user=user,
            task_type=request.task_type or "document_processing",
        )
    except (TaskNotFoundError, TaskOwnershipError, ManifestVerificationError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Task creation failed: {str(exc)}",
        )

    return CreateTaskResponse(
        task_id=task_ctx.task_id,
        principal_id=task_ctx.principal_id,
        task_type=task_ctx.task_type,
        allowed_operations=list(task_ctx.allowed_operations),
        allowed_resource_ids=list(task_ctx.resource_ids),
        permitted_recipients=list(task_ctx.permitted_recipients),
        expires_at=task_ctx.expires_at.isoformat(),
        status=task_ctx.status,
    )
