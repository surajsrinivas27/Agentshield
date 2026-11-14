"""
Task Repository — AgentShield

Provides principal-scoped task creation, capability manifest verification,
retrieval, and concurrency-safe lifecycle state management.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.agent.dtos import TaskContext
from backend.agent.exceptions import (
    InvalidTaskTransitionError,
    ManifestVerificationError,
    TaskNotFoundError,
    TaskOwnershipError,
    TaskTransactionError,
)
from backend.agent.models import (
    TASK_STATUS_ACTIVE,
    TASK_STATUS_CANCELLED,
    TASK_STATUS_COMPLETED,
    TASK_STATUS_FAILED,
    TASK_STATUSES,
    Task,
)
from backend.authorization.models import User
from backend.common.database import begin_immediate
from backend.common.security import verify_capability_manifest

TERMINAL_STATUSES = frozenset({
    TASK_STATUS_COMPLETED,
    TASK_STATUS_CANCELLED,
    TASK_STATUS_FAILED,
})

VALID_TRANSITIONS = frozenset({
    (TASK_STATUS_ACTIVE, TASK_STATUS_COMPLETED),
    (TASK_STATUS_ACTIVE, TASK_STATUS_CANCELLED),
    (TASK_STATUS_ACTIVE, TASK_STATUS_FAILED),
})


def _parse_iso_to_utc(iso_string: str) -> datetime:
    """Parse an ISO-8601 string to a timezone-aware UTC datetime."""
    try:
        dt = datetime.fromisoformat(iso_string.replace("Z", "+00:00"))
    except (ValueError, TypeError) as exc:
        raise ManifestVerificationError(f"Malformed manifest timestamp: {iso_string!r}") from exc
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ManifestVerificationError(f"Manifest timestamp must be timezone-aware: {iso_string!r}")
    return dt.astimezone(timezone.utc)


class TaskRepository:
    """Repository handling persistence, validation, and lifecycle of Tasks."""

    @staticmethod
    def create_task(
        db: Session,
        principal_id: str,
        task_type: str,
        capability_manifest: Mapping[str, Any],
        resource_ids: Sequence[str],
        allowed_operations: Sequence[str],
        permitted_recipients: Sequence[str],
        expires_at: datetime,
        task_id: Optional[str] = None,
    ) -> TaskContext:
        """
        Create a new Task with strict cryptographic capability manifest verification.
        INVARIANTS:
        - Confirms principal exists and is active.
        - Cryptographically verifies HMAC-SHA256 manifest signature.
        - Enforces 1-to-1 matching between manifest and task creation parameters.
        - Rejects duplicates in operation/resource/recipient lists.
        - Rejects expired tasks.
        - Returns an immutable TaskContext DTO.
        """
        if not principal_id or not isinstance(principal_id, str):
            raise TaskOwnershipError("principal_id must be a non-empty string.")

        # 1. Principal Existence and Active Verification
        user = db.get(User, principal_id)
        if user is None:
            raise TaskNotFoundError(f"Principal with id {principal_id!r} does not exist.")
        if not user.is_active:
            raise TaskOwnershipError(f"Principal {principal_id!r} is inactive or suspended.")

        # 2. Expiration Verification
        now = datetime.now(timezone.utc)
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise ManifestVerificationError("expires_at must be a timezone-aware datetime.")
        expires_at_utc = expires_at.astimezone(timezone.utc)
        if expires_at_utc <= now:
            raise ManifestVerificationError("Cannot create a task with an expired or past expiration time.")

        # 3. Duplicate Detection on Input Collections
        if len(allowed_operations) != len(set(allowed_operations)):
            raise ManifestVerificationError("Duplicate entries not permitted in allowed_operations.")
        if len(resource_ids) != len(set(resource_ids)):
            raise ManifestVerificationError("Duplicate entries not permitted in resource_ids.")
        if len(permitted_recipients) != len(set(permitted_recipients)):
            raise ManifestVerificationError("Duplicate entries not permitted in permitted_recipients.")

        # 4. Capability Manifest Cryptographic Verification
        if not isinstance(capability_manifest, (dict, Mapping)):
            raise ManifestVerificationError("capability_manifest must be a dictionary.")

        manifest_dict = dict(capability_manifest)
        signature = manifest_dict.get("manifest_signature")
        if not signature or not isinstance(signature, str):
            raise ManifestVerificationError("Missing or invalid 'manifest_signature' in capability_manifest.")

        # Build unsigned payload for verify_capability_manifest
        unsigned_payload = {k: v for k, v in manifest_dict.items() if k != "manifest_signature"}
        if not verify_capability_manifest(unsigned_payload, signature):
            raise ManifestVerificationError(
                "Capability manifest HMAC-SHA256 signature verification failed. "
                "The manifest is forged, tampered, or invalid."
            )

        # 5. Manifest Payload Consistency Checks
        resolved_task_id = task_id or manifest_dict.get("task_id") or str(uuid.uuid4())
        if manifest_dict.get("task_id") != resolved_task_id:
            raise ManifestVerificationError(
                f"Manifest task_id {manifest_dict.get('task_id')!r} does not match requested task_id {resolved_task_id!r}."
            )

        if manifest_dict.get("user_id") != principal_id:
            raise ManifestVerificationError(
                f"Manifest user_id {manifest_dict.get('user_id')!r} does not match requested principal_id {principal_id!r}."
            )

        if manifest_dict.get("task_type") != task_type:
            raise ManifestVerificationError(
                f"Manifest task_type {manifest_dict.get('task_type')!r} does not match requested task_type {task_type!r}."
            )

        manifest_expiry_utc = _parse_iso_to_utc(str(manifest_dict.get("expires_at")))
        if manifest_expiry_utc != expires_at_utc:
            raise ManifestVerificationError(
                f"Manifest expires_at ({manifest_expiry_utc.isoformat()}) does not match task expires_at ({expires_at_utc.isoformat()})."
            )

        manifest_ops = manifest_dict.get("allowed_operations", [])
        if len(manifest_ops) != len(set(manifest_ops)):
            raise ManifestVerificationError("Duplicate entries in manifest allowed_operations.")
        if sorted(allowed_operations) != sorted(manifest_ops):
            raise ManifestVerificationError("allowed_operations does not match capability_manifest allowed_operations.")

        manifest_res = manifest_dict.get("allowed_resource_ids", [])
        if len(manifest_res) != len(set(manifest_res)):
            raise ManifestVerificationError("Duplicate entries in manifest allowed_resource_ids.")
        if sorted(resource_ids) != sorted(manifest_res):
            raise ManifestVerificationError("resource_ids does not match capability_manifest allowed_resource_ids.")

        manifest_recips = manifest_dict.get("permitted_recipients", [])
        if len(manifest_recips) != len(set(manifest_recips)):
            raise ManifestVerificationError("Duplicate entries in manifest permitted_recipients.")
        if sorted(permitted_recipients) != sorted(manifest_recips):
            raise ManifestVerificationError("permitted_recipients does not match capability_manifest permitted_recipients.")

        # 6. Persistence
        task_orm = Task(
            task_id=resolved_task_id,
            principal_id=principal_id,
            task_type=task_type,
            resource_ids=list(resource_ids),
            allowed_operations=list(allowed_operations),
            permitted_recipients=list(permitted_recipients),
            created_at=now,
            expires_at=expires_at_utc,
            status=TASK_STATUS_ACTIVE,
            capability_manifest=manifest_dict,
        )
        db.add(task_orm)
        db.flush()

        return TaskContext.from_orm(task_orm)

    @staticmethod
    def get_task(
        db: Session,
        task_id: str,
        principal_id: str,
    ) -> TaskContext:
        """
        Retrieve a task scoped strictly to the requesting principal.
        FAILS CLOSED: If the task exists under another user, raises TaskOwnershipError.
        If it does not exist at all, raises TaskNotFoundError.
        """
        if not principal_id:
            raise TaskOwnershipError("principal_id is required.")

        task_orm = db.get(Task, task_id)
        if task_orm is None:
            raise TaskNotFoundError(f"Task {task_id!r} not found.")

        if task_orm.principal_id != principal_id:
            raise TaskOwnershipError(f"Principal {principal_id!r} does not own task {task_id!r}.")

        return TaskContext.from_orm(task_orm)

    @staticmethod
    def list_tasks(
        db: Session,
        principal_id: str,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[TaskContext]:
        """
        List tasks strictly belonging to the specified principal.
        Never returns tasks belonging to other principals.
        """
        if not principal_id:
            raise TaskOwnershipError("principal_id is required.")

        stmt = (
            select(Task)
            .where(Task.principal_id == principal_id)
            .order_by(Task.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        if status:
            if status not in TASK_STATUSES:
                raise ValueError(f"Invalid task status filter: {status!r}")
            stmt = stmt.where(Task.status == status)

        records = db.execute(stmt).scalars().all()
        return [TaskContext.from_orm(t) for t in records]

    @staticmethod
    def update_task_status(
        db: Session,
        task_id: str,
        principal_id: str,
        new_status: str,
    ) -> TaskContext:
        """
        Atomically and transactionally update a task's status under SQLite write lock.
        Enforces state transition rules and prevents reopening terminal tasks.
        """
        if not principal_id:
            raise TaskOwnershipError("principal_id is required.")

        if new_status not in TASK_STATUSES:
            raise ValueError(f"Invalid status {new_status!r}. Must be one of {sorted(TASK_STATUSES)}.")

        # Enforce transaction contract: update_task_status requires a clean session
        # to establish an exclusive SQLite write lock via begin_immediate().
        if db.in_transaction():
            raise TaskTransactionError(
                "Cannot update task status: an active transaction is already in progress on this session. "
                "update_task_status requires a clean session to guarantee exclusive immediate write locking."
            )

        with begin_immediate(db):
            task_orm = db.get(Task, task_id)
            if task_orm is None:
                raise TaskNotFoundError(f"Task {task_id!r} not found.")
            if task_orm.principal_id != principal_id:
                raise TaskOwnershipError(f"Principal {principal_id!r} does not own task {task_id!r}.")

            if task_orm.status in TERMINAL_STATUSES:
                raise InvalidTaskTransitionError(
                    f"Cannot update terminal task {task_id!r} in status {task_orm.status!r} to {new_status!r}."
                )

            if (task_orm.status, new_status) not in VALID_TRANSITIONS:
                raise InvalidTaskTransitionError(
                    f"Illegal task transition from {task_orm.status!r} to {new_status!r}."
                )

            task_orm.status = new_status
            db.flush()
            return TaskContext.from_orm(task_orm)
