"""
AgentShield Stage 2 - Provenance Repository
Enforces task-scoped provenance record persistence, retrieval, and ownership isolation.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.agent.dtos import ProvenanceRecordDTO, ValidatedProvenancePayload
from backend.agent.exceptions import (
    InvalidTaskTransitionError,
    ProvenanceError,
    TaskNotFoundError,
    TaskOwnershipError,
)
from backend.agent.hashing import is_valid_sha256_hex
from backend.agent.models import (
    ORIGIN_EXTERNAL,
    ORIGIN_USER_PROVIDED,
    TAINT_UNTRUSTED_DATA,
    TASK_STATUS_ACTIVE,
    ProvenanceRecord,
    Task,
)
from backend.agent.taint import (
    derive_trust_level,
    resolve_source_origin,
    validate_canonical_label,
)


class ProvenanceRepository:
    """
    Data access layer for ProvenanceRecord entities.
    Guarantees that provenance records are strictly attached to tasks owned by
    the authenticated principal, with automatic trust derivation and canonical taint validation.
    """

    @staticmethod
    def record_provenance(
        db: Session,
        payload: ValidatedProvenancePayload,
    ) -> ProvenanceRecordDTO:
        """
        Record a provenance entry for a task with mandatory ownership check,
        persistence-level baseline enforcement, and trust derivation.

        INTERNAL DOMAIN OPERATION:
        - Accepts a validated provenance object (ValidatedProvenancePayload).
        - Ordinary application callers cannot directly invoke persistence with arbitrary
          USER_PROVIDED origin and empty taint lists.
        - The associated task must exist, be owned by payload.principal_id, and be in ACTIVE status.
        - Persisted external content is guaranteed to receive TAINT_UNTRUSTED_DATA baseline taint
          inside the persistence boundary itself.
        - Trust level is derived strictly within the persistence layer; callers cannot override it.
        """
        if not isinstance(payload, ValidatedProvenancePayload):
            raise TypeError(
                f"record_provenance requires a ValidatedProvenancePayload instance, "
                f"got {type(payload).__name__}."
            )

        # 1. Enforce internal intake authorization at persistence boundary
        if not hasattr(payload, "verify_intake_authorization") or not payload.verify_intake_authorization():
            raise ProvenanceError(
                "Security violation: Provenance payload lacks valid internal intake authorization. "
                "Payloads constructed through model_construct, unverified factories, or tampering are rejected."
            )

        # 2. Verify Task Ownership and State
        task = db.get(Task, payload.task_id)
        if task is None:
            raise TaskNotFoundError(f"Task with id {payload.task_id!r} not found.")

        if task.principal_id != payload.principal_id:
            raise TaskOwnershipError(
                f"Principal {payload.principal_id!r} does not own task {payload.task_id!r}."
            )

        if task.status != TASK_STATUS_ACTIVE:
            raise InvalidTaskTransitionError(
                f"Cannot record provenance for task {payload.task_id!r} with status {task.status!r}. "
                "Task must be ACTIVE."
            )

        # 2. Validate Content Hash format
        if not is_valid_sha256_hex(payload.content_hash):
            raise ProvenanceError(
                f"Invalid content_hash {payload.content_hash!r}. "
                "Must be a 64-character lowercase hexadecimal SHA-256 digest."
            )

        # 3. Enforce persistence-boundary baseline taint for external content
        final_taints: List[str] = list(payload.taint_labels)
        if payload.source_origin == ORIGIN_EXTERNAL:
            if TAINT_UNTRUSTED_DATA not in final_taints:
                final_taints.append(TAINT_UNTRUSTED_DATA)

        # 4. Invariant: USER_PROVIDED cannot carry UNTRUSTED_DATA
        if payload.source_origin == ORIGIN_USER_PROVIDED and TAINT_UNTRUSTED_DATA in final_taints:
            raise ProvenanceError(
                "Security violation: USER_PROVIDED provenance cannot carry UNTRUSTED_DATA taint."
            )

        # 5. Derive Trust Level (caller has no control over trust_level)
        trust_level = derive_trust_level(payload.source_origin, final_taints)

        # 6. Instantiate and Persist ORM Entity
        resolved_source_id = payload.source_id or str(uuid.uuid4())
        record = ProvenanceRecord(
            source_id=resolved_source_id,
            task_id=payload.task_id,
            origin=payload.origin,
            source_type=payload.source_type,
            source_origin=payload.source_origin,
            trust_level=trust_level,
            content_hash=payload.content_hash,
            taint_labels=final_taints,
            created_at=datetime.now(timezone.utc),
        )

        db.add(record)
        db.flush()

        return ProvenanceRecordDTO.from_orm(record)

    @staticmethod
    def get_provenance(
        db: Session,
        source_id: str,
        principal_id: str,
    ) -> ProvenanceRecordDTO:
        """
        Retrieve a provenance record by source_id, enforcing ownership of the parent task.

        INVARIANTS:
        - Scoped strictly by (source_id, principal_id) through parent Task join.
        - Never performs an unscoped query or leaks whether a record exists for another user.
        - Non-existent records and other users' records both return the identical ProvenanceError.
        """
        if not principal_id:
            raise TaskOwnershipError("principal_id is required.")

        stmt = (
            select(ProvenanceRecord)
            .join(Task, ProvenanceRecord.task_id == Task.task_id)
            .where(
                ProvenanceRecord.source_id == source_id,
                Task.principal_id == principal_id,
            )
        )
        record = db.execute(stmt).scalar_one_or_none()
        if record is None:
            raise ProvenanceError(f"Provenance record with source_id {source_id!r} not found.")

        return ProvenanceRecordDTO.from_orm(record)

    @staticmethod
    def list_provenance_for_task(
        db: Session,
        task_id: str,
        principal_id: str,
    ) -> List[ProvenanceRecordDTO]:
        """
        List all provenance records for a task, verifying that principal_id owns the task.

        Raises:
        - TaskNotFoundError: If the task does not exist.
        - TaskOwnershipError: If the task is owned by another principal.
        """
        task = db.get(Task, task_id)
        if task is None:
            raise TaskNotFoundError(f"Task with id {task_id!r} not found.")

        if task.principal_id != principal_id:
            raise TaskOwnershipError(
                f"Principal {principal_id!r} does not own task {task_id!r}."
            )

        stmt = (
            select(ProvenanceRecord)
            .where(ProvenanceRecord.task_id == task_id)
            .order_by(ProvenanceRecord.created_at.asc())
        )
        records = db.execute(stmt).scalars().all()
        return [ProvenanceRecordDTO.from_orm(r) for r in records]

    @staticmethod
    def _get_provenance_unscoped(
        db: Session,
        source_id: str,
    ) -> Optional[ProvenanceRecordDTO]:
        """
        Private unscoped retrieval for internal subsystem use (e.g. gateway security audit).
        NEVER expose to public agent interfaces or end-user endpoints.
        """
        record = db.get(ProvenanceRecord, source_id)
        if record is None:
            return None
        return ProvenanceRecordDTO.from_orm(record)
