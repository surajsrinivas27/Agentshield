"""
Stage 2 Cross-Task and Multi-Tenant Isolation Tests
Comprehensive test suite verifying security boundaries across tasks and principals:
- Cross-principal task access isolation.
- Cross-principal task status tampering prevention.
- Cross-principal provenance registration and retrieval denial.
- Cross-task provenance trail separation within the same tenant.
- Manifest forgery and tenant spoofing rejection.
"""

import uuid
from datetime import datetime, timezone, timedelta
import pytest

from backend.agent.dtos import AuthenticatedUserContext
from backend.agent.exceptions import (
    ManifestVerificationError,
    ProvenanceError,
    TaskNotFoundError,
    TaskOwnershipError,
)
from backend.agent.models import (
    ORIGIN_EXTERNAL,
    ORIGIN_USER_PROVIDED,
    TASK_STATUS_COMPLETED,
    TAINT_UNTRUSTED_DATA,
)
from backend.agent.provenance_registry import ProvenanceRegistry
from backend.agent.task_repository import TaskRepository
from tests.agent.conftest import create_signed_manifest


class TestMultiTenantTaskIsolation:

    def test_principal_cannot_access_other_principal_task(self, session, test_user, other_user):
        """Task created by test_user is inaccessible to other_user."""
        task_id = str(uuid.uuid4())
        expiry = datetime.now(timezone.utc) + timedelta(hours=2)
        manifest = create_signed_manifest(
            task_id,
            test_user.id,
            allowed_operations=("read",),
            allowed_resource_ids=("DOC_001",),
            permitted_recipients=(),
            expires_at=expiry,
        )

        TaskRepository.create_task(
            db=session,
            principal_id=test_user.id,
            task_type="summarize_email",
            capability_manifest=manifest,
            resource_ids=["DOC_001"],
            allowed_operations=["read"],
            permitted_recipients=[],
            expires_at=expiry,
            task_id=task_id,
        )

        # Owner can read
        task = TaskRepository.get_task(session, task_id, principal_id=test_user.id)
        assert task.task_id == task_id
        assert task.principal_id == test_user.id

        # Other user is strictly denied
        with pytest.raises(TaskOwnershipError) as exc_info:
            TaskRepository.get_task(session, task_id, principal_id=other_user.id)
        assert "does not own task" in str(exc_info.value)

    def test_task_listing_never_leaks_across_principals(self, session, test_user, other_user):
        """list_tasks strictly isolates task lists between principals."""
        exp = datetime.now(timezone.utc) + timedelta(hours=2)

        # Create 2 tasks for test_user
        for i in range(2):
            tid = str(uuid.uuid4())
            m = create_signed_manifest(
                tid, test_user.id, allowed_operations=("read",), allowed_resource_ids=(f"RES_{i}",),
                permitted_recipients=(), expires_at=exp,
            )
            TaskRepository.create_task(
                session, test_user.id, "summarize_email", m, [f"RES_{i}"], ["read"], [], exp, tid
            )

        # Create 1 task for other_user
        other_tid = str(uuid.uuid4())
        other_m = create_signed_manifest(
            other_tid, other_user.id, allowed_operations=("read",), allowed_resource_ids=("OTHER_RES",),
            permitted_recipients=(), expires_at=exp,
        )
        TaskRepository.create_task(
            session, other_user.id, "summarize_email", other_m, ["OTHER_RES"], ["read"], [], exp, other_tid
        )

        user1_tasks = TaskRepository.list_tasks(session, principal_id=test_user.id)
        assert len(user1_tasks) == 2
        assert all(t.principal_id == test_user.id for t in user1_tasks)

        user2_tasks = TaskRepository.list_tasks(session, principal_id=other_user.id)
        assert len(user2_tasks) == 1
        assert user2_tasks[0].task_id == other_tid
        assert user2_tasks[0].principal_id == other_user.id

    def test_principal_cannot_modify_other_principal_task_status(self, session, test_user, other_user):
        """Principal B cannot update or terminate Principal A's task."""
        task_id = str(uuid.uuid4())
        expiry = datetime.now(timezone.utc) + timedelta(hours=2)
        manifest = create_signed_manifest(
            task_id,
            test_user.id,
            allowed_operations=("read",),
            allowed_resource_ids=("DOC_001",),
            permitted_recipients=(),
            expires_at=expiry,
        )

        TaskRepository.create_task(
            session, test_user.id, "summarize_email", manifest, ["DOC_001"], ["read"], [], expiry, task_id
        )
        session.commit()

        # Attempt transition by other user
        with pytest.raises(TaskOwnershipError) as exc_info:
            TaskRepository.update_task_status(
                db=session,
                task_id=task_id,
                principal_id=other_user.id,
                new_status=TASK_STATUS_COMPLETED,
            )
        assert "does not own task" in str(exc_info.value)


class TestCrossTaskProvenanceIsolation:

    def test_cross_task_provenance_trails_remain_isolated_within_same_principal(
        self, session, test_user
    ):
        """
        Tasks belonging to the SAME principal do not leak provenance records
        to each other.
        """
        exp = datetime.now(timezone.utc) + timedelta(hours=2)

        # Task 1
        t1_id = str(uuid.uuid4())
        m1 = create_signed_manifest(
            t1_id, test_user.id, allowed_operations=("read",), allowed_resource_ids=("R1",),
            permitted_recipients=(), expires_at=exp,
        )
        TaskRepository.create_task(session, test_user.id, "summarize_email", m1, ["R1"], ["read"], [], exp, t1_id)

        # Task 2
        t2_id = str(uuid.uuid4())
        m2 = create_signed_manifest(
            t2_id, test_user.id, allowed_operations=("read",), allowed_resource_ids=("R2",),
            permitted_recipients=(), expires_at=exp,
        )
        TaskRepository.create_task(session, test_user.id, "summarize_email", m2, ["R2"], ["read"], [], exp, t2_id)

        # Record provenance on Task 1
        rec1 = ProvenanceRegistry.register_external_content(
            db=session,
            task_id=t1_id,
            principal_id=test_user.id,
            sanitized_content="Content exclusively for Task 1",
            origin="ORIGIN_T1",
            source_type="email",
        )

        # Record provenance on Task 2
        auth_ctx = AuthenticatedUserContext.from_verified_session(db=session, session_user=test_user)
        rec2 = ProvenanceRegistry.register_user_input(
            db=session,
            auth_context=auth_ctx,
            task_id=t2_id,
            sanitized_content="Content exclusively for Task 2",
            origin="ORIGIN_T2",
        )

        t1_prov = ProvenanceRegistry.get_task_provenance(session, t1_id, test_user.id)
        assert len(t1_prov) == 1
        assert t1_prov[0].source_id == rec1.source_id

        t2_prov = ProvenanceRegistry.get_task_provenance(session, t2_id, test_user.id)
        assert len(t2_prov) == 1
        assert t2_prov[0].source_id == rec2.source_id

    def test_principal_cannot_attach_provenance_to_other_principal_task(
        self, session, test_user, other_user
    ):
        """Cross-tenant provenance attachment is rejected with TaskOwnershipError."""
        task_id = str(uuid.uuid4())
        exp = datetime.now(timezone.utc) + timedelta(hours=2)
        manifest = create_signed_manifest(
            task_id, test_user.id, allowed_operations=("read",), allowed_resource_ids=("R1",),
            permitted_recipients=(), expires_at=exp,
        )
        TaskRepository.create_task(session, test_user.id, "summarize_email", manifest, ["R1"], ["read"], [], exp, task_id)

        with pytest.raises(TaskOwnershipError):
            ProvenanceRegistry.register_external_content(
                db=session,
                task_id=task_id,
                principal_id=other_user.id,
                sanitized_content="Injected cross-tenant data",
                origin="INJECTION",
                source_type="email",
            )

    def test_principal_cannot_read_other_principal_provenance_by_id(
        self, session, test_user, other_user
    ):
        """
        Cross-tenant provenance record lookup by source_id fails with ProvenanceError,
        indistinguishable from a non-existent record.
        """
        task_id = str(uuid.uuid4())
        exp = datetime.now(timezone.utc) + timedelta(hours=2)
        manifest = create_signed_manifest(
            task_id, test_user.id, allowed_operations=("read",), allowed_resource_ids=("R1",),
            permitted_recipients=(), expires_at=exp,
        )
        TaskRepository.create_task(session, test_user.id, "summarize_email", manifest, ["R1"], ["read"], [], exp, task_id)

        auth_ctx = AuthenticatedUserContext.from_verified_session(db=session, session_user=test_user)
        rec = ProvenanceRegistry.register_user_input(
            db=session,
            auth_context=auth_ctx,
            task_id=task_id,
            sanitized_content="Confidential financial report",
            origin="FIN_REPORT_01",
        )

        with pytest.raises(ProvenanceError) as exc:
            ProvenanceRegistry.get_record(session, rec.source_id, other_user.id)
        assert f"Provenance record with source_id '{rec.source_id}' not found." in str(exc.value)


class TestManifestCrossTenantForging:

    def test_cannot_spoof_principal_in_signed_manifest(self, session, test_user, other_user):
        """
        If an attacker attempts to use a manifest signed for another user,
        or modifies user_id without signature re-computation, task creation is rejected.
        """
        task_id = str(uuid.uuid4())
        exp = datetime.now(timezone.utc) + timedelta(hours=2)

        # Manifest legitimately signed for test_user
        valid_manifest = create_signed_manifest(
            task_id,
            test_user.id,
            allowed_operations=("read",),
            allowed_resource_ids=("RES_1",),
            permitted_recipients=(),
            expires_at=exp,
        )

        # other_user tries to create task using test_user's manifest
        with pytest.raises(ManifestVerificationError) as exc_info:
            TaskRepository.create_task(
                db=session,
                principal_id=other_user.id,
                task_type="summarize_email",
                capability_manifest=valid_manifest,
                resource_ids=["RES_1"],
                allowed_operations=["read"],
                permitted_recipients=[],
                expires_at=exp,
                task_id=task_id,
            )
        assert "Manifest user_id" in str(exc_info.value)

        # other_user tampers user_id in the payload to match their own ID
        tampered_manifest = dict(valid_manifest)
        tampered_manifest["user_id"] = other_user.id

        with pytest.raises(ManifestVerificationError) as exc_info:
            TaskRepository.create_task(
                db=session,
                principal_id=other_user.id,
                task_type="summarize_email",
                capability_manifest=tampered_manifest,
                resource_ids=["RES_1"],
                allowed_operations=["read"],
                permitted_recipients=[],
                expires_at=exp,
                task_id=task_id,
            )
        assert "HMAC-SHA256 signature verification failed" in str(exc_info.value)
