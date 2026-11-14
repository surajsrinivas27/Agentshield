"""
Tests for Task Repository — AgentShield
Verifies task creation, manifest cryptographic binding, timestamp normalization,
principal scoping, and atomic state transitions.
"""

import threading
import uuid
from datetime import datetime, timezone, timedelta
import pytest

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
)
from backend.agent.task_repository import TaskRepository
from backend.authorization.models import User, ROLE_EMPLOYEE
from tests.agent.conftest import create_signed_manifest


class TestTaskRepositoryCreation:

    def test_create_task_success(self, session, test_user):
        """Task created with valid signed manifest and matching parameters."""
        task_id = str(uuid.uuid4())
        expiry = datetime.now(timezone.utc) + timedelta(hours=2)
        manifest = create_signed_manifest(task_id, test_user.id, expires_at=expiry)

        ctx = TaskRepository.create_task(
            db=session,
            principal_id=test_user.id,
            task_type="summarize_email",
            capability_manifest=manifest,
            resource_ids=["EMAIL_001", "EMAIL_002"],
            allowed_operations=["read", "summarize"],
            permitted_recipients=["auditor@example.com"],
            expires_at=expiry,
            task_id=task_id,
        )

        assert ctx.task_id == task_id
        assert ctx.principal_id == test_user.id
        assert ctx.status == TASK_STATUS_ACTIVE
        assert ctx.is_active() is True
        assert ctx.capability_manifest.manifest_signature == manifest["manifest_signature"]

    def test_create_task_equivalent_utc_timestamp_representations(self, session, test_user):
        """
        Manifest signed with an offset timestamp (e.g. +05:30) must match a task
        provided with equivalent UTC instant.
        """
        task_id = str(uuid.uuid4())
        # Base UTC time: 2026-11-14 10:00:00 UTC
        base_utc = datetime(2026, 11, 14, 10, 0, 0, tzinfo=timezone.utc)
        # Offset time: 2026-11-14 15:30:00 +05:30 (identical instant)
        offset_tz = timezone(timedelta(hours=5, minutes=30))
        offset_dt = base_utc.astimezone(offset_tz)

        # Manifest created with offset timestamp string
        manifest = create_signed_manifest(task_id, test_user.id, expires_at=offset_dt)

        ctx = TaskRepository.create_task(
            db=session,
            principal_id=test_user.id,
            task_type="summarize_email",
            capability_manifest=manifest,
            resource_ids=["EMAIL_001", "EMAIL_002"],
            allowed_operations=["read", "summarize"],
            permitted_recipients=["auditor@example.com"],
            expires_at=base_utc,  # Passed in UTC
            task_id=task_id,
        )
        assert ctx.expires_at == base_utc

    def test_create_task_tampered_manifest_rejected(self, session, test_user):
        """Altering manifest operations after signing must fail HMAC verification."""
        task_id = str(uuid.uuid4())
        expiry = datetime.now(timezone.utc) + timedelta(hours=2)
        manifest = create_signed_manifest(task_id, test_user.id, expires_at=expiry)

        # Attacker injects extra operation into manifest payload without re-signing
        manifest["allowed_operations"].append("delete_database")

        with pytest.raises(ManifestVerificationError) as exc_info:
            TaskRepository.create_task(
                db=session,
                principal_id=test_user.id,
                task_type="summarize_email",
                capability_manifest=manifest,
                resource_ids=["EMAIL_001", "EMAIL_002"],
                allowed_operations=["read", "summarize", "delete_database"],
                permitted_recipients=["auditor@example.com"],
                expires_at=expiry,
                task_id=task_id,
            )
        assert "HMAC-SHA256 signature verification failed" in str(exc_info.value)

    def test_create_task_mismatched_principal_rejected(self, session, test_user, other_user):
        """Manifest user_id mismatch with principal_id raises ManifestVerificationError."""
        task_id = str(uuid.uuid4())
        expiry = datetime.now(timezone.utc) + timedelta(hours=2)
        # Signed for other_user
        manifest = create_signed_manifest(task_id, other_user.id, expires_at=expiry)

        with pytest.raises(ManifestVerificationError) as exc_info:
            TaskRepository.create_task(
                db=session,
                principal_id=test_user.id,  # Attempt to create under test_user
                task_type="summarize_email",
                capability_manifest=manifest,
                resource_ids=["EMAIL_001", "EMAIL_002"],
                allowed_operations=["read", "summarize"],
                permitted_recipients=["auditor@example.com"],
                expires_at=expiry,
                task_id=task_id,
            )
        assert "Manifest user_id" in str(exc_info.value)

    def test_create_task_mismatched_task_type_rejected(self, session, test_user):
        """Manifest task_type mismatch with requested task_type raises ManifestVerificationError."""
        task_id = str(uuid.uuid4())
        expiry = datetime.now(timezone.utc) + timedelta(hours=2)
        manifest = create_signed_manifest(task_id, test_user.id, task_type="read_document", expires_at=expiry)

        with pytest.raises(ManifestVerificationError) as exc_info:
            TaskRepository.create_task(
                db=session,
                principal_id=test_user.id,
                task_type="forward_email",  # Different from manifest
                capability_manifest=manifest,
                resource_ids=["EMAIL_001", "EMAIL_002"],
                allowed_operations=["read", "summarize"],
                permitted_recipients=["auditor@example.com"],
                expires_at=expiry,
                task_id=task_id,
            )
        assert "Manifest task_type" in str(exc_info.value)

    def test_create_task_duplicate_permissions_rejected(self, session, test_user):
        """Duplicate permissions in allowed_operations are rejected."""
        task_id = str(uuid.uuid4())
        expiry = datetime.now(timezone.utc) + timedelta(hours=2)
        manifest = create_signed_manifest(task_id, test_user.id, expires_at=expiry)

        with pytest.raises(ManifestVerificationError) as exc_info:
            TaskRepository.create_task(
                db=session,
                principal_id=test_user.id,
                task_type="summarize_email",
                capability_manifest=manifest,
                resource_ids=["EMAIL_001", "EMAIL_002"],
                allowed_operations=["read", "read"],  # Duplicate!
                permitted_recipients=["auditor@example.com"],
                expires_at=expiry,
                task_id=task_id,
            )
        assert "Duplicate entries not permitted" in str(exc_info.value)

    def test_create_task_expired_rejected(self, session, test_user):
        """Attempting to create a task with an expired timestamp raises ManifestVerificationError."""
        task_id = str(uuid.uuid4())
        past_expiry = datetime.now(timezone.utc) - timedelta(minutes=10)
        manifest = create_signed_manifest(task_id, test_user.id, expires_at=past_expiry)

        with pytest.raises(ManifestVerificationError) as exc_info:
            TaskRepository.create_task(
                db=session,
                principal_id=test_user.id,
                task_type="summarize_email",
                capability_manifest=manifest,
                resource_ids=["EMAIL_001", "EMAIL_002"],
                allowed_operations=["read", "summarize"],
                permitted_recipients=["auditor@example.com"],
                expires_at=past_expiry,
                task_id=task_id,
            )
        assert "expired" in str(exc_info.value)

    def test_create_task_inactive_principal_rejected(self, session):
        """Suspended/inactive user cannot create tasks."""
        suspended_uid = str(uuid.uuid4())
        suspended_user = User(
            id=suspended_uid,
            username=f"suspended_{suspended_uid[:8]}",
            password_hash="$argon2id$placeholder",
            role=ROLE_EMPLOYEE,
            is_active=False,  # Suspended!
        )
        session.add(suspended_user)
        session.flush()

        task_id = str(uuid.uuid4())
        expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        manifest = create_signed_manifest(task_id, suspended_uid, expires_at=expiry)

        with pytest.raises(TaskOwnershipError) as exc_info:
            TaskRepository.create_task(
                db=session,
                principal_id=suspended_uid,
                task_type="summarize_email",
                capability_manifest=manifest,
                resource_ids=["EMAIL_001", "EMAIL_002"],
                allowed_operations=["read", "summarize"],
                permitted_recipients=["auditor@example.com"],
                expires_at=expiry,
                task_id=task_id,
            )
        assert "inactive or suspended" in str(exc_info.value)


class TestTaskRepositoryRetrievalAndStatus:

    def test_get_task_ownership_enforced(self, session, test_user, other_user):
        """Principal A cannot retrieve Principal B's task; raises TaskOwnershipError."""
        task_id = str(uuid.uuid4())
        expiry = datetime.now(timezone.utc) + timedelta(hours=2)
        manifest = create_signed_manifest(
            task_id,
            test_user.id,
            allowed_operations=("read",),
            allowed_resource_ids=("EMAIL_001",),
            permitted_recipients=("auditor@example.com",),
            expires_at=expiry,
        )

        TaskRepository.create_task(
            db=session,
            principal_id=test_user.id,
            task_type="summarize_email",
            capability_manifest=manifest,
            resource_ids=["EMAIL_001"],
            allowed_operations=["read"],
            permitted_recipients=["auditor@example.com"],
            expires_at=expiry,
            task_id=task_id,
        )

        # Owner succeeds
        ctx = TaskRepository.get_task(session, task_id, principal_id=test_user.id)
        assert ctx.task_id == task_id

        # Other user fails
        with pytest.raises(TaskOwnershipError) as exc_info:
            TaskRepository.get_task(session, task_id, principal_id=other_user.id)
        assert "does not own task" in str(exc_info.value)

    def test_list_tasks_scoped_to_principal(self, session, test_user, other_user):
        """list_tasks strictly returns tasks belonging to requesting principal."""
        t1_id = str(uuid.uuid4())
        exp = datetime.now(timezone.utc) + timedelta(hours=2)
        m1 = create_signed_manifest(
            t1_id,
            test_user.id,
            allowed_operations=("read",),
            allowed_resource_ids=("RES_1",),
            permitted_recipients=(),
            expires_at=exp,
        )
        TaskRepository.create_task(
            session, test_user.id, "summarize_email", m1, ["RES_1"], ["read"], [], exp, t1_id
        )

        t2_id = str(uuid.uuid4())
        m2 = create_signed_manifest(
            t2_id,
            other_user.id,
            allowed_operations=("read",),
            allowed_resource_ids=("RES_1",),
            permitted_recipients=(),
            expires_at=exp,
        )
        TaskRepository.create_task(
            session, other_user.id, "summarize_email", m2, ["RES_1"], ["read"], [], exp, t2_id
        )

        user1_tasks = TaskRepository.list_tasks(session, principal_id=test_user.id)
        assert len(user1_tasks) == 1
        assert user1_tasks[0].task_id == t1_id

        user2_tasks = TaskRepository.list_tasks(session, principal_id=other_user.id)
        assert len(user2_tasks) == 1
        assert user2_tasks[0].task_id == t2_id

    def test_task_status_valid_transitions(self, session, test_user):
        """Clean session: ACTIVE -> COMPLETED succeeds."""
        task_id = str(uuid.uuid4())
        expiry = datetime.now(timezone.utc) + timedelta(hours=2)
        manifest = create_signed_manifest(
            task_id,
            test_user.id,
            allowed_operations=("read",),
            allowed_resource_ids=("RES_1",),
            permitted_recipients=(),
            expires_at=expiry,
        )

        TaskRepository.create_task(
            session, test_user.id, "summarize_email", manifest, ["RES_1"], ["read"], [], expiry, task_id
        )
        session.commit()

        updated = TaskRepository.update_task_status(
            session, task_id, principal_id=test_user.id, new_status=TASK_STATUS_COMPLETED
        )
        assert updated.status == TASK_STATUS_COMPLETED

    def test_task_status_active_transaction_rejected(self, session, test_user):
        """
        A session with an already-active transaction is rejected with TaskTransactionError.
        Guarantees update_task_status cannot run without exclusive write lock.
        """
        task_id = str(uuid.uuid4())
        expiry = datetime.now(timezone.utc) + timedelta(hours=2)
        manifest = create_signed_manifest(
            task_id,
            test_user.id,
            allowed_operations=("read",),
            allowed_resource_ids=("RES_1",),
            permitted_recipients=(),
            expires_at=expiry,
        )

        TaskRepository.create_task(
            session, test_user.id, "summarize_email", manifest, ["RES_1"], ["read"], [], expiry, task_id
        )
        session.commit()

        # Intentionally start a transaction on this session
        from sqlalchemy import text
        session.execute(text("SELECT 1"))
        assert session.in_transaction() is True

        with pytest.raises(TaskTransactionError) as exc_info:
            TaskRepository.update_task_status(
                session, task_id, principal_id=test_user.id, new_status=TASK_STATUS_COMPLETED
            )
        assert "an active transaction is already in progress" in str(exc_info.value)
        session.rollback()

    def test_task_status_terminal_states_cannot_reopen(self, session, test_user):
        """Terminal tasks (COMPLETED, CANCELLED, FAILED) cannot be reopened."""
        user_id = test_user.id
        task_id = str(uuid.uuid4())
        expiry = datetime.now(timezone.utc) + timedelta(hours=2)
        manifest = create_signed_manifest(
            task_id,
            user_id,
            allowed_operations=("read",),
            allowed_resource_ids=("RES_1",),
            permitted_recipients=(),
            expires_at=expiry,
        )

        TaskRepository.create_task(
            session, user_id, "summarize_email", manifest, ["RES_1"], ["read"], [], expiry, task_id
        )
        session.commit()
        TaskRepository.update_task_status(
            session, task_id, principal_id=user_id, new_status=TASK_STATUS_COMPLETED
        )

        # Attempt to transition COMPLETED -> ACTIVE
        with pytest.raises(InvalidTaskTransitionError) as exc_info:
            TaskRepository.update_task_status(
                session, task_id, principal_id=user_id, new_status=TASK_STATUS_ACTIVE
            )
        assert "Cannot update terminal task" in str(exc_info.value)

        # Attempt to transition COMPLETED -> CANCELLED
        with pytest.raises(InvalidTaskTransitionError):
            TaskRepository.update_task_status(
                session, task_id, principal_id=user_id, new_status=TASK_STATUS_CANCELLED
            )

    def test_task_status_rollback_and_session_recovery(self, session, test_user):
        """
        A rejected operation cleanly rolls back and leaves the session reusable
        for subsequent valid operations.
        """
        user_id = test_user.id
        task_id = str(uuid.uuid4())
        expiry = datetime.now(timezone.utc) + timedelta(hours=2)
        manifest = create_signed_manifest(
            task_id,
            user_id,
            allowed_operations=("read",),
            allowed_resource_ids=("RES_1",),
            permitted_recipients=(),
            expires_at=expiry,
        )

        TaskRepository.create_task(
            session, user_id, "summarize_email", manifest, ["RES_1"], ["read"], [], expiry, task_id
        )
        session.commit()

        # 1. Attempt illegal transition (e.g. to unrecognized or self transition)
        with pytest.raises(InvalidTaskTransitionError):
            TaskRepository.update_task_status(
                session, task_id, principal_id=user_id, new_status=TASK_STATUS_ACTIVE
            )

        # 2. Verify session is clean and not stuck in a transaction
        assert session.in_transaction() is False

        # 3. Subsequent valid transition succeeds cleanly
        recovered = TaskRepository.update_task_status(
            session, task_id, principal_id=user_id, new_status=TASK_STATUS_COMPLETED
        )
        assert recovered.status == TASK_STATUS_COMPLETED
        assert session.in_transaction() is False


class TestTaskRepositoryConcurrency:

    def test_concurrent_task_status_updates(self):
        """
        Simulates two concurrent attempts to transition an ACTIVE task to terminal states.
        Uses a file-backed SQLite database with WAL mode to allow true multi-connection concurrency.
        Exactly one transition must succeed; the other must raise InvalidTaskTransitionError.
        """
        import os
        import tempfile
        from sqlalchemy import create_engine, event
        from sqlalchemy.orm import sessionmaker
        from backend.common.database import Base

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_db = f.name

        try:
            eng = create_engine(
                f"sqlite:///{temp_db}",
                connect_args={"check_same_thread": False},
                future=True,
            )

            @event.listens_for(eng, "connect")
            def _setup(conn, _):
                c = conn.cursor()
                c.execute("PRAGMA foreign_keys = ON;")
                c.execute("PRAGMA journal_mode = WAL;")
                c.execute("PRAGMA busy_timeout = 5000;")
                c.close()

            Base.metadata.create_all(bind=eng)
            sf = sessionmaker(autocommit=False, autoflush=False, bind=eng, future=True)

            # Setup user and task
            init_session = sf()
            uid = str(uuid.uuid4())
            user = User(
                id=uid,
                username=f"concurrent_user_{uid[:8]}",
                password_hash="$argon2id$mock",
                role=ROLE_EMPLOYEE,
                is_active=True,
            )
            init_session.add(user)
            init_session.flush()

            task_id = str(uuid.uuid4())
            expiry = datetime.now(timezone.utc) + timedelta(hours=2)
            manifest = create_signed_manifest(
                task_id,
                user.id,
                allowed_operations=("read",),
                allowed_resource_ids=("RES_1",),
                permitted_recipients=(),
                expires_at=expiry,
            )

            TaskRepository.create_task(
                init_session, user.id, "summarize_email", manifest, ["RES_1"], ["read"], [], expiry, task_id
            )
            init_session.commit()
            init_session.close()

            results = []
            errors = []

            def _worker(target_status):
                db = sf()
                try:
                    updated = TaskRepository.update_task_status(
                        db, task_id=task_id, principal_id=uid, new_status=target_status
                    )
                    db.commit()
                    results.append(updated.status)
                except Exception as e:
                    db.rollback()
                    errors.append(e)
                finally:
                    db.close()

            t1 = threading.Thread(target=_worker, args=(TASK_STATUS_COMPLETED,))
            t2 = threading.Thread(target=_worker, args=(TASK_STATUS_CANCELLED,))

            t1.start()
            t2.start()
            t1.join()
            t2.join()

            # Exactly one worker succeeded; the second worker saw terminal status and was rejected
            if errors and not results:
                pytest.fail(f"Workers failed with errors: {errors}")
            assert len(results) == 1
            assert len(errors) == 1
            assert isinstance(errors[0], InvalidTaskTransitionError)

        finally:
            eng.dispose()
            for ext in ["", "-wal", "-shm"]:
                p = temp_db + ext
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except OSError:
                        pass
