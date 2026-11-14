"""
Unit and Integration Tests for ProvenanceRepository (Stage 2)
Verifies:
- Scoped persistence and retrieval by principal_id.
- Automatic trust level derivation.
- Task status requirement (active tasks only).
- Cross-principal attachment and retrieval prevention.
- Foreign key retention (RESTRICT behavior).
- Persistence-boundary baseline taint enforcement.
- Direct repository adversarial attacks prevention.
"""

import uuid
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy.exc import IntegrityError

from backend.agent.dtos import (
    AuthenticatedUserContext,
    ProvenanceRecordDTO,
    ValidatedProvenancePayload,
)
from backend.agent.exceptions import (
    InvalidTaskTransitionError,
    ProvenanceError,
    TaskNotFoundError,
    TaskOwnershipError,
)
from backend.agent.hashing import hash_content
from backend.agent.models import (
    ORIGIN_EXTERNAL,
    ORIGIN_USER_PROVIDED,
    TAINT_UNTRUSTED_DATA,
    TASK_STATUS_COMPLETED,
    TRUST_TRUSTED,
    TRUST_UNTRUSTED,
    Task,
)
from backend.agent.provenance_repository import ProvenanceRepository
from backend.agent.task_repository import TaskRepository
from tests.agent.conftest import create_signed_manifest


@pytest.fixture
def active_task(session, test_user):
    """Fixture providing an active Task owned by test_user."""
    task_id = str(uuid.uuid4())
    expiry = datetime.now(timezone.utc) + timedelta(hours=2)
    manifest = create_signed_manifest(
        task_id,
        test_user.id,
        allowed_operations=("read",),
        allowed_resource_ids=("EMAIL_001",),
        permitted_recipients=(),
        expires_at=expiry,
    )
    task = TaskRepository.create_task(
        db=session,
        principal_id=test_user.id,
        task_type="summarize_email",
        capability_manifest=manifest,
        resource_ids=["EMAIL_001"],
        allowed_operations=["read"],
        permitted_recipients=[],
        expires_at=expiry,
        task_id=task_id,
    )
    session.commit()
    return task


class TestProvenanceRepositoryPersistence:

    def test_record_provenance_user_provided_clean(self, session, test_user, active_task):
        """User-provided content without taints derives TRUSTED status."""
        digest = hash_content("Clean user input prompt")
        auth_ctx = AuthenticatedUserContext.from_verified_session(db=session, session_user=test_user)
        payload = ValidatedProvenancePayload.create_user_input(
            auth_context=auth_ctx,
            task_id=active_task.task_id,
            content_hash=digest,
            origin="USER_PROMPT_1",
            taint_labels=[],
        )
        dto = ProvenanceRepository.record_provenance(
            db=session,
            payload=payload,
        )

        assert isinstance(dto, ProvenanceRecordDTO)
        assert dto.task_id == active_task.task_id
        assert dto.content_hash == digest
        assert dto.trust_level == TRUST_TRUSTED
        assert dto.is_trusted() is True
        assert dto.has_taint() is False
        assert dto.created_at.tzinfo == timezone.utc

    def test_record_provenance_external_derives_untrusted(self, session, test_user, active_task):
        """External content derives UNTRUSTED status and retains canonical taint."""
        digest = hash_content("Important incoming vendor email")
        payload = ValidatedProvenancePayload.create_external(
            task_id=active_task.task_id,
            principal_id=test_user.id,
            origin="EMAIL_001",
            source_type="email",
            content_hash=digest,
            taint_labels=[TAINT_UNTRUSTED_DATA],
        )
        dto = ProvenanceRepository.record_provenance(
            db=session,
            payload=payload,
        )

        assert dto.trust_level == TRUST_UNTRUSTED
        assert dto.is_trusted() is False
        assert dto.has_taint() is True
        assert TAINT_UNTRUSTED_DATA in dto.taint_labels

    def test_record_provenance_invalid_hash_rejected(self, session, test_user, active_task):
        """Invalid SHA-256 hash strings are rejected."""
        with pytest.raises(ProvenanceError) as exc_info:
            ValidatedProvenancePayload.create_external(
                task_id=active_task.task_id,
                principal_id=test_user.id,
                origin="EMAIL_001",
                source_type="email",
                content_hash="not_a_valid_sha256",
                taint_labels=[TAINT_UNTRUSTED_DATA],
            )
        assert "Invalid content_hash" in str(exc_info.value)

    def test_record_provenance_invalid_taint_rejected(self, session, test_user, active_task):
        """Non-canonical taint labels fail fast."""
        digest = hash_content("Sample text")
        with pytest.raises(ProvenanceError) as exc_info:
            ValidatedProvenancePayload.create_external(
                task_id=active_task.task_id,
                principal_id=test_user.id,
                origin="EMAIL_001",
                source_type="email",
                content_hash=digest,
                taint_labels=["UNRECOGNIZED_LABEL"],
            )
        assert "Invalid canonical taint label" in str(exc_info.value)

    def test_record_provenance_cannot_spoof_user_input_in_external_payload(
        self, session, test_user, active_task
    ):
        """
        Caller cannot label external content with user source types to bypass taint or gain TRUSTED status.
        """
        digest = hash_content("Malicious external input pretending to be user prompt")
        for bad_type in ("user_input", "user_prompt", "user_instruction", "user_message"):
            with pytest.raises(ProvenanceError) as exc:
                ValidatedProvenancePayload.create_external(
                    task_id=active_task.task_id,
                    principal_id=test_user.id,
                    origin="FAKE_USER_INPUT",
                    source_type=bad_type,
                    content_hash=digest,
                    taint_labels=[],
                )
            assert "Attempted to spoof external intake with user source_type" in str(exc.value)

    def test_external_content_with_empty_taints_receives_untrusted_data_at_persistence(
        self, session, test_user, active_task
    ):
        """
        Adversarial test: External content provided with empty taint labels is guaranteed
        to receive TAINT_UNTRUSTED_DATA inside the persistence boundary and derive TRUST_UNTRUSTED.
        """
        digest = hash_content("External data with empty taint argument")
        payload = ValidatedProvenancePayload.create_external(
            task_id=active_task.task_id,
            principal_id=test_user.id,
            origin="DOC_001",
            source_type="document",
            content_hash=digest,
            taint_labels=[],  # Caller passed empty taints
        )
        # Payload and persistence layer both enforce TAINT_UNTRUSTED_DATA
        dto = ProvenanceRepository.record_provenance(session, payload)
        assert dto.trust_level == TRUST_UNTRUSTED
        assert dto.is_trusted() is False
        assert dto.has_taint(TAINT_UNTRUSTED_DATA) is True
        assert dto.source_origin == ORIGIN_EXTERNAL

    def test_direct_record_provenance_rejects_non_payload_arguments(
        self, session, test_user, active_task
    ):
        """
        Adversarial test: A caller attempting to pass raw arguments or dictionary to
        record_provenance() is rejected with TypeError.
        """
        with pytest.raises(TypeError) as exc:
            ProvenanceRepository.record_provenance(
                session,
                {"task_id": active_task.task_id, "principal_id": test_user.id},  # type: ignore
            )
        assert "record_provenance requires a ValidatedProvenancePayload instance" in str(exc.value)

    def test_direct_payload_construction_without_intake_authorization_rejected(
        self, session, test_user, active_task
    ):
        """
        Adversarial test: Direct instantiation of ValidatedProvenancePayload bypassing
        trusted factory methods is rejected with ProvenanceError.
        """
        digest = hash_content("Attempted bypass")
        with pytest.raises(ProvenanceError) as exc:
            ValidatedProvenancePayload(
                task_id=active_task.task_id,
                principal_id=test_user.id,
                origin="HACK_ORIGIN",
                source_type="user_input",
                source_origin=ORIGIN_USER_PROVIDED,
                content_hash=digest,
                taint_labels=(),
            )
        assert "Direct construction of ValidatedProvenancePayload is restricted" in str(exc.value)

    def test_unauthenticated_caller_cannot_construct_user_provided_payload(
        self, session, test_user, active_task
    ):
        """
        Adversarial test: Unauthenticated context cannot construct a USER_PROVIDED payload.
        """
        digest = hash_content("Attempted unauthenticated payload")
        unauth_ctx = AuthenticatedUserContext(user_id=test_user.id)
        with pytest.raises(ProvenanceError) as exc:
            ValidatedProvenancePayload.create_user_input(
                auth_context=unauth_ctx,
                task_id=active_task.task_id,
                content_hash=digest,
                origin="PROMPT",
            )
        assert "Unauthenticated caller cannot construct USER_PROVIDED provenance payload" in str(exc.value)

    def test_user_provided_payload_cannot_carry_untrusted_data_taint(
        self, session, test_user, active_task
    ):
        """USER_PROVIDED payload rejects UNTRUSTED_DATA taint."""
        digest = hash_content("Tainted user prompt")
        auth_ctx = AuthenticatedUserContext.from_verified_session(db=session, session_user=test_user)
        with pytest.raises(ProvenanceError) as exc:
            ValidatedProvenancePayload.create_user_input(
                auth_context=auth_ctx,
                task_id=active_task.task_id,
                content_hash=digest,
                origin="PROMPT",
                taint_labels=[TAINT_UNTRUSTED_DATA],
            )
        assert "USER_PROVIDED provenance cannot carry UNTRUSTED_DATA taint" in str(exc.value)

    def test_persisting_payload_created_via_model_construct_fails_at_persistence(
        self, session, test_user, active_task
    ):
        """
        Adversarial test: If an attacker attempts to bypass intake factories
        using model_construct or forged attribute tampering, ProvenanceRepository.record_provenance
        strictly rejects the payload at the persistence boundary.
        """
        digest = hash_content("Sneaky bypass attempt")
        # 1. model_construct is blocked on the DTO class
        with pytest.raises(ProvenanceError):
            ValidatedProvenancePayload.model_construct(
                task_id=active_task.task_id,
                principal_id=test_user.id,
                origin="SNEAKY",
                source_type="user_input",
                source_origin=ORIGIN_USER_PROVIDED,
                content_hash=digest,
                taint_labels=(),
            )

        # 2. Forged object instantiated via object.__new__ lacking valid cryptographic authorization
        fake_payload = object.__new__(ValidatedProvenancePayload)
        object.__setattr__(fake_payload, "task_id", active_task.task_id)
        object.__setattr__(fake_payload, "principal_id", test_user.id)
        object.__setattr__(fake_payload, "origin", "SNEAKY")
        object.__setattr__(fake_payload, "source_type", "user_input")
        object.__setattr__(fake_payload, "source_origin", ORIGIN_USER_PROVIDED)
        object.__setattr__(fake_payload, "content_hash", digest)
        object.__setattr__(fake_payload, "taint_labels", ())
        object.__setattr__(fake_payload, "source_id", None)
        object.__setattr__(fake_payload, "_intake_authorization", "forged_auth_signature_12345")

        with pytest.raises(ProvenanceError) as exc:
            ProvenanceRepository.record_provenance(db=session, payload=fake_payload)
        assert "lacks valid internal intake authorization" in str(exc.value)


class TestProvenanceRepositoryIsolation:

    def test_record_provenance_cross_principal_rejected(self, session, other_user, active_task):
        """Principal B cannot attach provenance to Principal A's task."""
        digest = hash_content("Attacker input")
        payload = ValidatedProvenancePayload.create_external(
            task_id=active_task.task_id,
            principal_id=other_user.id,  # Not the owner
            origin="ATTACK_1",
            source_type="email",
            content_hash=digest,
            taint_labels=[TAINT_UNTRUSTED_DATA],
        )
        with pytest.raises(TaskOwnershipError) as exc_info:
            ProvenanceRepository.record_provenance(
                db=session,
                payload=payload,
            )
        assert "does not own task" in str(exc_info.value)

    def test_record_provenance_nonexistent_task_rejected(self, session, test_user):
        """Non-existent task raises TaskNotFoundError."""
        digest = hash_content("Some content")
        payload = ValidatedProvenancePayload.create_external(
            task_id=str(uuid.uuid4()),
            principal_id=test_user.id,
            origin="SRC_1",
            source_type="email",
            content_hash=digest,
            taint_labels=[TAINT_UNTRUSTED_DATA],
        )
        with pytest.raises(TaskNotFoundError):
            ProvenanceRepository.record_provenance(
                db=session,
                payload=payload,
            )

    def test_record_provenance_terminal_task_rejected(self, session, test_user, active_task):
        """Cannot attach provenance to a COMPLETED or CANCELLED task."""
        TaskRepository.update_task_status(
            db=session,
            task_id=active_task.task_id,
            principal_id=test_user.id,
            new_status=TASK_STATUS_COMPLETED,
        )

        digest = hash_content("Late arriving data")
        payload = ValidatedProvenancePayload.create_external(
            task_id=active_task.task_id,
            principal_id=test_user.id,
            origin="LATE_EMAIL",
            source_type="email",
            content_hash=digest,
            taint_labels=[TAINT_UNTRUSTED_DATA],
        )
        with pytest.raises(InvalidTaskTransitionError) as exc_info:
            ProvenanceRepository.record_provenance(
                db=session,
                payload=payload,
            )
        assert "Cannot record provenance for task" in str(exc_info.value)

    def test_get_provenance_privacy_indistinguishable_from_not_found(
        self, session, test_user, other_user, active_task
    ):
        """
        Cross-principal provenance lookup returns the EXACT same ProvenanceError
        as a non-existent record, preventing user enumeration / oracle probing.
        """
        digest = hash_content("Confidential statement")
        payload = ValidatedProvenancePayload.create_external(
            task_id=active_task.task_id,
            principal_id=test_user.id,
            origin="SECRET_DOC",
            source_type="document",
            content_hash=digest,
            taint_labels=[TAINT_UNTRUSTED_DATA],
        )
        dto = ProvenanceRepository.record_provenance(
            db=session,
            payload=payload,
        )

        # 1. Owner succeeds
        retrieved = ProvenanceRepository.get_provenance(
            db=session,
            source_id=dto.source_id,
            principal_id=test_user.id,
        )
        assert retrieved.source_id == dto.source_id

        # 2. Non-owner lookup raises ProvenanceError (NOT TaskOwnershipError)
        with pytest.raises(ProvenanceError) as cross_exc:
            ProvenanceRepository.get_provenance(
                db=session,
                source_id=dto.source_id,
                principal_id=other_user.id,
            )

        # 3. Nonexistent ID raises ProvenanceError
        nonexistent_id = str(uuid.uuid4())
        with pytest.raises(ProvenanceError) as nonexist_exc:
            ProvenanceRepository.get_provenance(
                db=session,
                source_id=nonexistent_id,
                principal_id=other_user.id,
            )

        # Verify behavior and error message structure are completely indistinguishable
        assert type(cross_exc.value) is type(nonexist_exc.value)
        assert str(cross_exc.value) == f"Provenance record with source_id '{dto.source_id}' not found."
        assert str(nonexist_exc.value) == f"Provenance record with source_id '{nonexistent_id}' not found."

    def test_list_provenance_scoped_and_ordered(self, session, test_user, other_user, active_task):
        """list_provenance_for_task returns ordered records for owner; rejects non-owner."""
        d1 = hash_content("First message")
        d2 = hash_content("Second message")

        p1 = ValidatedProvenancePayload.create_external(
            task_id=active_task.task_id, principal_id=test_user.id, origin="M1", source_type="email",
            content_hash=d1, taint_labels=[TAINT_UNTRUSTED_DATA],
        )
        p2 = ValidatedProvenancePayload.create_external(
            task_id=active_task.task_id, principal_id=test_user.id, origin="M2", source_type="email",
            content_hash=d2, taint_labels=[TAINT_UNTRUSTED_DATA],
        )

        r1 = ProvenanceRepository.record_provenance(session, p1)
        r2 = ProvenanceRepository.record_provenance(session, p2)

        # Owner retrieves in order
        records = ProvenanceRepository.list_provenance_for_task(
            db=session,
            task_id=active_task.task_id,
            principal_id=test_user.id,
        )
        assert len(records) == 2
        assert records[0].source_id == r1.source_id
        assert records[1].source_id == r2.source_id

        # Non-owner is denied
        with pytest.raises(TaskOwnershipError):
            ProvenanceRepository.list_provenance_for_task(
                db=session,
                task_id=active_task.task_id,
                principal_id=other_user.id,
            )


class TestProvenanceRepositoryRetention:

    def test_foreign_key_restrict_prevents_task_deletion_with_provenance(
        self, session, test_user, active_task
    ):
        """
        Verify that deleting a Task with attached ProvenanceRecords fails due to RESTRICT.
        Provenance records cannot be orphaned or deleted via cascade.
        """
        digest = hash_content("Vital Audit Trail Item")
        payload = ValidatedProvenancePayload.create_external(
            task_id=active_task.task_id,
            principal_id=test_user.id,
            origin="AUDIT_LOG_01",
            source_type="document",
            content_hash=digest,
            taint_labels=[TAINT_UNTRUSTED_DATA],
        )
        ProvenanceRepository.record_provenance(
            db=session,
            payload=payload,
        )

        # Attempt to delete the task directly via ORM
        task_orm = session.get(Task, active_task.task_id)
        session.delete(task_orm)

        with pytest.raises(IntegrityError):
            session.flush()
        session.rollback()
