"""
Tests for Immutable DTOs — AgentShield
Verifies deep immutability, nested manifest protection, timezone validation, and ORM conversion.
"""

import copy
import uuid
from datetime import datetime, timezone, timedelta
import jwt
import pytest
from pydantic import ValidationError

from backend.authorization.models import User
from backend.common.security import create_access_token, get_jwt_secret_key
from backend.agent.dtos import (
    AuthenticatedUserContext,
    CapabilityManifestDTO,
    ProvenanceRecordDTO,
    TaskContext,
    UserAuthContext,
    ValidatedProvenancePayload,
)
from backend.agent.exceptions import ProvenanceError
from backend.agent.models import (
    Task,
    ProvenanceRecord,
    TASK_STATUS_ACTIVE,
    TASK_STATUS_COMPLETED,
    TRUST_TRUSTED,
    TRUST_UNTRUSTED,
    ORIGIN_EXTERNAL,
    TAINT_UNTRUSTED_DATA,
    TAINT_UNTRUSTED_INSTRUCTIONS,
)


def _make_manifest_dict(task_id: str, user_id: str) -> dict:
    return {
        "task_id": task_id,
        "user_id": user_id,
        "task_type": "test_type",
        "allowed_operations": ["read", "forward"],
        "allowed_resource_ids": ["RES_1", "RES_2"],
        "permitted_recipients": ["alice@example.com"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "manifest_signature": "aabbcc112233" * 4,
    }


class TestCapabilityManifestDTO:

    def test_deep_immutability(self):
        """CapabilityManifestDTO cannot have attributes reassigned."""
        manifest = CapabilityManifestDTO.from_dict(_make_manifest_dict("t1", "u1"))
        with pytest.raises(ValidationError):
            manifest.task_id = "new_task_id"  # type: ignore[misc]

        with pytest.raises(ValidationError):
            manifest.allowed_operations = ("write",)  # type: ignore[misc]

    def test_extra_fields_forbidden(self):
        """Extra fields in manifest constructor raise ValidationError."""
        raw = _make_manifest_dict("t1", "u1")
        raw["extra_unverified_field"] = "malicious"
        with pytest.raises(ValidationError):
            CapabilityManifestDTO(**raw)

    def test_from_dict_rejects_non_dict_input(self):
        """Passing non-dict/mapping to from_dict raises TypeError."""
        with pytest.raises(TypeError) as exc:
            CapabilityManifestDTO.from_dict("not_a_dict")  # type: ignore[arg-type]
        assert "must be a Mapping" in str(exc.value)

    def test_from_dict_rejects_non_string_scalar_fields(self):
        """Passing non-string scalars (int, list, bool) raises TypeError."""
        raw = _make_manifest_dict("t1", "u1")
        raw["task_id"] = 12345  # Not a string
        with pytest.raises(TypeError) as exc:
            CapabilityManifestDTO.from_dict(raw)
        assert "must be a non-empty string" in str(exc.value)

    def test_from_dict_rejects_missing_required_fields(self):
        """Missing required string fields raise ValueError."""
        raw = _make_manifest_dict("t1", "u1")
        del raw["expires_at"]
        with pytest.raises(ValueError) as exc:
            CapabilityManifestDTO.from_dict(raw)
        assert "Missing required manifest field" in str(exc.value)

    def test_from_dict_rejects_string_as_collection(self):
        """Passing a bare string instead of a sequence raises TypeError (prevents char-splitting)."""
        raw = _make_manifest_dict("t1", "u1")
        raw["allowed_operations"] = "read"  # String instead of list/tuple
        with pytest.raises(TypeError) as exc:
            CapabilityManifestDTO.from_dict(raw)
        assert "not a string or bytes" in str(exc.value)

    def test_from_dict_rejects_non_string_collection_elements(self):
        """Collections containing non-string items raise TypeError."""
        raw = _make_manifest_dict("t1", "u1")
        raw["allowed_operations"] = ["read", 123, None]
        with pytest.raises(TypeError) as exc:
            CapabilityManifestDTO.from_dict(raw)
        assert "must be a string" in str(exc.value)


class TestTaskContextDTO:

    def test_task_context_deep_immutability(self):
        """TaskContext top-level and nested attributes cannot be mutated."""
        t_id = str(uuid.uuid4())
        u_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        exp = now + timedelta(hours=1)
        manifest_dto = CapabilityManifestDTO.from_dict(_make_manifest_dict(t_id, u_id))

        ctx = TaskContext(
            task_id=t_id,
            principal_id=u_id,
            task_type="test_type",
            resource_ids=("RES_1",),
            allowed_operations=("read",),
            permitted_recipients=("alice@example.com",),
            created_at=now,
            expires_at=exp,
            status=TASK_STATUS_ACTIVE,
            capability_manifest=manifest_dto,
        )

        with pytest.raises(ValidationError):
            ctx.status = TASK_STATUS_COMPLETED  # type: ignore[misc]

        with pytest.raises(ValidationError):
            ctx.principal_id = "attacker"  # type: ignore[misc]

        with pytest.raises(ValidationError):
            ctx.capability_manifest.task_id = "tampered"  # type: ignore[misc]

    def test_task_context_naive_datetime_rejected(self):
        """Naive datetime in created_at or expires_at raises ValidationError."""
        t_id = str(uuid.uuid4())
        u_id = str(uuid.uuid4())
        manifest_dto = CapabilityManifestDTO.from_dict(_make_manifest_dict(t_id, u_id))

        with pytest.raises(ValidationError):
            TaskContext(
                task_id=t_id,
                principal_id=u_id,
                task_type="test_type",
                created_at=datetime.now(),  # naive!
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                status=TASK_STATUS_ACTIVE,
                capability_manifest=manifest_dto,
            )

    def test_task_context_helper_methods(self):
        """Test is_expired, is_active, allows_operation, allows_resource."""
        t_id = str(uuid.uuid4())
        u_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        future = now + timedelta(hours=2)
        past = now - timedelta(hours=1)
        manifest_dto = CapabilityManifestDTO.from_dict(_make_manifest_dict(t_id, u_id))

        active_ctx = TaskContext(
            task_id=t_id,
            principal_id=u_id,
            task_type="test_type",
            resource_ids=("RES_1",),
            allowed_operations=("read",),
            permitted_recipients=(),
            created_at=now,
            expires_at=future,
            status=TASK_STATUS_ACTIVE,
            capability_manifest=manifest_dto,
        )
        assert active_ctx.is_expired() is False
        assert active_ctx.is_active() is True
        assert active_ctx.allows_operation("read") is True
        assert active_ctx.allows_operation("delete") is False
        assert active_ctx.allows_resource("RES_1") is True
        assert active_ctx.allows_resource("RES_2") is False

        expired_ctx = TaskContext(
            task_id=t_id,
            principal_id=u_id,
            task_type="test_type",
            created_at=now - timedelta(hours=2),
            expires_at=past,
            status=TASK_STATUS_ACTIVE,
            capability_manifest=manifest_dto,
        )
        assert expired_ctx.is_expired() is True
        assert expired_ctx.is_active() is False

    def test_from_orm_decoupling(self):
        """TaskContext.from_orm creates an independent snapshot detached from ORM object."""
        t_id = str(uuid.uuid4())
        u_id = str(uuid.uuid4())
        manifest = _make_manifest_dict(t_id, u_id)
        now = datetime.now(timezone.utc)
        exp = now + timedelta(hours=1)

        task_orm = Task(
            task_id=t_id,
            principal_id=u_id,
            task_type="test_type",
            resource_ids=["RES_A"],
            allowed_operations=["read"],
            permitted_recipients=["alice@example.com"],
            created_at=now,
            expires_at=exp,
            status=TASK_STATUS_ACTIVE,
            capability_manifest=manifest,
        )

        dto = TaskContext.from_orm(task_orm)
        assert dto.task_id == t_id
        assert dto.resource_ids == ("RES_A",)

        # Modifying ORM object attributes does not affect DTO snapshot
        task_orm.status = TASK_STATUS_COMPLETED
        task_orm.resource_ids.append("RES_B")
        assert dto.status == TASK_STATUS_ACTIVE
        assert dto.resource_ids == ("RES_A",)


class TestProvenanceRecordDTO:

    def test_provenance_dto_immutability(self):
        """ProvenanceRecordDTO cannot be mutated."""
        now = datetime.now(timezone.utc)
        dto = ProvenanceRecordDTO(
            source_id="s1",
            task_id="t1",
            origin="EMAIL_001",
            source_type="email",
            source_origin=ORIGIN_EXTERNAL,
            trust_level=TRUST_UNTRUSTED,
            content_hash="a" * 64,
            taint_labels=(TAINT_UNTRUSTED_DATA,),
            created_at=now,
        )

        with pytest.raises(ValidationError):
            dto.trust_level = TRUST_TRUSTED  # type: ignore[misc]

    def test_provenance_dto_hash_validation(self):
        """Invalid content_hash format raises ValidationError."""
        now = datetime.now(timezone.utc)
        with pytest.raises(ValidationError):
            ProvenanceRecordDTO(
                source_id="s1",
                task_id="t1",
                origin="EMAIL_001",
                source_type="email",
                source_origin=ORIGIN_EXTERNAL,
                trust_level=TRUST_UNTRUSTED,
                content_hash="not_a_valid_hash",  # invalid
                taint_labels=(),
                created_at=now,
            )

    def test_provenance_dto_aliases(self):
        """Backward-compatibility aliases provenance_id and source_identifier."""
        now = datetime.now(timezone.utc)
        dto = ProvenanceRecordDTO(
            source_id="src_uuid_123",
            task_id="task_uuid_456",
            origin="DOC_REPORT_99",
            source_type="document",
            source_origin=ORIGIN_EXTERNAL,
            trust_level=TRUST_UNTRUSTED,
            content_hash="b" * 64,
            taint_labels=(TAINT_UNTRUSTED_DATA, TAINT_UNTRUSTED_INSTRUCTIONS),
            created_at=now,
        )
        assert dto.provenance_id == "src_uuid_123"
        assert dto.source_identifier == "DOC_REPORT_99"
        assert dto.is_trusted() is False
        assert dto.has_taint(TAINT_UNTRUSTED_DATA) is True
        assert dto.has_instruction_taint() is True


class TestAuthenticatedUserContext:

    def test_default_is_unauthenticated(self):
        """AuthenticatedUserContext defaults to is_authenticated=False and unauthenticated method."""
        ctx = AuthenticatedUserContext(user_id="user_123")
        assert ctx.user_id == "user_123"
        assert ctx.is_authenticated is False
        assert ctx.auth_method == "unauthenticated"
        assert ctx.is_verified() is False

    def test_direct_is_authenticated_true_rejected(self):
        """Setting is_authenticated=True directly without gateway verification is rejected."""
        with pytest.raises(ProvenanceError) as exc:
            AuthenticatedUserContext(user_id="victim_user", is_authenticated=True)
        assert "Cannot set is_authenticated=True without verified cryptographic authentication" in str(exc.value)

    def test_model_construct_forbidden(self):
        """Bypassing constructor via model_construct is strictly forbidden."""
        with pytest.raises(ProvenanceError) as exc:
            AuthenticatedUserContext.model_construct(user_id="victim_user", is_authenticated=True)
        assert "model_construct is forbidden" in str(exc.value)

    def test_model_copy_forbidden(self):
        """Bypassing immutability via model_copy is strictly forbidden."""
        ctx = AuthenticatedUserContext(user_id="user_123")
        with pytest.raises(ProvenanceError) as exc:
            ctx.model_copy(update={"is_authenticated": True})
        assert "model_copy is forbidden" in str(exc.value)

    def test_copy_and_deepcopy_forbidden(self):
        """Copying and deepcopying AuthenticatedUserContext are strictly forbidden."""
        ctx = AuthenticatedUserContext(user_id="user_123")
        with pytest.raises(ProvenanceError) as exc:
            copy.copy(ctx)
        assert "copy is forbidden" in str(exc.value)

        with pytest.raises(ProvenanceError) as exc:
            copy.deepcopy(ctx)
        assert "deepcopy is forbidden" in str(exc.value)

    def test_immutability(self):
        """AuthenticatedUserContext is frozen and cannot be mutated."""
        ctx = AuthenticatedUserContext(user_id="user_123")
        with pytest.raises(ValidationError):
            ctx.user_id = "user_456"  # type: ignore[misc]

    def test_empty_user_id_rejected(self):
        """Empty or whitespace user_id is rejected."""
        with pytest.raises(ValidationError):
            AuthenticatedUserContext(user_id="")
        with pytest.raises(ValidationError):
            AuthenticatedUserContext(user_id="   ")

    def test_extra_fields_forbidden(self):
        """Extra fields are strictly forbidden."""
        with pytest.raises(ValidationError):
            AuthenticatedUserContext(user_id="user_1", role="admin")  # type: ignore[call-arg]

    def test_bearer_token_factory_success(self, session, test_user):
        """Cryptographically verified JWT produces an authenticated and verified context."""
        token = create_access_token(subject=test_user.id, role="Employee")
        ctx = AuthenticatedUserContext.from_bearer_token(token, db=session)
        assert ctx.user_id == test_user.id
        assert ctx.is_authenticated is True
        assert ctx.is_verified() is True
        assert ctx.auth_method == "jwt_bearer"
        assert ctx.auth_time is not None

    def test_bearer_token_missing_db_rejected(self, test_user):
        """Bearer token verification fails closed if valid database session is omitted."""
        token = create_access_token(subject=test_user.id, role="Employee")
        with pytest.raises(ProvenanceError) as exc:
            AuthenticatedUserContext.from_bearer_token(token, db=None)  # type: ignore[arg-type]
        assert "Valid database session required" in str(exc.value)

        with pytest.raises(ProvenanceError) as exc2:
            AuthenticatedUserContext.from_bearer_token(token, db="not_a_session")  # type: ignore[arg-type]
        assert "Valid database session required" in str(exc2.value)

    def test_bearer_token_custom_signing_secret_rejected(self, session, test_user):
        """Token signed with caller-controlled custom secret is rejected."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": test_user.id,
            "role": "Employee",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "jti": str(uuid.uuid4()),
        }
        forged_token = jwt.encode(payload, "unauthorized_forged_secret_key_12345", algorithm="HS256")
        with pytest.raises(ProvenanceError) as exc:
            AuthenticatedUserContext.from_bearer_token(forged_token, db=session)
        assert "Authentication failed" in str(exc.value)

    def test_bearer_token_nonexistent_user_rejected(self, session):
        """Bearer token for a user that does not exist in DB is rejected."""
        fake_uid = str(uuid.uuid4())
        token = create_access_token(subject=fake_uid, role="Employee")
        with pytest.raises(ProvenanceError) as exc:
            AuthenticatedUserContext.from_bearer_token(token, db=session)
        assert f"User '{fake_uid}' not found in database" in str(exc.value)

    def test_bearer_token_inactive_user_rejected(self, session):
        """Bearer token for an inactive user is rejected."""
        uid = str(uuid.uuid4())
        inactive_user = User(
            id=uid,
            username=f"inactive_{uid[:8]}",
            password_hash="$argon2id$placeholder",
            role="Employee",
            is_active=False,
        )
        session.add(inactive_user)
        session.commit()

        token = create_access_token(subject=uid, role="Employee")
        with pytest.raises(ProvenanceError) as exc:
            AuthenticatedUserContext.from_bearer_token(token, db=session)
        assert f"User '{uid}' is inactive" in str(exc.value)

    def test_bearer_token_revoked_by_token_valid_after(self, session, test_user):
        """Token issued before user.token_valid_after is rejected as revoked."""
        token = create_access_token(subject=test_user.id, role="Employee")
        test_user.token_valid_after = datetime.now(timezone.utc) + timedelta(minutes=10)
        session.commit()

        with pytest.raises(ProvenanceError) as exc:
            AuthenticatedUserContext.from_bearer_token(token, db=session)
        assert "Token is revoked" in str(exc.value)

    def test_bearer_token_malformed_timestamps_and_missing_jti(self, session, test_user):
        """Tokens with invalid timestamps or missing jti fail verification."""
        secret = get_jwt_secret_key()
        now = datetime.now(timezone.utc)

        # 1. iat >= exp
        bad_time_payload = {
            "sub": test_user.id,
            "iat": int((now + timedelta(hours=2)).timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "jti": str(uuid.uuid4()),
        }
        bad_token = jwt.encode(bad_time_payload, secret, algorithm="HS256")
        with pytest.raises(ProvenanceError) as exc:
            AuthenticatedUserContext.from_bearer_token(bad_token, db=session)
        assert "Authentication failed" in str(exc.value)

        # 2. iat <= 0
        zero_iat_payload = {
            "sub": test_user.id,
            "iat": 0,
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "jti": str(uuid.uuid4()),
        }
        zero_iat_token = jwt.encode(zero_iat_payload, secret, algorithm="HS256")
        with pytest.raises(ProvenanceError) as exc:
            AuthenticatedUserContext.from_bearer_token(zero_iat_token, db=session)
        assert "Authentication failed" in str(exc.value)

        # 3. Missing jti
        missing_jti_payload = {
            "sub": test_user.id,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp()),
        }
        no_jti_token = jwt.encode(missing_jti_payload, secret, algorithm="HS256")
        with pytest.raises(ProvenanceError) as exc:
            AuthenticatedUserContext.from_bearer_token(no_jti_token, db=session)
        assert "Authentication failed" in str(exc.value)

    def test_bearer_token_invalid_string_rejected(self, session):
        """Malformed or non-JWT string fails closed."""
        with pytest.raises(ProvenanceError) as exc:
            AuthenticatedUserContext.from_bearer_token("not.a.valid.jwt", db=session)
        assert "Authentication failed" in str(exc.value)

    def test_verified_session_factory_success(self, session, test_user):
        """Persistent active User instance in session produces a verified context."""
        ctx = AuthenticatedUserContext.from_verified_session(db=session, session_user=test_user)
        assert ctx.user_id == test_user.id
        assert ctx.is_authenticated is True
        assert ctx.is_verified() is True
        assert ctx.auth_method == "session"
        assert ctx.auth_time is not None

    def test_verified_session_missing_db_rejected(self, test_user):
        """Verified session factory fails closed if db is None or not a Session."""
        with pytest.raises(ProvenanceError) as exc:
            AuthenticatedUserContext.from_verified_session(db=None, session_user=test_user)  # type: ignore[arg-type]
        assert "Valid database session required" in str(exc.value)

    def test_verified_session_manually_constructed_user_rejected(self, session):
        """Adversarial test: Transient/in-memory constructed User is rejected."""
        fake_user = User(
            id=str(uuid.uuid4()),
            username="fake_in_memory_user",
            password_hash="$argon2id$fake",
            role="Employee",
            is_active=True,
        )
        with pytest.raises(ProvenanceError) as exc:
            AuthenticatedUserContext.from_verified_session(db=session, session_user=fake_user)
        assert "Manually constructed, transient, or unattached User instance" in str(exc.value)

    def test_verified_session_inactive_user_rejected(self, session):
        """Persistent but inactive user in session is rejected."""
        uid = str(uuid.uuid4())
        inactive_user = User(
            id=uid,
            username=f"inactive_sess_{uid[:8]}",
            password_hash="$argon2id$placeholder",
            role="Employee",
            is_active=False,
        )
        session.add(inactive_user)
        session.commit()

        with pytest.raises(ProvenanceError) as exc:
            AuthenticatedUserContext.from_verified_session(db=session, session_user=inactive_user)
        assert f"User '{uid}' is inactive" in str(exc.value)


class TestValidatedProvenancePayloadDTO:

    def test_direct_instantiation_forbidden(self):
        """Direct instantiation without internal intake authorization is rejected."""
        with pytest.raises(ProvenanceError) as exc:
            ValidatedProvenancePayload(
                task_id="t1",
                principal_id="u1",
                origin="SRC",
                source_type="user_input",
                source_origin="USER_PROVIDED",
                content_hash="a" * 64,
                taint_labels=(),
            )
        assert "Direct construction of ValidatedProvenancePayload is restricted" in str(exc.value)

    def test_model_construct_forbidden(self):
        """Bypassing constructor via model_construct is strictly forbidden."""
        with pytest.raises(ProvenanceError) as exc:
            ValidatedProvenancePayload.model_construct(
                task_id="t1",
                principal_id="u1",
                origin="SRC",
                source_type="user_input",
                source_origin="USER_PROVIDED",
                content_hash="a" * 64,
                taint_labels=(),
            )
        assert "model_construct is forbidden" in str(exc.value)

    def test_model_copy_forbidden(self, session, test_user):
        """Bypassing immutability via model_copy is strictly forbidden."""
        auth_ctx = AuthenticatedUserContext.from_verified_session(db=session, session_user=test_user)
        payload = ValidatedProvenancePayload.create_user_input(
            auth_context=auth_ctx,
            task_id="task_1",
            content_hash="a" * 64,
            origin="PROMPT",
        )
        with pytest.raises(ProvenanceError) as exc:
            payload.model_copy(update={"origin": "HACKED"})
        assert "model_copy is forbidden" in str(exc.value)

    def test_copy_and_deepcopy_forbidden(self, session, test_user):
        """Copying and deepcopying ValidatedProvenancePayload are strictly forbidden."""
        auth_ctx = AuthenticatedUserContext.from_verified_session(db=session, session_user=test_user)
        payload = ValidatedProvenancePayload.create_user_input(
            auth_context=auth_ctx,
            task_id="task_1",
            content_hash="a" * 64,
            origin="PROMPT",
        )
        with pytest.raises(ProvenanceError) as exc:
            copy.copy(payload)
        assert "copy is forbidden" in str(exc.value)

        with pytest.raises(ProvenanceError) as exc:
            copy.deepcopy(payload)
        assert "deepcopy is forbidden" in str(exc.value)

    def test_unauthenticated_context_rejected_in_create_user_input(self):
        """Unauthenticated or unverified context cannot construct USER_PROVIDED payload."""
        unauth_ctx = AuthenticatedUserContext(user_id="user_123")
        with pytest.raises(ProvenanceError) as exc:
            ValidatedProvenancePayload.create_user_input(
                auth_context=unauth_ctx,
                task_id="task_1",
                content_hash="a" * 64,
                origin="PROMPT",
            )
        assert "Unauthenticated caller cannot construct USER_PROVIDED provenance payload" in str(exc.value)

    def test_create_user_input_factory_success(self, session, test_user):
        """ValidatedProvenancePayload created via verified context is authorized and frozen."""
        auth_ctx = AuthenticatedUserContext.from_verified_session(db=session, session_user=test_user)
        payload = ValidatedProvenancePayload.create_user_input(
            auth_context=auth_ctx,
            task_id="task_1",
            content_hash="a" * 64,
            origin="PROMPT",
        )
        assert payload.principal_id == test_user.id
        assert payload.source_origin == "USER_PROVIDED"
        assert payload.verify_intake_authorization() is True

        with pytest.raises(ValidationError):
            payload.origin = "MUTATED"  # type: ignore[misc]

    def test_create_external_factory_success(self):
        """ValidatedProvenancePayload created via create_external enforces baseline taint and is authorized."""
        payload = ValidatedProvenancePayload.create_external(
            task_id="task_2",
            principal_id="usr_123",
            content_hash="b" * 64,
            origin="EMAIL",
            source_type="email",
            taint_labels=(),
        )
        assert payload.source_origin == ORIGIN_EXTERNAL
        assert TAINT_UNTRUSTED_DATA in payload.taint_labels
        assert payload.verify_intake_authorization() is True

        with pytest.raises(ValidationError):
            payload.source_origin = "USER_PROVIDED"  # type: ignore[misc]

    def test_tampered_payload_fails_authorization(self, session, test_user):
        """Payload whose attributes are tampered with fails cryptographic authorization verification."""
        auth_ctx = AuthenticatedUserContext.from_verified_session(db=session, session_user=test_user)
        payload = ValidatedProvenancePayload.create_user_input(
            auth_context=auth_ctx,
            task_id="task_1",
            content_hash="a" * 64,
            origin="PROMPT",
        )
        assert payload.verify_intake_authorization() is True

        object.__setattr__(payload, "origin", "TAMPERED_ORIGIN")
        assert payload.verify_intake_authorization() is False
