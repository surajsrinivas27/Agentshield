"""
Immutable Domain Transfer Objects (DTOs) — AgentShield

Provides deeply immutable, type-safe data snapshots for task context and provenance
tracking, completely decoupled from SQLAlchemy ORM session state.
"""

import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import Session

from backend.agent.exceptions import ProvenanceError
from backend.agent.hashing import is_valid_sha256_hex
from backend.agent.models import (
    ORIGIN_EXTERNAL,
    ORIGIN_USER_PROVIDED,
    TAINT_UNTRUSTED_DATA,
    TASK_STATUS_ACTIVE,
    TRUST_TRUSTED,
    TAINT_UNTRUSTED_INSTRUCTIONS,
    Task,
    ProvenanceRecord,
)
from backend.agent.taint import (
    USER_SOURCE_TYPES,
    validate_canonical_label,
)


def _ensure_utc(dt: datetime) -> datetime:
    """Ensure datetime is timezone-aware and normalized to UTC."""
    if not isinstance(dt, datetime):
        raise TypeError(f"Expected datetime, got {type(dt).__name__}")
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("Datetime must be timezone-aware with a valid UTC offset.")
    return dt.astimezone(timezone.utc)


class CapabilityManifestDTO(BaseModel):
    """
    Deeply immutable snapshot of a signed capability manifest.
    Contains verified permissions, parameters, and cryptographic signature.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: str
    user_id: str
    task_type: str
    allowed_operations: Tuple[str, ...] = Field(default_factory=tuple)
    allowed_resource_ids: Tuple[str, ...] = Field(default_factory=tuple)
    permitted_recipients: Tuple[str, ...] = Field(default_factory=tuple)
    expires_at: str
    manifest_signature: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CapabilityManifestDTO":
        """
        Create from raw dictionary with strict type validation.
        Rejects malformed collections and avoids unsafe string coercion.
        """
        if not isinstance(data, (dict, Mapping)):
            raise TypeError(f"Manifest data must be a Mapping, got {type(data).__name__}")

        required_string_fields = (
            "task_id",
            "user_id",
            "task_type",
            "expires_at",
            "manifest_signature",
        )
        for field in required_string_fields:
            if field not in data:
                raise ValueError(f"Missing required manifest field: {field!r}")
            val = data[field]
            if not isinstance(val, str) or not val.strip():
                raise TypeError(
                    f"Manifest field {field!r} must be a non-empty string, got {type(val).__name__}"
                )

        collection_fields = (
            "allowed_operations",
            "allowed_resource_ids",
            "permitted_recipients",
        )
        validated_collections = {}
        for col in collection_fields:
            val = data.get(col, ())
            if isinstance(val, (str, bytes)):
                raise TypeError(
                    f"Manifest field {col!r} must be a collection of strings, not a string or bytes."
                )
            if not isinstance(val, (list, tuple, set)):
                raise TypeError(
                    f"Manifest field {col!r} must be a collection of strings, got {type(val).__name__}"
                )
            for item in val:
                if not isinstance(item, str):
                    raise TypeError(
                        f"Every item in manifest field {col!r} must be a string, got {type(item).__name__}"
                    )
            validated_collections[col] = tuple(val)

        return cls(
            task_id=data["task_id"],
            user_id=data["user_id"],
            task_type=data["task_type"],
            allowed_operations=validated_collections["allowed_operations"],
            allowed_resource_ids=validated_collections["allowed_resource_ids"],
            permitted_recipients=validated_collections["permitted_recipients"],
            expires_at=data["expires_at"],
            manifest_signature=data["manifest_signature"],
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to regular dict for JSON serialization or cryptographic verification."""
        return {
            "task_id": self.task_id,
            "user_id": self.user_id,
            "task_type": self.task_type,
            "allowed_operations": list(self.allowed_operations),
            "allowed_resource_ids": list(self.allowed_resource_ids),
            "permitted_recipients": list(self.permitted_recipients),
            "expires_at": self.expires_at,
            "manifest_signature": self.manifest_signature,
        }


class TaskContext(BaseModel):
    """
    Deeply immutable domain snapshot representing the active security context of a Task.
    Decoupled from SQLAlchemy sessions; prevents in-memory caller tampering.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: str
    principal_id: str
    task_type: str
    resource_ids: Tuple[str, ...] = Field(default_factory=tuple)
    allowed_operations: Tuple[str, ...] = Field(default_factory=tuple)
    permitted_recipients: Tuple[str, ...] = Field(default_factory=tuple)
    created_at: datetime
    expires_at: datetime
    status: str
    capability_manifest: CapabilityManifestDTO

    @field_validator("created_at", "expires_at")
    @classmethod
    def validate_utc_datetime(cls, v: datetime) -> datetime:
        return _ensure_utc(v)

    @classmethod
    def from_orm(cls, task: Task) -> "TaskContext":
        """Construct an independent, detached DTO from a Task ORM model."""
        manifest_dto = CapabilityManifestDTO.from_dict(task.capability_manifest)
        return cls(
            task_id=task.task_id,
            principal_id=task.principal_id,
            task_type=task.task_type,
            resource_ids=tuple(task.resource_ids or ()),
            allowed_operations=tuple(task.allowed_operations or ()),
            permitted_recipients=tuple(task.permitted_recipients or ()),
            created_at=_ensure_utc(task.created_at),
            expires_at=_ensure_utc(task.expires_at),
            status=task.status,
            capability_manifest=manifest_dto,
        )

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """Return True if the task's capability has expired."""
        current = _ensure_utc(now) if now else datetime.now(timezone.utc)
        return current >= self.expires_at

    def is_active(self) -> bool:
        """Return True if task is currently ACTIVE and unexpired."""
        return self.status == TASK_STATUS_ACTIVE and not self.is_expired()

    def allows_operation(self, operation: str) -> bool:
        """Informational check whether operation is in allowed_operations."""
        return operation in self.allowed_operations

    def allows_resource(self, resource_id: str) -> bool:
        """Informational check whether resource is in resource_ids."""
        return resource_id in self.resource_ids


class ProvenanceRecordDTO(BaseModel):
    """
    Deeply immutable snapshot of a provenance record.
    Never stores or exposes raw content text; only the cryptographic content_hash.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: str
    task_id: str
    origin: str
    source_type: str
    source_origin: str
    trust_level: str
    content_hash: str
    taint_labels: Tuple[str, ...] = Field(default_factory=tuple)
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def validate_utc_created_at(cls, v: datetime) -> datetime:
        return _ensure_utc(v)

    @field_validator("content_hash")
    @classmethod
    def validate_hash_format(cls, v: str) -> str:
        if not is_valid_sha256_hex(v):
            raise ValueError(f"content_hash must be a valid 64-character lowercase hex string, got {v!r}")
        return v

    @property
    def provenance_id(self) -> str:
        """Backward-compatibility alias for source_id."""
        return self.source_id

    @property
    def source_identifier(self) -> str:
        """Backward-compatibility alias for origin."""
        return self.origin

    @classmethod
    def from_orm(cls, model: ProvenanceRecord) -> "ProvenanceRecordDTO":
        """Construct an independent, detached DTO from a ProvenanceRecord ORM model."""
        return cls(
            source_id=model.source_id,
            task_id=model.task_id,
            origin=model.origin,
            source_type=model.source_type,
            source_origin=model.source_origin,
            trust_level=model.trust_level,
            content_hash=model.content_hash,
            taint_labels=tuple(model.taint_labels or ()),
            created_at=_ensure_utc(model.created_at),
        )

    def is_trusted(self) -> bool:
        """Return True if the source has been evaluated as TRUSTED."""
        return self.trust_level == TRUST_TRUSTED

    def has_taint(self, label: Optional[str] = None) -> bool:
        """Check presence of a specific canonical taint label, or any taint if label is None."""
        if label is None:
            return len(self.taint_labels) > 0
        return label in self.taint_labels

    def has_instruction_taint(self) -> bool:
        """Check presence of TAINT_UNTRUSTED_INSTRUCTIONS."""
        return TAINT_UNTRUSTED_INSTRUCTIONS in self.taint_labels


# Module-private sentinel protecting AuthenticatedUserContext from unauthorized direct authentication
_AUTH_GATEWAY_TOKEN = object()


class AuthenticatedUserContext(BaseModel):
    """
    Immutable representation of an authenticated human user session context.

    TRUST BOUNDARY SPECIFICATION:
    This context MUST be created exclusively by the application gateway / session authentication
    layer upon verifying human credentials (signed JWT bearer tokens, active server-side sessions).

    AUTHENTICATION EVIDENCE GUARANTEES:
    - Default is_authenticated is FALSE. A Pydantic model or Boolean is NEVER treated as authentication evidence.
    - Attempting to construct AuthenticatedUserContext with is_authenticated=True directly is rejected.
    - Setting is_authenticated=True requires cryptographic verification through trusted factory methods:
      - AuthenticatedUserContext.from_bearer_token(token, db): Cryptographically verifies signed JWT and DB user.
      - AuthenticatedUserContext.from_verified_session(db, session_user): Verifies persistent DB session User.
    - Principal identity is derived directly from the verified authentication result (token 'sub' or session_user.id),
      NEVER from an arbitrary request field.

    INTEGRATION DEPENDENCY NOTE:
    In Stage 2, this DTO defines the trust-boundary contract between the authentication layer
    and the Agent provenance subsystem. The full session/gateway authentication layer is an
    explicit integration dependency to be delivered in subsequent application stages.
    Presence of the JWT 'jti' claim alone is not proof that the token has not been revoked (requires
    revocation checking in Stage 3). Regex and structural inspection (detect_external_content_indicators)
    acts as defense-in-depth, not absolute cryptographic proof of human origin.
    Unverified inputs remain untrusted by default.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    user_id: str
    is_authenticated: bool = False
    auth_method: str = "unauthenticated"
    auth_time: Optional[datetime] = None
    _gateway_token: Any = PrivateAttr(default=None)

    def __init__(self, **data: Any):
        token = data.pop("_gateway_token", None)
        super().__init__(**data)
        object.__setattr__(self, "_gateway_token", token)
        if self.is_authenticated and self._gateway_token is not _AUTH_GATEWAY_TOKEN:
            raise ProvenanceError(
                "Security violation: Cannot set is_authenticated=True without verified "
                "cryptographic authentication. Use an authenticated gateway factory."
            )

    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> Any:
        raise ProvenanceError("Security violation: model_construct is forbidden on AuthenticatedUserContext.")

    def model_copy(self, *args: Any, **kwargs: Any) -> Any:
        raise ProvenanceError("Security violation: model_copy is forbidden on AuthenticatedUserContext.")

    def __copy__(self) -> Any:
        raise ProvenanceError("Security violation: copy is forbidden on AuthenticatedUserContext.")

    def __deepcopy__(self, memo: Any) -> Any:
        raise ProvenanceError("Security violation: deepcopy is forbidden on AuthenticatedUserContext.")

    def is_verified(self) -> bool:
        """
        Return True only if the context has been cryptographically verified by the gateway.
        Guarantees that a caller cannot promote content by forging boolean attributes.
        """
        return self.is_authenticated and (self._gateway_token is _AUTH_GATEWAY_TOKEN)

    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, v: str) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("user_id must be a non-empty string.")
        return v.strip()

    @field_validator("auth_time")
    @classmethod
    def validate_auth_time(cls, v: Optional[datetime]) -> Optional[datetime]:
        if v is not None:
            return _ensure_utc(v)
        return v

    @classmethod
    def from_bearer_token(
        cls,
        token: str,
        db: Session,
    ) -> "AuthenticatedUserContext":
        """
        Authenticate a human user via signed Bearer JWT using application security configuration.

        INVARIANTS & VERIFICATION:
        - Uses strictly application-managed JWT configuration (no caller-supplied secret keys).
        - Cryptographically decodes and verifies JWT signature and expiration.
        - Validates all required claims (sub, exp, iat, jti) and rejects malformed/invalid timestamps.
        - Requires a valid database session; verifies user exists in DB and is_active is True.
        - Validates User.token_valid_after against the JWT iat claim.
        - Fails closed on missing, malformed, expired, revoked, or tampered tokens.
        """
        from backend.authorization.models import User
        from backend.common.security import decode_access_token

        if db is None or not isinstance(db, Session):
            raise ProvenanceError("Authentication failed: Valid database session required for Bearer token verification.")

        if not token or not isinstance(token, str):
            raise ProvenanceError("Authentication failed: Bearer token is missing or invalid.")

        try:
            claims = decode_access_token(token)
        except Exception as e:
            raise ProvenanceError(f"Authentication failed: Invalid or expired Bearer token: {e}")

        user_id = claims.get("sub")
        if not user_id or not isinstance(user_id, str):
            raise ProvenanceError("Authentication failed: Token missing valid subject claim.")

        iat = claims.get("iat")
        exp = claims.get("exp")
        jti = claims.get("jti")

        if not isinstance(iat, (int, float)) or iat <= 0:
            raise ProvenanceError("Authentication failed: Token missing or invalid iat claim.")
        if not isinstance(exp, (int, float)) or exp <= iat:
            raise ProvenanceError("Authentication failed: Token missing or invalid exp claim.")
        if not jti or not isinstance(jti, str):
            raise ProvenanceError("Authentication failed: Token missing valid jti claim.")

        user = db.get(User, user_id)
        if user is None:
            raise ProvenanceError(f"Authentication failed: User {user_id!r} not found in database.")
        if not user.is_active:
            raise ProvenanceError(f"Authentication failed: User {user_id!r} is inactive.")

        token_iat_dt = datetime.fromtimestamp(iat, tz=timezone.utc)
        if user.token_valid_after is not None and token_iat_dt < user.token_valid_after:
            raise ProvenanceError(
                f"Authentication failed: Token was issued at {token_iat_dt.isoformat()}, "
                f"before token_valid_after ({user.token_valid_after.isoformat()}). Token is revoked."
            )

        return cls(
            user_id=user.id,
            is_authenticated=True,
            auth_method="jwt_bearer",
            auth_time=token_iat_dt,
            _gateway_token=_AUTH_GATEWAY_TOKEN,
        )

    @classmethod
    def from_verified_session(
        cls,
        db: Session,
        session_user: Any,
        auth_method: str = "session",
    ) -> "AuthenticatedUserContext":
        """
        Construct a verified AuthenticatedUserContext from an authenticated server-side session User.

        INVARIANTS:
        - Requires a valid database session.
        - Rejects manually constructed, transient, or detached User ORM instances.
        - Verifies user exists in database and is_active is True.
        - Derives principal identity strictly from session_user.id.
        """
        from backend.authorization.models import User

        if db is None or not isinstance(db, Session):
            raise ProvenanceError("Authentication failed: Valid database session required for session verification.")

        if not isinstance(session_user, User):
            raise ProvenanceError(
                f"Authentication failed: Expected authenticated User instance, got {type(session_user).__name__}."
            )

        insp = sa_inspect(session_user)
        if not insp.persistent or insp.session is not db:
            raise ProvenanceError(
                "Security violation: Manually constructed, transient, or unattached User instance "
                "is not proof of an authenticated server-side session."
            )

        db_user = db.get(User, session_user.id)
        if db_user is None:
            raise ProvenanceError(f"Authentication failed: User {session_user.id!r} not found in database.")
        if not db_user.is_active:
            raise ProvenanceError(f"Authentication failed: User {session_user.id!r} is inactive.")

        return cls(
            user_id=db_user.id,
            is_authenticated=True,
            auth_method=auth_method,
            auth_time=datetime.now(timezone.utc),
            _gateway_token=_AUTH_GATEWAY_TOKEN,
        )


UserAuthContext = AuthenticatedUserContext

# Process-lifetime ephemeral HMAC secret for internal domain intake authorization.
# Generated once per process memory space. Cannot be forged by external callers.
_INTAKE_AUTH_SECRET = secrets.token_bytes(32)


def _compute_intake_authorization_digest(
    task_id: str,
    principal_id: str,
    origin: str,
    source_type: str,
    source_origin: str,
    content_hash: str,
    taint_labels: Tuple[str, ...],
    source_id: Optional[str] = None,
) -> str:
    """Compute HMAC-SHA256 signature for internal payload intake authorization."""
    elements = [
        str(task_id).strip(),
        str(principal_id).strip(),
        str(origin).strip(),
        str(source_type).strip(),
        str(source_origin).strip(),
        str(content_hash).strip(),
        ",".join(sorted(taint_labels)),
        str(source_id or "").strip(),
    ]
    canonical_payload = "|".join(elements).encode("utf-8")
    return hmac.new(_INTAKE_AUTH_SECRET, canonical_payload, hashlib.sha256).hexdigest()


class ValidatedProvenancePayload(BaseModel):
    """
    Internal domain representation of a validated provenance record payload.
    Constructed exclusively through trusted intake boundary factories.
    Enforces cryptographic intake authorization verified at the repository persistence boundary.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: str
    principal_id: str
    origin: str
    source_type: str
    source_origin: str
    content_hash: str
    taint_labels: Tuple[str, ...] = Field(default_factory=tuple)
    source_id: Optional[str] = None
    _intake_authorization: Optional[str] = PrivateAttr(default=None)

    def __init__(self, **data: Any):
        auth_sig = data.pop("_intake_authorization", None)
        super().__init__(**data)
        object.__setattr__(self, "_intake_authorization", auth_sig)
        if not self.verify_intake_authorization():
            raise ProvenanceError(
                "Direct construction of ValidatedProvenancePayload is restricted. "
                "Provenance payloads must be constructed via trusted intake factory methods."
            )

    @classmethod
    def model_construct(cls, *args: Any, **kwargs: Any) -> Any:
        raise ProvenanceError("Security violation: model_construct is forbidden on ValidatedProvenancePayload.")

    def model_copy(self, *args: Any, **kwargs: Any) -> Any:
        raise ProvenanceError("Security violation: model_copy is forbidden on ValidatedProvenancePayload.")

    def __copy__(self) -> Any:
        raise ProvenanceError("Security violation: copy is forbidden on ValidatedProvenancePayload.")

    def __deepcopy__(self, memo: Any) -> Any:
        raise ProvenanceError("Security violation: deepcopy is forbidden on ValidatedProvenancePayload.")

    def verify_intake_authorization(self) -> bool:
        """
        Cryptographically verify that this payload was issued by an authorized intake factory.
        Guarantees that any payload constructed via model_construct, model_copy, or attribute tampering fails.
        """
        auth_sig = getattr(self, "_intake_authorization", None)
        if not auth_sig or not isinstance(auth_sig, str):
            return False
        expected_sig = _compute_intake_authorization_digest(
            task_id=self.task_id,
            principal_id=self.principal_id,
            origin=self.origin,
            source_type=self.source_type,
            source_origin=self.source_origin,
            content_hash=self.content_hash,
            taint_labels=tuple(sorted(self.taint_labels or ())),
            source_id=self.source_id,
        )
        return hmac.compare_digest(auth_sig, expected_sig)

    @classmethod
    def create_user_input(
        cls,
        auth_context: AuthenticatedUserContext,
        task_id: str,
        content_hash: str,
        origin: str = "user_prompt",
        taint_labels: Sequence[str] = (),
        source_id: Optional[str] = None,
    ) -> "ValidatedProvenancePayload":
        """
        Construct a validated provenance payload for authenticated human user input.
        Enforces that the caller provides a cryptographically verified AuthenticatedUserContext.
        """
        if not isinstance(auth_context, AuthenticatedUserContext):
            raise ProvenanceError(
                f"Authenticated user context required: expected AuthenticatedUserContext, "
                f"got {type(auth_context).__name__}"
            )
        if not auth_context.is_verified():
            raise ProvenanceError("Unauthenticated caller cannot construct USER_PROVIDED provenance payload.")
        if not task_id or not isinstance(task_id, str):
            raise ProvenanceError("task_id must be a non-empty string.")
        if not origin or not isinstance(origin, str):
            raise ProvenanceError("origin must be a non-empty string.")
        if not is_valid_sha256_hex(content_hash):
            raise ProvenanceError(
                f"Invalid content_hash {content_hash!r}. "
                "Must be a 64-character lowercase hexadecimal SHA-256 digest."
            )

        validated_taints = []
        for t in taint_labels:
            validate_canonical_label(t)
            if t == TAINT_UNTRUSTED_DATA:
                raise ProvenanceError(
                    "Security violation: USER_PROVIDED provenance cannot carry UNTRUSTED_DATA taint."
                )
            if t not in validated_taints:
                validated_taints.append(t)

        sorted_taints = tuple(sorted(validated_taints))
        auth_sig = _compute_intake_authorization_digest(
            task_id=task_id,
            principal_id=auth_context.user_id,
            origin=origin,
            source_type="user_input",
            source_origin=ORIGIN_USER_PROVIDED,
            content_hash=content_hash,
            taint_labels=sorted_taints,
            source_id=source_id,
        )

        return cls(
            task_id=task_id,
            principal_id=auth_context.user_id,
            origin=origin,
            source_type="user_input",
            source_origin=ORIGIN_USER_PROVIDED,
            content_hash=content_hash,
            taint_labels=sorted_taints,
            source_id=source_id,
            _intake_authorization=auth_sig,
        )

    @classmethod
    def create_external(
        cls,
        task_id: str,
        principal_id: str,
        content_hash: str,
        origin: str,
        source_type: str = "email",
        taint_labels: Sequence[str] = (),
        source_id: Optional[str] = None,
    ) -> "ValidatedProvenancePayload":
        """
        Construct a validated provenance payload for external content (email, doc, api, etc.).
        Enforces baseline TAINT_UNTRUSTED_DATA and rejects user_input source_type spoofing.
        """
        if not task_id or not isinstance(task_id, str):
            raise ProvenanceError("task_id must be a non-empty string.")
        if not principal_id or not isinstance(principal_id, str):
            raise ProvenanceError("principal_id must be a non-empty string.")
        if not origin or not isinstance(origin, str):
            raise ProvenanceError("origin must be a non-empty string.")
        if not source_type or not isinstance(source_type, str):
            raise ProvenanceError("source_type must be a non-empty string.")
        if not is_valid_sha256_hex(content_hash):
            raise ProvenanceError(
                f"Invalid content_hash {content_hash!r}. "
                "Must be a 64-character lowercase hexadecimal SHA-256 digest."
            )

        norm_type = source_type.strip().lower()
        if norm_type in USER_SOURCE_TYPES:
            raise ProvenanceError(
                f"Security violation: Attempted to spoof external intake with user source_type {source_type!r}."
            )

        validated_taints = [TAINT_UNTRUSTED_DATA]
        for t in taint_labels:
            validate_canonical_label(t)
            if t not in validated_taints:
                validated_taints.append(t)

        sorted_taints = tuple(sorted(validated_taints))
        auth_sig = _compute_intake_authorization_digest(
            task_id=task_id,
            principal_id=principal_id,
            origin=origin,
            source_type=source_type,
            source_origin=ORIGIN_EXTERNAL,
            content_hash=content_hash,
            taint_labels=sorted_taints,
            source_id=source_id,
        )

        return cls(
            task_id=task_id,
            principal_id=principal_id,
            origin=origin,
            source_type=source_type,
            source_origin=ORIGIN_EXTERNAL,
            content_hash=content_hash,
            taint_labels=sorted_taints,
            source_id=source_id,
            _intake_authorization=auth_sig,
        )
