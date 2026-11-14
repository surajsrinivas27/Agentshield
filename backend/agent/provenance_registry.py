"""
AgentShield Stage 2 - Persistent Provenance Registry
Domain service orchestrating content ingestion, SHA-256 hashing, taint resolution,
and task-scoped provenance persistence across trusted application intake boundaries.
"""

from typing import List, Optional, Sequence

from sqlalchemy.orm import Session

from backend.agent.dtos import (
    AuthenticatedUserContext,
    ProvenanceRecordDTO,
    ValidatedProvenancePayload,
)
from backend.agent.exceptions import (
    InvalidTaskTransitionError,
    ProvenanceError,
    TaskOwnershipError,
)
from backend.agent.hashing import (
    hash_content,
    is_valid_sha256_hex,
    verify_content_hash,
)
from backend.agent.models import (
    ORIGIN_EXTERNAL,
    ORIGIN_USER_PROVIDED,
    TAINT_UNTRUSTED_DATA,
)
from backend.agent.provenance_repository import ProvenanceRepository
from backend.agent.taint import (
    EXTERNAL_TAINT_CATEGORIES,
    USER_SOURCE_TYPES,
    combine_and_validate_taint,
    detect_external_content_indicators,
)
from backend.agent.task_repository import TaskRepository


class ProvenanceRegistry:
    """
    Domain service for managing provenance tracking and content integrity.

    TRUSTED APPLICATION INTAKE BOUNDARY ARCHITECTURE:
    1. Authenticated User Input (register_user_input):
       - Authoritative Caller: Authenticated Application Gateway / Human User Session layer.
       - Caller Responsibility: Authenticate the human user (signed JWT, session cookies, MFA),
         bind verified principal identity to AuthenticatedUserContext, and guarantee that content
         originated from direct human interaction (chat UI, CLI prompt), not external feeds.
       - Integration Dependency Contract: The application gateway authentication layer is an explicit
         integration dependency delivered in subsequent application stages. Unverified inputs remain
         untrusted by default. Freely constructible contexts cannot produce TRUSTED provenance.
         Regex/structural pattern inspection (detect_external_content_indicators) is defense-in-depth,
         not cryptographic proof of human origin.
       - Enforces strict human-origin invariants: Rejects external structural markers (RFC 822
         email headers, HTML/XML markup, document frontmatter), rejects external taint categories,
         and rejects explicit UNTRUSTED_DATA.
       - Result: Content with no taints produces a TRUST_TRUSTED provenance record.

    2. External Content Ingestion (register_external_content):
       - Caller: External Resource Adapters (email inboxes, document parsers, API clients, Agent tool outputs).
       - Enforces external origin invariants: Binds origin to ORIGIN_EXTERNAL, rejects spoofed
         source_type='user_input', and automatically applies baseline TAINT_UNTRUSTED_DATA.
       - Result: Guaranteed to produce a TRUST_UNTRUSTED provenance record.

    3. Content Privacy & Non-Persistence:
       - Raw source content is hashed in-memory using Unicode NFC and newline normalization;
         raw content strings are never written to database tables or logs.
    """

    @staticmethod
    def register_user_input(
        db: Session,
        auth_context: AuthenticatedUserContext,
        task_id: str,
        sanitized_content: str,
        origin: str = "user_prompt",
        runtime_taint_categories: Optional[Sequence[str]] = None,
        explicit_taint_labels: Optional[Sequence[str]] = None,
        source_id: Optional[str] = None,
    ) -> ProvenanceRecordDTO:
        """
        Trusted application intake boundary for authenticated human user input.

        TRUST BOUNDARY CONTRACT:
        - Must be invoked exclusively by the verified application gateway / session layer.
        - Principal identity is derived directly from auth_context.user_id (never from an
          arbitrary or caller-supplied request field).
        - Requires an active, authenticated AuthenticatedUserContext.
        - Verifies that the target task exists, is owned by auth_context.user_id, and is ACTIVE.
        - Content inspection (defense-in-depth): Rejects content bearing external structural markers
          (RFC 822 email headers, HTML/XML markup, document frontmatter).
        - Taint category inspection: Rejects external data categories (EMAIL_BODY, DOCUMENT_CONTENT, etc.).
        - Explicit taint inspection: Rejects UNTRUSTED_DATA label on user input.
        - Binds source_origin strictly to ORIGIN_USER_PROVIDED.
        """
        if not isinstance(auth_context, AuthenticatedUserContext):
            raise ProvenanceError(
                f"Authentication context required: expected AuthenticatedUserContext, "
                f"got {type(auth_context).__name__}."
            )

        if not auth_context.is_verified():
            raise ProvenanceError("Unauthenticated caller cannot register user input.")

        if not isinstance(sanitized_content, str):
            raise TypeError(
                f"sanitized_content must be a string, got {type(sanitized_content).__name__}"
            )

        principal_id = auth_context.user_id

        # 1. Enforce task existence, ownership, and active state
        task = TaskRepository.get_task(db, task_id=task_id, principal_id=principal_id)
        if not task.is_active():
            raise InvalidTaskTransitionError(
                f"Cannot record provenance for task {task_id!r} with status {task.status!r}. "
                "Task must be ACTIVE."
            )

        # 2. Defense-in-depth structural inspection for external content signatures
        ext_indicator = detect_external_content_indicators(sanitized_content)
        if ext_indicator:
            raise ProvenanceError(
                f"Security violation: External content indicators ({ext_indicator!r}) detected "
                f"at user intake boundary. External content cannot be ingested as user input."
            )

        # 3. Reject external runtime taint categories
        if runtime_taint_categories:
            for cat in runtime_taint_categories:
                if str(cat).strip().upper() in EXTERNAL_TAINT_CATEGORIES:
                    raise ProvenanceError(
                        f"Security violation: External taint category {cat!r} cannot be "
                        f"ingested through user input intake."
                    )

        # 4. Reject explicit UNTRUSTED_DATA on user input
        if explicit_taint_labels and TAINT_UNTRUSTED_DATA in explicit_taint_labels:
            raise ProvenanceError(
                "Security violation: User input cannot be registered with UNTRUSTED_DATA taint."
            )

        # 5. Compute cryptographic SHA-256 digest over normalized content
        content_hash = hash_content(sanitized_content)

        # 6. Combine and validate taint labels
        combined_taints = combine_and_validate_taint(
            source_origin=ORIGIN_USER_PROVIDED,
            runtime_categories=runtime_taint_categories,
            explicit_labels=explicit_taint_labels,
        )

        # 7. Construct validated payload through internal trusted intake factory
        payload = ValidatedProvenancePayload.create_user_input(
            auth_context=auth_context,
            task_id=task_id,
            content_hash=content_hash,
            origin=origin,
            taint_labels=combined_taints,
            source_id=source_id,
        )

        # 8. Record provenance entry (trust_level derived inside repository persistence boundary)
        return ProvenanceRepository.record_provenance(db=db, payload=payload)

    @staticmethod
    def register_external_content(
        db: Session,
        task_id: str,
        principal_id: str,
        sanitized_content: str,
        origin: str,
        source_type: str = "email",
        runtime_taint_categories: Optional[Sequence[str]] = None,
        explicit_taint_labels: Optional[Sequence[str]] = None,
        source_id: Optional[str] = None,
    ) -> ProvenanceRecordDTO:
        """
        Trusted application intake boundary for external content (emails, documents, APIs, attachments).

        INVARIANTS:
        - Verifies that target task exists, is owned by principal_id, and is ACTIVE.
        - Binds source_origin strictly to ORIGIN_EXTERNAL (caller cannot override).
        - Rejects any attempt to spoof source_type as 'user_input' or user source types.
        - Automatically marks content with baseline TAINT_UNTRUSTED_DATA.
        - Resulting record is GUARANTEED to be TRUST_UNTRUSTED.
        """
        if not isinstance(sanitized_content, str):
            raise TypeError(
                f"sanitized_content must be a string, got {type(sanitized_content).__name__}"
            )

        if not principal_id or not isinstance(principal_id, str):
            raise TaskOwnershipError("principal_id must be a non-empty string.")

        # 1. Enforce task existence, ownership, and active state
        task = TaskRepository.get_task(db, task_id=task_id, principal_id=principal_id)
        if not task.is_active():
            raise InvalidTaskTransitionError(
                f"Cannot record provenance for task {task_id!r} with status {task.status!r}. "
                "Task must be ACTIVE."
            )

        # 2. Reject attempts to spoof source_type as user_input
        norm_type = (source_type or "").strip().lower()
        if norm_type in USER_SOURCE_TYPES:
            raise ProvenanceError(
                f"Security violation: Attempted to spoof external intake with user source_type {source_type!r}."
            )

        # 3. Compute cryptographic SHA-256 digest over normalized content
        content_hash = hash_content(sanitized_content)

        # 4. Combine and validate taint labels (always enforces TAINT_UNTRUSTED_DATA for external)
        combined_taints = combine_and_validate_taint(
            source_origin=ORIGIN_EXTERNAL,
            runtime_categories=runtime_taint_categories,
            explicit_labels=explicit_taint_labels,
        )

        # 5. Construct validated payload through internal trusted intake factory
        payload = ValidatedProvenancePayload.create_external(
            task_id=task_id,
            principal_id=principal_id,
            content_hash=content_hash,
            origin=origin,
            source_type=source_type,
            taint_labels=combined_taints,
            source_id=source_id,
        )

        # 6. Record provenance entry (trust_level derived inside repository persistence boundary)
        return ProvenanceRepository.record_provenance(db=db, payload=payload)

    @staticmethod
    def _register_precomputed_hash_internal(
        db: Session,
        task_id: str,
        principal_id: str,
        content_hash: str,
        origin: str,
        source_type: str,
        source_origin: Optional[str] = None,
        runtime_taint_categories: Optional[Sequence[str]] = None,
        explicit_taint_labels: Optional[Sequence[str]] = None,
        source_id: Optional[str] = None,
    ) -> ProvenanceRecordDTO:
        """
        Restricted internal registration using a precomputed hash.
        For internal subsystem use only (e.g. large external file streaming adapters).

        INVARIANTS:
        - Must strictly validate SHA-256 hex format.
        - Precomputed hashes cannot be registered as USER_PROVIDED (fails closed).
        - Enforces identical ownership, task state, taint combination, and trust derivation.
        - A precomputed hash is NOT treated as proof of sanitization or trustworthiness.
        """
        if not is_valid_sha256_hex(content_hash):
            raise ProvenanceError(
                f"Invalid content_hash {content_hash!r}. "
                "Must be a 64-character lowercase hexadecimal SHA-256 digest."
            )

        norm_origin = (source_origin or "").strip()
        norm_type = (source_type or "").strip().lower()
        if norm_origin == ORIGIN_USER_PROVIDED or norm_type in USER_SOURCE_TYPES:
            raise ProvenanceError(
                "Security violation: Precomputed hashes cannot be registered as USER_PROVIDED. "
                "User provenance requires active authenticated intake."
            )

        task = TaskRepository.get_task(db, task_id=task_id, principal_id=principal_id)
        if not task.is_active():
            raise InvalidTaskTransitionError(
                f"Cannot record provenance for task {task_id!r} with status {task.status!r}. "
                "Task must be ACTIVE."
            )

        combined_taints = combine_and_validate_taint(
            source_origin=ORIGIN_EXTERNAL,
            runtime_categories=runtime_taint_categories,
            explicit_labels=explicit_taint_labels,
        )

        payload = ValidatedProvenancePayload.create_external(
            task_id=task_id,
            principal_id=principal_id,
            content_hash=content_hash,
            origin=origin,
            source_type=source_type,
            taint_labels=combined_taints,
            source_id=source_id,
        )

        return ProvenanceRepository.record_provenance(db=db, payload=payload)

    @staticmethod
    def get_task_provenance(
        db: Session,
        task_id: str,
        principal_id: str,
    ) -> List[ProvenanceRecordDTO]:
        """List all provenance records for a task, verifying ownership."""
        return ProvenanceRepository.list_provenance_for_task(
            db=db,
            task_id=task_id,
            principal_id=principal_id,
        )

    @staticmethod
    def get_record(
        db: Session,
        source_id: str,
        principal_id: str,
    ) -> ProvenanceRecordDTO:
        """
        Retrieve a specific provenance record, verifying task ownership.
        Returns ProvenanceError indistinguishably if record does not exist or belongs to another user.
        """
        return ProvenanceRepository.get_provenance(
            db=db,
            source_id=source_id,
            principal_id=principal_id,
        )

    @staticmethod
    def verify_content_integrity(
        sanitized_content: str,
        record: ProvenanceRecordDTO,
    ) -> bool:
        """
        Verify whether in-memory sanitized content matches the digest in a provenance record.
        Reuses verify_content_hash helper.
        """
        if not isinstance(sanitized_content, str):
            raise TypeError("sanitized_content must be a string.")
        return verify_content_hash(sanitized_content, record.content_hash)
