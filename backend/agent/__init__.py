"""
Agent Subsystem Public Package Exports (AgentShield Stage 2)
Provides immutable DTOs, domain repositories, persistent provenance registry,
cryptographic content hashing, canonical taint validation, and domain exceptions.
"""

from backend.agent.dtos import (
    AuthenticatedUserContext,
    CapabilityManifestDTO,
    ProvenanceRecordDTO,
    TaskContext,
    UserAuthContext,
    ValidatedProvenancePayload,
)
from backend.agent.exceptions import (
    AgentShieldError,
    InvalidTaskTransitionError,
    ManifestVerificationError,
    ProvenanceError,
    TaskNotFoundError,
    TaskOwnershipError,
    TaskTransactionError,
)
from backend.agent.hashing import (
    hash_content,
    is_valid_sha256_hex,
    normalize_content,
    verify_content_hash,
)
from backend.agent.models import (
    ORIGIN_EXTERNAL,
    ORIGIN_USER_PROVIDED,
    SOURCE_ORIGINS,
    TAINT_UNTRUSTED_DATA,
    TAINT_UNTRUSTED_INSTRUCTIONS,
    TASK_STATUS_ACTIVE,
    TASK_STATUS_CANCELLED,
    TASK_STATUS_COMPLETED,
    TASK_STATUS_FAILED,
    TASK_STATUSES,
    TRUST_LEVELS,
    TRUST_TRUSTED,
    TRUST_UNTRUSTED,
    VALID_TAINT_LABELS,
    ProvenanceRecord,
    Task,
)

# Friendly aliases
VALID_TASK_STATUSES = TASK_STATUSES
VALID_TRUST_LEVELS = TRUST_LEVELS
VALID_ORIGINS = SOURCE_ORIGINS
from backend.agent.provenance_registry import ProvenanceRegistry
from backend.agent.provenance_repository import ProvenanceRepository
from backend.agent.taint import (
    EXTERNAL_SOURCE_TYPES,
    USER_SOURCE_TYPES,
    combine_and_validate_taint,
    derive_trust_level,
    map_runtime_categories,
    resolve_source_origin,
    validate_canonical_label,
)
from backend.agent.task_repository import TaskRepository

__all__ = [
    # Domain Exceptions
    "AgentShieldError",
    "TaskNotFoundError",
    "TaskOwnershipError",
    "ManifestVerificationError",
    "ProvenanceError",
    "InvalidTaskTransitionError",
    "TaskTransactionError",
    # DTOs
    "CapabilityManifestDTO",
    "TaskContext",
    "ProvenanceRecordDTO",
    "AuthenticatedUserContext",
    "UserAuthContext",
    "ValidatedProvenancePayload",
    # Hashing & Normalization
    "hash_content",
    "normalize_content",
    "verify_content_hash",
    "is_valid_sha256_hex",
    # Taint & Trust
    "TAINT_UNTRUSTED_DATA",
    "TAINT_UNTRUSTED_INSTRUCTIONS",
    "VALID_TAINT_LABELS",
    "USER_SOURCE_TYPES",
    "EXTERNAL_SOURCE_TYPES",
    "resolve_source_origin",
    "map_runtime_categories",
    "validate_canonical_label",
    "combine_and_validate_taint",
    "derive_trust_level",
    # Repositories & Registry
    "TaskRepository",
    "ProvenanceRepository",
    "ProvenanceRegistry",
    # Models & Constants
    "Task",
    "ProvenanceRecord",
    "TASK_STATUS_ACTIVE",
    "TASK_STATUS_COMPLETED",
    "TASK_STATUS_CANCELLED",
    "TASK_STATUS_FAILED",
    "VALID_TASK_STATUSES",
    "TRUST_TRUSTED",
    "TRUST_UNTRUSTED",
    "VALID_TRUST_LEVELS",
    "ORIGIN_USER_PROVIDED",
    "ORIGIN_EXTERNAL",
    "VALID_ORIGINS",
]
