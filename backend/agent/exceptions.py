"""
Domain Exceptions for AgentShield Agent & Provenance Subsystems.

Provides structured, fail-closed domain exceptions for task lifecycle management,
capability manifest validation, provenance tracking, and cross-principal isolation.
"""


class AgentShieldError(Exception):
    """Base exception for all AgentShield agent domain errors."""


class TaskNotFoundError(AgentShieldError):
    """Raised when a requested task does not exist."""


class TaskOwnershipError(AgentShieldError):
    """Raised when an operation violates task ownership or cross-principal boundaries."""


class ManifestVerificationError(AgentShieldError):
    """Raised when a capability manifest signature or parameter binding is invalid or expired."""


class ProvenanceError(AgentShieldError):
    """Raised when provenance intake, hashing, taint validation, or persistence fails."""


class InvalidTaskTransitionError(AgentShieldError):
    """Raised when an illegal task lifecycle state transition is attempted."""


class TaskTransactionError(AgentShieldError):
    """Raised when a task operation cannot satisfy transaction isolation or safety contracts."""
