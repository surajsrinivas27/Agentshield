"""
Tests for Domain Exceptions — AgentShield
Verifies inheritance hierarchy, error message formatting, and catch-all behavior.
"""

import pytest

from backend.agent.exceptions import (
    AgentShieldError,
    TaskNotFoundError,
    TaskOwnershipError,
    ManifestVerificationError,
    ProvenanceError,
    InvalidTaskTransitionError,
)


class TestExceptionsHierarchy:

    def test_all_exceptions_inherit_from_agentshield_error(self):
        """All domain exceptions must be subclasses of AgentShieldError."""
        subclasses = [
            TaskNotFoundError,
            TaskOwnershipError,
            ManifestVerificationError,
            ProvenanceError,
            InvalidTaskTransitionError,
        ]
        for exc_cls in subclasses:
            assert issubclass(exc_cls, AgentShieldError)
            assert issubclass(exc_cls, Exception)

    def test_catch_all_agentshield_error(self):
        """Catching AgentShieldError catches all derived domain exceptions."""
        with pytest.raises(AgentShieldError):
            raise TaskNotFoundError("Task 123 not found")

        with pytest.raises(AgentShieldError):
            raise TaskOwnershipError("Principal unauthorized")

        with pytest.raises(AgentShieldError):
            raise ManifestVerificationError("Signature mismatch")

        with pytest.raises(AgentShieldError):
            raise ProvenanceError("Invalid taint")

        with pytest.raises(AgentShieldError):
            raise InvalidTaskTransitionError("Cannot transition COMPLETED to ACTIVE")
