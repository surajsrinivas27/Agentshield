"""
Tests for Taint Classification and Trust Derivation — AgentShield
Verifies runtime mapping, dual taint combination, fail-closed handling, and trust invariants.
"""

import pytest

from backend.agent.exceptions import ProvenanceError
from backend.agent.models import (
    ORIGIN_EXTERNAL,
    ORIGIN_USER_PROVIDED,
    TAINT_UNTRUSTED_DATA,
    TAINT_UNTRUSTED_INSTRUCTIONS,
    TRUST_TRUSTED,
    TRUST_UNTRUSTED,
    VALID_TAINT_LABELS,
)
from backend.agent.taint import (
    combine_and_validate_taint,
    derive_trust_level,
    map_runtime_categories,
    validate_canonical_label,
)


class TestTaintClassificationAndTrust:

    def test_canonical_constants_exported(self):
        """Canonical labels are members of VALID_TAINT_LABELS."""
        assert TAINT_UNTRUSTED_DATA in VALID_TAINT_LABELS
        assert TAINT_UNTRUSTED_INSTRUCTIONS in VALID_TAINT_LABELS
        assert VALID_TAINT_LABELS == {"UNTRUSTED_DATA", "UNTRUSTED_INSTRUCTIONS"}

    def test_validate_canonical_label_valid(self):
        """Valid canonical labels pass validation."""
        assert validate_canonical_label(TAINT_UNTRUSTED_DATA) == TAINT_UNTRUSTED_DATA
        assert validate_canonical_label(TAINT_UNTRUSTED_INSTRUCTIONS) == TAINT_UNTRUSTED_INSTRUCTIONS

    def test_validate_canonical_label_invalid_raises_provenance_error(self):
        """Non-canonical labels raise ProvenanceError."""
        for invalid in ["EXTERNAL_INSTRUCTION", "UNTRUSTED_SOURCE", "RANDOM"]:
            with pytest.raises(ProvenanceError) as exc_info:
                validate_canonical_label(invalid)
            assert "Invalid canonical taint label" in str(exc_info.value)

    def test_map_runtime_categories_data_and_instruction(self):
        """Runtime categories map accurately to canonical boundary labels."""
        data_cats = ["EMAIL_BODY", "DOCUMENT_CONTENT", "API_PAYLOAD", "UNTRUSTED_SOURCE"]
        assert map_runtime_categories(data_cats) == (TAINT_UNTRUSTED_DATA,)

        instruction_cats = ["EXTERNAL_INSTRUCTION", "INDIRECT_PROMPT_INJECTION"]
        assert map_runtime_categories(instruction_cats) == (TAINT_UNTRUSTED_INSTRUCTIONS,)

        mixed = ["EMAIL_BODY", "INDIRECT_PROMPT_INJECTION"]
        assert map_runtime_categories(mixed) == (TAINT_UNTRUSTED_DATA, TAINT_UNTRUSTED_INSTRUCTIONS)

    def test_map_runtime_categories_fails_closed_on_unknown(self):
        """Unrecognized runtime categories MUST raise ProvenanceError, never silently discarded."""
        with pytest.raises(ProvenanceError) as exc_info:
            map_runtime_categories(["EMAIL_BODY", "UNKNOWN_TAG_123"])
        assert "Unknown runtime taint category: 'UNKNOWN_TAG_123'" in str(exc_info.value)

    def test_combine_and_validate_taint_external_always_has_data_taint(self):
        """Content with source_origin=EXTERNAL must always carry TAINT_UNTRUSTED_DATA."""
        labels = combine_and_validate_taint(
            source_origin=ORIGIN_EXTERNAL,
            runtime_categories=None,
            explicit_labels=None,
        )
        assert labels == (TAINT_UNTRUSTED_DATA,)

    def test_combine_and_validate_taint_merges_and_deduplicates(self):
        """Deduplicates when both runtime and explicit specify data taint."""
        labels = combine_and_validate_taint(
            source_origin=ORIGIN_USER_PROVIDED,
            runtime_categories=["EMAIL_BODY"],
            explicit_labels=[TAINT_UNTRUSTED_DATA, TAINT_UNTRUSTED_INSTRUCTIONS],
        )
        assert labels == (TAINT_UNTRUSTED_DATA, TAINT_UNTRUSTED_INSTRUCTIONS)

    def test_combine_and_validate_taint_fails_closed_on_bad_inputs(self):
        """Fails closed if runtime categories or explicit labels contain invalid values."""
        with pytest.raises(ProvenanceError):
            combine_and_validate_taint(
                source_origin=ORIGIN_USER_PROVIDED,
                runtime_categories=["NOT_A_REAL_TAG"],
            )

        with pytest.raises(ProvenanceError):
            combine_and_validate_taint(
                source_origin=ORIGIN_USER_PROVIDED,
                explicit_labels=["NOT_CANONICAL"],
            )

    def test_trust_derivation_external_never_trusted(self):
        """External content can NEVER become TRUSTED."""
        # Without taint labels
        assert derive_trust_level(ORIGIN_EXTERNAL, []) == TRUST_UNTRUSTED
        # With data taint
        assert derive_trust_level(ORIGIN_EXTERNAL, [TAINT_UNTRUSTED_DATA]) == TRUST_UNTRUSTED
        # With instruction taint
        assert derive_trust_level(ORIGIN_EXTERNAL, [TAINT_UNTRUSTED_INSTRUCTIONS]) == TRUST_UNTRUSTED

    def test_trust_derivation_tainted_user_content_is_untrusted(self):
        """User content that is tainted can NEVER become TRUSTED."""
        assert derive_trust_level(ORIGIN_USER_PROVIDED, [TAINT_UNTRUSTED_DATA]) == TRUST_UNTRUSTED
        assert derive_trust_level(ORIGIN_USER_PROVIDED, [TAINT_UNTRUSTED_INSTRUCTIONS]) == TRUST_UNTRUSTED

    def test_trust_derivation_clean_user_content_is_trusted(self):
        """Only untainted user-provided content may be TRUSTED."""
        assert derive_trust_level(ORIGIN_USER_PROVIDED, []) == TRUST_TRUSTED

    def test_trust_derivation_invalid_origin_raises(self):
        """Invalid origin raises ProvenanceError."""
        with pytest.raises(ProvenanceError):
            derive_trust_level("INVALID_ORIGIN", [])
