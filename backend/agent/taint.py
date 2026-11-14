"""
Canonical Taint Classification and Trust Derivation — AgentShield

Bridges runtime TaintTracker categories to persistent boundary labels and enforces
trust level derivation invariants.
"""

import re
from typing import Iterable, Mapping, Optional, Sequence

from backend.agent.exceptions import ProvenanceError
from backend.agent.models import (
    ORIGIN_EXTERNAL,
    ORIGIN_USER_PROVIDED,
    SOURCE_ORIGINS,
    TAINT_UNTRUSTED_DATA,
    TAINT_UNTRUSTED_INSTRUCTIONS,
    TRUST_TRUSTED,
    TRUST_UNTRUSTED,
    VALID_TAINT_LABELS,
)

# Granular runtime categories produced during content intake and prompt inspection
# mapped deterministically to coarse-grained persistent security boundary labels.
RUNTIME_TO_CANONICAL_TAINT: Mapping[str, str] = {
    # Data categories: external or third-party content payloads
    "EMAIL_BODY": TAINT_UNTRUSTED_DATA,
    "DOCUMENT_CONTENT": TAINT_UNTRUSTED_DATA,
    "API_PAYLOAD": TAINT_UNTRUSTED_DATA,
    "UNTRUSTED_SOURCE": TAINT_UNTRUSTED_DATA,
    "WEB_PAGE": TAINT_UNTRUSTED_DATA,
    "ATTACHMENT_TEXT": TAINT_UNTRUSTED_DATA,
    # Instruction categories: imperative prompts or injection vectors inside content
    "EXTERNAL_INSTRUCTION": TAINT_UNTRUSTED_INSTRUCTIONS,
    "INDIRECT_PROMPT_INJECTION": TAINT_UNTRUSTED_INSTRUCTIONS,
    "UNTRUSTED_TOOL_ARGUMENT": TAINT_UNTRUSTED_INSTRUCTIONS,
    "UNVERIFIED_PROMPT": TAINT_UNTRUSTED_INSTRUCTIONS,
}

# Runtime categories that inherently indicate external origin
EXTERNAL_TAINT_CATEGORIES: frozenset[str] = frozenset({
    "EMAIL_BODY",
    "DOCUMENT_CONTENT",
    "API_PAYLOAD",
    "UNTRUSTED_SOURCE",
    "WEB_PAGE",
    "ATTACHMENT_TEXT",
})

# Trusted classifications for content source types
USER_SOURCE_TYPES = frozenset({
    "user_input",
    "user_prompt",
    "user_instruction",
    "user_message",
})

EXTERNAL_SOURCE_TYPES = frozenset({
    "email",
    "document",
    "api_response",
    "external_data",
    "third_party",
    "attachment",
    "web_page",
    "file",
})

# Structural patterns that betray external content (emails, HTML/XML documents, frontmatter)
EXTERNAL_CONTENT_PATTERNS = [
    # RFC 822/2822 email header lines at line start
    re.compile(r"(?im)^(?:From|To|Subject|Cc|Bcc|Date|Received|Message-ID|Return-Path|MIME-Version|Content-Type):\s+.+"),
    # MIME / email boundaries
    re.compile(r"(?i)Content-Transfer-Encoding:\s+\w+"),
    re.compile(r"(?i)boundary=[\"']?[\w\-]+[\"']?"),
    # HTML document tags
    re.compile(r"(?i)<\s*(?:!DOCTYPE\s+html|html|head|body|script|iframe|table|div|p|span)[^>]*>"),
    # XML document prolog
    re.compile(r"(?i)<\?xml[^>]*\?>"),
    # Document frontmatter
    re.compile(r"(?m)^---\s*\n(?:title|author|subject|description):", re.IGNORECASE),
]


def detect_external_content_indicators(content: str) -> Optional[str]:
    """
    Inspect content at the intake boundary for structural indicators of external content
    (e.g., email RFC headers, HTML/XML tags, document frontmatter).
    Returns the matching snippet if detected, None if clean.
    """
    if not isinstance(content, str):
        return None
    for pattern in EXTERNAL_CONTENT_PATTERNS:
        match = pattern.search(content)
        if match:
            return match.group(0).strip()
    return None


def resolve_source_origin(
    source_type: str,
    requested_origin: Optional[str] = None,
    content: Optional[str] = None,
) -> str:
    """
    Validate and determine source_origin based on trusted intake boundary rules.
    Prevents untrusted callers from promoting external content to USER_PROVIDED.

    INVARIANTS:
    - If content displays external indicators (email headers, HTML/XML markup, etc.),
      attempting to claim USER_PROVIDED is rejected with ProvenanceError.
    - If source_type is external, origin MUST be EXTERNAL.
    - If source_type is user-provided, origin is USER_PROVIDED (provided content is clean).
    - If source_type is unclassified or unknown, defaults to EXTERNAL (fail-closed).
    """
    if not source_type or not isinstance(source_type, str):
        raise ProvenanceError("source_type must be a non-empty string.")

    if requested_origin is not None and requested_origin not in SOURCE_ORIGINS:
        raise ProvenanceError(
            f"Invalid source_origin {requested_origin!r}. Must be one of {sorted(SOURCE_ORIGINS)}."
        )

    # 1. Structural inspection of content at the boundary
    if content is not None:
        indicator = detect_external_content_indicators(content)
        if indicator:
            if requested_origin == ORIGIN_USER_PROVIDED:
                raise ProvenanceError(
                    f"Security violation: external content indicators ({indicator!r}) detected "
                    f"at user intake boundary. Content cannot be registered as {ORIGIN_USER_PROVIDED!r}."
                )
            return ORIGIN_EXTERNAL

    normalized_type = source_type.strip().lower()

    if normalized_type in EXTERNAL_SOURCE_TYPES:
        if requested_origin is not None and requested_origin != ORIGIN_EXTERNAL:
            raise ProvenanceError(
                f"Security violation: external source_type {source_type!r} cannot be "
                f"registered as {requested_origin!r}. External content is always EXTERNAL."
            )
        return ORIGIN_EXTERNAL

    if normalized_type in USER_SOURCE_TYPES:
        if requested_origin is not None and requested_origin != ORIGIN_USER_PROVIDED:
            raise ProvenanceError(
                f"Invalid origin: user source_type {source_type!r} cannot be "
                f"registered as {requested_origin!r}."
            )
        return ORIGIN_USER_PROVIDED

    # Unrecognized source_type: fail-closed to EXTERNAL
    if requested_origin == ORIGIN_USER_PROVIDED:
        raise ProvenanceError(
            f"Security violation: unverified source_type {source_type!r} cannot be "
            f"registered as {ORIGIN_USER_PROVIDED!r}. Only verified user inputs may be USER_PROVIDED."
        )
    return ORIGIN_EXTERNAL


def validate_canonical_label(label: str) -> str:
    """Validate that a label is an approved member of VALID_TAINT_LABELS."""
    if not isinstance(label, str):
        raise ProvenanceError(f"Taint label must be a string, got {type(label).__name__}")
    if label not in VALID_TAINT_LABELS:
        raise ProvenanceError(
            f"Invalid canonical taint label: {label!r}. "
            f"Must be one of {sorted(VALID_TAINT_LABELS)}."
        )
    return label


def map_runtime_categories(categories: Iterable[str]) -> tuple[str, ...]:
    """
    Map runtime categories to canonical boundary labels.
    FAILS CLOSED: Any unrecognized or unmapped category raises ProvenanceError.
    Never silently discards unknown categories.
    """
    mapped: set[str] = set()
    for cat in categories:
        if not isinstance(cat, str):
            raise ProvenanceError(f"Runtime taint category must be a string, got {type(cat).__name__}")
        normalized_cat = cat.strip().upper()
        if normalized_cat not in RUNTIME_TO_CANONICAL_TAINT:
            raise ProvenanceError(
                f"Unknown runtime taint category: {cat!r}. "
                f"Cannot map to canonical boundary label; failing closed."
            )
        mapped.add(RUNTIME_TO_CANONICAL_TAINT[normalized_cat])
    return tuple(sorted(mapped))


def combine_and_validate_taint(
    source_origin: str,
    runtime_categories: Optional[Sequence[str]] = None,
    explicit_labels: Optional[Sequence[str]] = None,
) -> tuple[str, ...]:
    """
    Combine and validate runtime categories and explicit taint labels.
    - Validates both sources independently.
    - Merges and deduplicates.
    - Preserves origin baseline: external content always receives TAINT_UNTRUSTED_DATA.
    - Fails closed on any unknown category or invalid label.
    """
    if source_origin not in SOURCE_ORIGINS:
        raise ProvenanceError(
            f"Invalid source_origin {source_origin!r}. Must be one of {sorted(SOURCE_ORIGINS)}."
        )

    combined: set[str] = set()

    # 1. Map and validate runtime categories
    if runtime_categories is not None:
        if not isinstance(runtime_categories, (list, tuple, set)):
            raise ProvenanceError(
                f"runtime_categories must be a collection, got {type(runtime_categories).__name__}"
            )
        for label in map_runtime_categories(runtime_categories):
            combined.add(label)

    # 2. Validate explicit labels
    if explicit_labels is not None:
        if not isinstance(explicit_labels, (list, tuple, set)):
            raise ProvenanceError(
                f"explicit_labels must be a collection, got {type(explicit_labels).__name__}"
            )
        for label in explicit_labels:
            validated = validate_canonical_label(label)
            combined.add(validated)

    # 3. Baseline origin taint: external content must ALWAYS carry UNTRUSTED_DATA
    if source_origin == ORIGIN_EXTERNAL:
        combined.add(TAINT_UNTRUSTED_DATA)

    return tuple(sorted(combined))


def derive_trust_level(source_origin: str, taint_labels: Sequence[str]) -> str:
    """
    Derive the runtime trust level strictly based on origin and taint labels.
    INVARIANTS:
    - External content is ALWAYS UNTRUSTED.
    - Any content with taint labels (data or instruction) is ALWAYS UNTRUSTED.
    - Only untainted user-provided content may be TRUSTED.
    - Callers cannot override this derivation.
    """
    if source_origin not in SOURCE_ORIGINS:
        raise ProvenanceError(
            f"Invalid source_origin {source_origin!r}. Must be one of {sorted(SOURCE_ORIGINS)}."
        )

    if source_origin == ORIGIN_EXTERNAL or len(taint_labels) > 0:
        return TRUST_UNTRUSTED

    if source_origin == ORIGIN_USER_PROVIDED and len(taint_labels) == 0:
        return TRUST_TRUSTED

    raise ProvenanceError(f"Unable to derive trust level for origin {source_origin!r}")
