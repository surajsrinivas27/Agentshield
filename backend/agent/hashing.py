"""
Deterministic Content Hashing — AgentShield

Provides cryptographic SHA-256 content hashing with canonical Unicode NFC
normalization and newline normalization.

Memory & Privacy Semantics
--------------------------
In CPython, string objects are immutable, managed on the runtime heap, and subject
to string interning and non-deterministic garbage collection. Python does not expose
an API for deterministic in-memory zeroization of string buffers.

AgentShield guarantees architectural data containment:
- Raw content is received as an ephemeral function parameter and used exclusively
  to compute the cryptographic SHA-256 digest.
- Raw content is NEVER persisted to the database, NEVER stored in ORM models,
  and NEVER emitted to logs or telemetry.
- Once the hash is computed, the string reference is discarded to standard
  Python garbage collection.
"""

import hashlib
import hmac
import re
import unicodedata

_SHA256_HEX_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def is_valid_sha256_hex(digest: str) -> bool:
    """Return True if the string is a valid 64-character lowercase hex SHA-256 digest."""
    if not isinstance(digest, str):
        return False
    return bool(_SHA256_HEX_PATTERN.fullmatch(digest))


def normalize_content(content: str) -> str:
    """
    Apply canonical normalization to text content:
    1. Normalize newlines: CRLF (\\r\\n) and CR (\\r) -> LF (\\n).
    2. Normalize Unicode: canonical decomposition followed by canonical composition (NFC).
    """
    if not isinstance(content, str):
        raise TypeError(f"Content must be a string, got {type(content).__name__}")

    # Step 1: Newline normalization (standardize all line endings to Unix \\n)
    normalized_newlines = content.replace("\r\n", "\n").replace("\r", "\n")

    # Step 2: Unicode normalization (NFC precomposed canonical form)
    normalized_unicode = unicodedata.normalize("NFC", normalized_newlines)

    return normalized_unicode


def hash_content(content: str) -> str:
    """
    Calculate the deterministic SHA-256 hex digest of content after canonical
    newline and Unicode NFC normalization.
    """
    normalized = normalize_content(content)
    content_bytes = normalized.encode("utf-8")
    return hashlib.sha256(content_bytes).hexdigest()


def verify_content_hash(content: str, expected_hash: str) -> bool:
    """
    Verify in constant time whether the provided content matches the expected
    SHA-256 digest.
    """
    if not isinstance(content, str) or not isinstance(expected_hash, str):
        return False
    computed = hash_content(content)
    return hmac.compare_digest(computed, expected_hash.strip().lower())
