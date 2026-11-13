"""
Shared Security Utilities for AgentShield
Modular Monolith: Cryptographic primitives, token management, and canonicalization.

Provides:
- Strict environment-based secret validation with zero hardcoded fallbacks
- Argon2id password hashing and constant-time verification (RFC 9106)
- Signed Bearer JWT token generation, decoding, and expiration validation (HS256 only)
- Strict RFC 8785 canonical JSON serialization (via rfc8785)
- Server-held HMAC-SHA256 Task Capability Manifest signing and verification
- Complete object-level RFC 8785 tamper-evident audit log hash-chaining
"""

import hashlib
import hmac
import os
import uuid
from datetime import datetime, timezone, timedelta, date
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

import argon2
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from dotenv import load_dotenv
import jwt
import rfc8785

# Load environment configuration if present
load_dotenv()

# Forbidden placeholder fragments: application configuration fails closed if detected
FORBIDDEN_PLACEHOLDER_SUBSTRINGS = (
    "change_this",
    "replace_with",
    "your_secret",
    "default_secret",
    "placeholder",
    "example_key",
)


# --- 1. ENVIRONMENT SECRET MANAGEMENT ---


def _validate_secret_material(env_var_name: str, secret_val: Optional[str]) -> str:
    """
    Validates secret key material strictly:
    - Must be a non-empty string.
    - Must not contain forbidden placeholder substrings.
    - Must contain at least 32 bytes of key material.
    Fails closed and NEVER exposes secret values in error messages.
    """
    if not secret_val or not isinstance(secret_val, str) or not secret_val.strip():
        raise ValueError(
            f"Security configuration error: '{env_var_name}' is missing or empty. "
            f"Set a cryptographically secure key of at least 32 bytes in your environment."
        )

    stripped = secret_val.strip()
    if len(stripped.encode("utf-8")) < 32:
        raise ValueError(
            f"Security configuration error: '{env_var_name}' has insufficient key length. "
            f"Must contain at least 32 bytes of key material."
        )

    lowered = stripped.lower()
    for placeholder in FORBIDDEN_PLACEHOLDER_SUBSTRINGS:
        if placeholder in lowered:
            raise ValueError(
                f"Security configuration error: '{env_var_name}' contains an insecure placeholder. "
                f"Replace it with a securely generated key."
            )

    return stripped


def get_jwt_secret_key() -> str:
    """Retrieves and validates JWT_SECRET_KEY from environment."""
    return _validate_secret_material("JWT_SECRET_KEY", os.getenv("JWT_SECRET_KEY"))


def get_manifest_signing_secret() -> str:
    """
    Retrieves and validates MANIFEST_SIGNING_SECRET from environment.
    Ensures MANIFEST_SIGNING_SECRET and JWT_SECRET_KEY are distinct.
    """
    manifest_sec = _validate_secret_material(
        "MANIFEST_SIGNING_SECRET",
        os.getenv("MANIFEST_SIGNING_SECRET"),
    )
    jwt_sec = os.getenv("JWT_SECRET_KEY", "").strip()
    if jwt_sec and manifest_sec == jwt_sec:
        raise ValueError(
            "Security configuration error: 'MANIFEST_SIGNING_SECRET' and 'JWT_SECRET_KEY' "
            "must be distinct, separate secrets."
        )
    return manifest_sec


def get_jwt_algorithm() -> str:
    """Retrieves and enforces that JWT_ALGORITHM is strictly HS256."""
    algo = os.getenv("JWT_ALGORITHM", "HS256")
    if algo != "HS256":
        raise ValueError(
            f"Security configuration error: JWT algorithm '{algo}' is not permitted. "
            f"Only the approved algorithm 'HS256' is allowed."
        )
    return algo


def get_access_token_expire_minutes() -> int:
    """Retrieves access token expiration minutes from environment (defaults to 60)."""
    raw = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")
    try:
        val = int(raw)
        if val <= 0:
            raise ValueError()
        return val
    except ValueError:
        raise ValueError("ACCESS_TOKEN_EXPIRE_MINUTES must be a positive integer.")


def validate_security_configuration() -> Dict[str, str]:
    """
    Validates complete application security configuration on startup.
    Fails closed if any secret is missing, placeholder, weak, identical, or unapproved algorithm.
    Does NOT log or leak secret values.
    """
    get_jwt_secret_key()
    get_manifest_signing_secret()
    algo = get_jwt_algorithm()
    return {
        "JWT_ALGORITHM": algo,
        "JWT_SECRET_KEY_STATUS": "CONFIGURED",
        "MANIFEST_SIGNING_SECRET_STATUS": "CONFIGURED",
    }


# --- 2. ARGON2ID PASSWORD HASHING ---

# Configure Argon2id according to RFC 9106 recommended parameters:
# Memory cost: 65536 KiB (64 MiB), Time cost: 3 iterations, Parallelism: 4 threads
_password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=argon2.Type.ID,
)


def hash_password(plain_password: str) -> str:
    """
    Hashes a plaintext password using Argon2id with memory-hard RFC 9106 parameters.
    """
    if not plain_password or not isinstance(plain_password, str):
        raise ValueError("Password must be a non-empty string.")
    return _password_hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plaintext password against an Argon2id hash in constant time.
    Fails closed (returns False) on any mismatch, corruption, or invalid format.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return _password_hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception:
        return False


# --- 3. SIGNED BEARER TOKENS (JWT) ---


def create_access_token(
    subject: str,
    role: str,
    username: Optional[str] = None,
    department: Optional[str] = None,
    expires_delta: Optional[timedelta] = None,
    jti: Optional[str] = None,
    secret_key: Optional[str] = None,
    algorithm: Optional[str] = None,
) -> str:
    """
    Creates a signed JWT bearer token containing verified identity and claim nonce.

    SECURITY ARCHITECTURE NOTE:
    Claims embedded in the JWT (such as role, username, department) are strictly
    informational convenience claims for frontend display. The Authorization Gateway
    in Phase 2 MUST query the database on every authenticated request as the sole
    source of truth for role, active status, revoked tokens (jti check), and
    token invalidation (iat >= user.token_valid_after).
    """
    if not subject:
        raise ValueError("Token subject (user_id) cannot be empty.")

    now = datetime.now(timezone.utc)
    expire_minutes = get_access_token_expire_minutes()
    expire = now + (expires_delta if expires_delta else timedelta(minutes=expire_minutes))

    token_jti = jti or str(uuid.uuid4())
    key = secret_key if secret_key is not None else get_jwt_secret_key()
    algo = algorithm if algorithm is not None else get_jwt_algorithm()
    if algo != "HS256":
        raise ValueError(f"Only approved JWT algorithm 'HS256' is allowed, got '{algo}'.")

    payload: Dict[str, Any] = {
        "sub": str(subject),
        "role": str(role),
        "jti": token_jti,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    if username:
        payload["username"] = str(username)
    if department:
        payload["department"] = str(department)

    return jwt.encode(payload, key, algorithm=algo)


def decode_access_token(
    token: str,
    secret_key: Optional[str] = None,
    algorithm: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Decodes and cryptographically verifies a signed JWT bearer token.
    Enforces signature validity and expiration check.
    Raises jwt.PyJWTError subclasses upon invalid token or expired signature.

    Returns claims dict containing:
      - 'sub': User ID
      - 'jti': Token nonce (for checking revoked_tokens table in Phase 2)
      - 'iat': Token issued-at timestamp (for checking user.token_valid_after in Phase 2)
      - 'exp': Expiration timestamp
      - 'role', 'username', 'department': Informational claims
    """
    key = secret_key if secret_key is not None else get_jwt_secret_key()
    algo = algorithm if algorithm is not None else get_jwt_algorithm()
    if algo != "HS256":
        raise ValueError(f"Only approved JWT algorithm 'HS256' is allowed, got '{algo}'.")

    return jwt.decode(
        token,
        key,
        algorithms=[algo],
        options={"require": ["sub", "exp", "iat", "jti"]},
    )


# --- 4. STRICT RFC 8785 CANONICAL JSON SERIALIZATION ---


def _normalize_for_canonicalization(obj: Any) -> Any:
    """
    Recursively normalizes Python objects into types serializable by rfc8785:
    - Dicts: strictly validates that all keys are strings (rejects non-string keys).
    - Rejects sets (unordered collections cause non-deterministic output).
    - Lists/tuples: recursively normalizes elements.
    - Datetime: timezone-aware normalized to UTC; naive assumed UTC.
    - Date: ISO-8601 string.
    - Enum: underlying value normalized.
    - Primitives (str, int, float, bool, None): preserved as-is.
    """
    if isinstance(obj, dict):
        normalized_dict = {}
        for k, v in obj.items():
            if not isinstance(k, str):
                raise TypeError(
                    f"Canonical JSON dictionary keys must be strings, got key of type {type(k).__name__}"
                )
            normalized_dict[k] = _normalize_for_canonicalization(v)
        return normalized_dict

    if isinstance(obj, set):
        raise TypeError(
            "Unordered Python sets are not permitted in canonical JSON serialization; "
            "use an explicitly ordered list or tuple."
        )

    if isinstance(obj, (list, tuple)):
        return [_normalize_for_canonicalization(item) for item in obj]

    if isinstance(obj, datetime):
        if obj.tzinfo is None:
            # Naive datetime: assume UTC
            dt_utc = obj.replace(tzinfo=timezone.utc)
        else:
            # Timezone-aware datetime: normalize to UTC
            dt_utc = obj.astimezone(timezone.utc)
        return dt_utc.isoformat()

    if isinstance(obj, date):
        return obj.isoformat()

    if isinstance(obj, Enum):
        return _normalize_for_canonicalization(obj.value)

    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj

    raise TypeError(f"Object of type '{type(obj).__name__}' is not serializable to canonical JSON.")


def canonicalize_json(data: Any) -> bytes:
    """
    Serializes data into RFC 8785 canonical JSON bytes.
    Guarantees deterministic, reproducible byte output regardless of dict key ordering.
    """
    normalized = _normalize_for_canonicalization(data)
    return rfc8785.dumps(normalized)


# --- 5. TASK CAPABILITY MANIFEST HMAC-SHA256 SIGNING ---


def _build_canonical_manifest_dict(manifest_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates manifest fields strictly and extracts deterministic structure for signing:
    - Rejects any unknown keys to guarantee no unsigned attributes influence authorization.
    - Requires task_id, user_id, task_type, allowed_operations, allowed_resource_ids,
      permitted_recipients, and expires_at.
    - Validates string identifiers and element types inside lists.
    - Validates expires_at as a valid datetime object or ISO-8601 string, normalizing
      timezone-aware timestamps to UTC. Rejects malformed timestamps.
    - Sorts list fields deterministically.
    """
    if not isinstance(manifest_payload, dict):
        raise TypeError(f"Manifest payload must be a dictionary, got {type(manifest_payload).__name__}")

    required_keys = {
        "task_id",
        "user_id",
        "task_type",
        "allowed_operations",
        "allowed_resource_ids",
        "permitted_recipients",
        "expires_at",
    }
    payload_keys = set(manifest_payload.keys())

    # 1. Reject unknown manifest keys to prevent unsigned authorization properties
    unknown_keys = payload_keys - required_keys
    if unknown_keys:
        raise ValueError(
            f"Unknown manifest keys not permitted in signed capability structure: {sorted(unknown_keys)}"
        )

    # 2. Check for missing required keys
    missing_keys = required_keys - payload_keys
    if missing_keys:
        raise ValueError(f"Cannot sign capability manifest: missing required keys {sorted(missing_keys)}")

    # 3. Validate string identifier fields
    for id_field in ["task_id", "user_id", "task_type"]:
        val = manifest_payload[id_field]
        if not isinstance(val, str) or not val.strip():
            raise ValueError(f"Manifest field '{id_field}' must be a non-empty string, got {type(val).__name__}")

    # 4. Validate and sort list fields (reject invalid types, reject non-string elements)
    def _validate_and_sort_strings(field_name: str) -> List[str]:
        raw_val = manifest_payload[field_name]
        if not isinstance(raw_val, (list, tuple)):
            raise TypeError(
                f"Manifest field '{field_name}' must be a list or tuple of strings, got {type(raw_val).__name__}"
            )
        elements = []
        for idx, item in enumerate(raw_val):
            if not isinstance(item, str):
                raise TypeError(
                    f"Element at index {idx} in manifest field '{field_name}' must be a string, got {type(item).__name__}"
                )
            elements.append(item)
        # Deterministically sort to ensure signature is order-independent
        return sorted(elements)

    # 5. Validate and normalize expires_at (must be valid datetime or ISO-8601 string)
    expires_at = manifest_payload["expires_at"]
    if isinstance(expires_at, datetime):
        # Require timezone-aware datetime with a valid UTC offset
        if expires_at.tzinfo is None:
            raise ValueError("Manifest field 'expires_at' must be a timezone-aware datetime object.")
        if expires_at.utcoffset() is None:
            raise ValueError("Manifest field 'expires_at' must have a valid UTC offset.")
        dt_utc = expires_at.astimezone(timezone.utc)
        normalized_expires_at = dt_utc.isoformat()
    elif isinstance(expires_at, str):
        if not expires_at.strip():
            raise ValueError("Manifest field 'expires_at' string cannot be empty.")
        # Define regex patterns for validation
        full_iso_tz_pattern = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$'
        date_only_pattern = r'^\d{4}-\d{2}-\d{2}$'
        naive_datetime_pattern = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?$'
        import re
        if re.fullmatch(full_iso_tz_pattern, expires_at):
            # Full ISO with timezone; attempt to parse
            try:
                parsed_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            except (ValueError, TypeError) as exc:
                raise ValueError(
                    f"Manifest field 'expires_at' contains malformed ISO datetime: '{expires_at}'"
                ) from exc
        elif re.fullmatch(date_only_pattern, expires_at):
            raise ValueError(
                "Manifest field 'expires_at' must be a full ISO-8601 datetime string with explicit timezone."
            )
        elif re.fullmatch(naive_datetime_pattern, expires_at):
            raise ValueError(
                "Manifest field 'expires_at' must be a full ISO-8601 datetime string with explicit timezone."
            )
        else:
            # Any other format considered malformed
            raise ValueError(
                f"Manifest field 'expires_at' contains malformed ISO datetime: '{expires_at}'"
            )

        # Normalize to UTC
        if parsed_dt.tzinfo is None:
            dt_utc = parsed_dt.replace(tzinfo=timezone.utc)
        else:
            dt_utc = parsed_dt.astimezone(timezone.utc)
        normalized_expires_at = dt_utc.isoformat()
    else:
        raise TypeError(
            f"Manifest field 'expires_at' must be a datetime object or ISO string, got {type(expires_at).__name__}"
        )

    return {
        "task_id": manifest_payload["task_id"].strip(),
        "user_id": manifest_payload["user_id"].strip(),
        "task_type": manifest_payload["task_type"].strip(),
        "allowed_operations": _validate_and_sort_strings("allowed_operations"),
        "allowed_resource_ids": _validate_and_sort_strings("allowed_resource_ids"),
        "permitted_recipients": _validate_and_sort_strings("permitted_recipients"),
        "expires_at": normalized_expires_at,
    }


def sign_capability_manifest(
    manifest_payload: Dict[str, Any],
    secret_key: Optional[str] = None,
) -> str:
    """
    Cryptographically signs a TaskCapabilityManifest using HMAC-SHA256.
    Binds task_id, user_id, task_type, allowed_operations, allowed_resource_ids,
    permitted_recipients, and expires_at.
    """
    canonical_dict = _build_canonical_manifest_dict(manifest_payload)
    canonical_bytes = canonicalize_json(canonical_dict)
    key = secret_key if secret_key is not None else get_manifest_signing_secret()
    key_bytes = key.encode("utf-8")
    return hmac.new(key_bytes, canonical_bytes, hashlib.sha256).hexdigest()


def verify_capability_manifest(
    manifest_payload: Dict[str, Any],
    signature: str,
    secret_key: Optional[str] = None,
) -> bool:
    """
    Verifies a TaskCapabilityManifest's HMAC-SHA256 signature in constant time.
    Returns True if valid and untampered; False otherwise.

    IMPORTANT SECURITY NOTE:
    Cryptographic HMAC verification validates that the manifest contents were generated
    by this server and have not been tampered with. It does NOT assert that the manifest
    is currently unexpired or that the task is currently active. The future authorization
    gateway must independently verify:
      1. current_utc_time < manifest["expires_at"]
      2. manifest["task_id"] matches the active task context in SQLite
      3. manifest["user_id"] matches the authenticated task initiator
      4. Task status in SQLite is active.
    """
    if not signature or not isinstance(signature, str):
        return False
    try:
        expected_sig = sign_capability_manifest(manifest_payload, secret_key=secret_key)
        return hmac.compare_digest(expected_sig, signature)
    except Exception:
        return False


# --- 6. TAMPER-EVIDENT AUDIT LOG HASH-CHAINING ---


def compute_audit_entry_hash(
    sequence_number: int,
    previous_hash: str,
    timestamp_iso: str,
    event_type: str,
    actor_id: str,
    payload_dict: Dict[str, Any],
) -> str:
    """
    Calculates the SHA-256 cryptographic entry hash for an audit log record.
    Constructs a complete audit entry object, canonicalizes it with RFC 8785,
    and calculates SHA-256 over the canonical bytes.

    Eliminates delimiter collisions and guarantees deterministic, tamper-evident hash chaining.
    """
    if not isinstance(sequence_number, int):
        raise TypeError(f"sequence_number must be an integer, got {type(sequence_number).__name__}")
    if not isinstance(previous_hash, str) or not previous_hash:
        raise ValueError("previous_hash must be a non-empty string.")
    if not isinstance(timestamp_iso, str) or not timestamp_iso:
        raise ValueError("timestamp_iso must be a non-empty string.")
    if not isinstance(event_type, str) or not event_type:
        raise ValueError("event_type must be a non-empty string.")
    if not isinstance(actor_id, str) or not actor_id:
        raise ValueError("actor_id must be a non-empty string.")
    if not isinstance(payload_dict, dict):
        raise TypeError(f"payload_dict must be a dictionary, got {type(payload_dict).__name__}")

    audit_entry_obj = {
        "sequence_number": sequence_number,
        "previous_hash": previous_hash,
        "timestamp": timestamp_iso,
        "event_type": event_type,
        "actor_id": actor_id,
        "payload": payload_dict,
    }

    canonical_bytes = canonicalize_json(audit_entry_obj)
    return hashlib.sha256(canonical_bytes).hexdigest()


def verify_audit_entry_hash(
    sequence_number: int,
    previous_hash: str,
    timestamp_iso: str,
    event_type: str,
    actor_id: str,
    payload_dict: Dict[str, Any],
    expected_entry_hash: str,
) -> bool:
    """
    Verifies an audit entry's cryptographic hash in constant time.
    Returns True if valid; False if tampered or mismatched.
    """
    if not expected_entry_hash or not isinstance(expected_entry_hash, str):
        return False
    try:
        calculated = compute_audit_entry_hash(
            sequence_number=sequence_number,
            previous_hash=previous_hash,
            timestamp_iso=timestamp_iso,
            event_type=event_type,
            actor_id=actor_id,
            payload_dict=payload_dict,
        )
        return hmac.compare_digest(calculated, expected_entry_hash)
    except Exception:
        return False
