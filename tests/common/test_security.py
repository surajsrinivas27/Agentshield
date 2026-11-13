"""
Tests for backend/common/security.py
Verifies:
- Strict secret validation (missing, weak, placeholder, identical secrets, algorithm restriction)
- Secret redaction in exception messages
- Argon2id password hashing and constant-time verification
- Signed JWT Bearer token generation, decoding, and expiration validation
- Strict RFC 8785 canonical JSON serialization (key order, UTC normalization, type validation, set rejection)
- Task Capability Manifest HMAC-SHA256 signing, strict type validation, and tamper detection
- Tamper-evident audit log cryptographic hash-chaining over complete audit objects (including delimiter tests)
"""

from datetime import datetime, timezone, timedelta, date
from enum import Enum
import pytest
import jwt

from backend.common.security import (
    canonicalize_json,
    compute_audit_entry_hash,
    create_access_token,
    decode_access_token,
    get_jwt_algorithm,
    get_jwt_secret_key,
    get_manifest_signing_secret,
    hash_password,
    sign_capability_manifest,
    validate_security_configuration,
    verify_audit_entry_hash,
    verify_capability_manifest,
    verify_password,
)


# --- 1. ENVIRONMENT SECRET MANAGEMENT TESTS ---


def test_secret_management_valid_configuration():
    """Verify that valid 32+ byte distinct secrets pass configuration validation."""
    status = validate_security_configuration()
    assert status["JWT_ALGORITHM"] == "HS256"
    assert status["JWT_SECRET_KEY_STATUS"] == "CONFIGURED"
    assert status["MANIFEST_SIGNING_SECRET_STATUS"] == "CONFIGURED"


def test_secret_management_missing_or_empty(monkeypatch):
    """Verify fail-closed behavior when a secret is missing or empty."""
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    with pytest.raises(ValueError, match="missing or empty"):
        get_jwt_secret_key()

    monkeypatch.setenv("JWT_SECRET_KEY", "   ")
    with pytest.raises(ValueError, match="missing or empty"):
        get_jwt_secret_key()


def test_secret_management_short_secret(monkeypatch):
    """Verify that secrets shorter than 32 bytes are rejected."""
    monkeypatch.setenv("JWT_SECRET_KEY", "too_short_secret_only_24_ch")
    with pytest.raises(ValueError, match="insufficient key length"):
        get_jwt_secret_key()


def test_secret_management_placeholder_rejected(monkeypatch):
    """Verify that placeholder strings from examples are strictly rejected."""
    placeholder_val = "change_this_to_a_secure_random_jwt_secret_minimum_32_bytes_long"
    monkeypatch.setenv("JWT_SECRET_KEY", placeholder_val)
    with pytest.raises(ValueError, match="contains an insecure placeholder"):
        get_jwt_secret_key()


def test_secret_management_identical_secrets_rejected(monkeypatch):
    """Verify that using the same secret for JWT and manifest signing is rejected."""
    same_secret = "same_secret_key_used_for_both_jwt_and_manifest_32b!"
    monkeypatch.setenv("JWT_SECRET_KEY", same_secret)
    monkeypatch.setenv("MANIFEST_SIGNING_SECRET", same_secret)
    with pytest.raises(ValueError, match="must be distinct, separate secrets"):
        get_manifest_signing_secret()


def test_secret_management_unapproved_algorithm_rejected(monkeypatch):
    """Verify that only the approved HS256 algorithm is permitted."""
    monkeypatch.setenv("JWT_ALGORITHM", "none")
    with pytest.raises(ValueError, match="Only the approved algorithm 'HS256' is allowed"):
        get_jwt_algorithm()

    monkeypatch.setenv("JWT_ALGORITHM", "RS256")
    with pytest.raises(ValueError, match="Only the approved algorithm 'HS256' is allowed"):
        get_jwt_algorithm()


def test_secret_redaction_in_exceptions(monkeypatch):
    """Verify that exception messages NEVER expose secret key values."""
    sensitive_material = "super_sensitive_password_placeholder_in_key_123456"
    monkeypatch.setenv("JWT_SECRET_KEY", sensitive_material)

    try:
        get_jwt_secret_key()
    except ValueError as exc:
        err_msg = str(exc)
        assert sensitive_material not in err_msg, "Secret material was leaked in exception message!"
        assert "JWT_SECRET_KEY" in err_msg


# --- 2. ARGON2ID TESTS ---


def test_argon2id_hashing_and_verification():
    """Verify that hash_password creates a valid Argon2id hash and verify_password works."""
    raw_pass = "SecureP@ssw0rd2026!"
    hashed = hash_password(raw_pass)

    assert hashed.startswith("$argon2id$")
    assert verify_password(raw_pass, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False


def test_argon2id_empty_and_corrupt_inputs():
    """Verify fail-closed behavior on empty strings or malformed hashes."""
    with pytest.raises(ValueError):
        hash_password("")

    assert verify_password("", "$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy") is False
    assert verify_password("some_password", "") is False
    assert verify_password("some_password", "not_an_argon2_hash") is False


# --- 3. JWT BEARER TOKEN TESTS ---


def test_jwt_token_lifecycle():
    """Verify access token creation and decoding preserves all security claims."""
    user_id = "user-uuid-1234"
    role = "Manager"
    username = "bob_manager"
    department = "Engineering"

    token = create_access_token(
        subject=user_id,
        role=role,
        username=username,
        department=department,
        expires_delta=timedelta(minutes=30),
    )

    claims = decode_access_token(token)
    assert claims["sub"] == user_id
    assert claims["role"] == role
    assert claims["username"] == username
    assert claims["department"] == department
    assert "jti" in claims
    assert "exp" in claims
    assert "iat" in claims
    assert claims["exp"] > claims["iat"]


def test_jwt_token_expiration():
    """Verify that expired tokens are rejected with jwt.ExpiredSignatureError."""
    token = create_access_token(
        subject="user-uuid-1",
        role="Employee",
        expires_delta=timedelta(seconds=-10),  # expired 10 seconds ago
    )

    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(token)


def test_jwt_token_wrong_secret():
    """Verify signature validation fails when signed with a different key."""
    other_valid_key = "attacker_secret_key_long_enough_32b_material_ok!"
    token = create_access_token(
        subject="user-uuid-1",
        role="Administrator",
        secret_key=other_valid_key,
    )

    with pytest.raises(jwt.InvalidSignatureError):
        decode_access_token(token)  # uses default server secret


# New tests for expires_at validation improvements

def test_expires_at_date_only_rejection(monkeypatch):
    """Reject date-only string without time component."""
    base = {
        "task_id": "TASK_001",
        "user_id": "USER_ALICE",
        "task_type": "SUMMARIZE_EMAIL",
        "allowed_operations": ["read_email"],
        "allowed_resource_ids": ["EMAIL_001"],
        "permitted_recipients": [],
        "expires_at": "2026-11-13",
    }
    with pytest.raises(ValueError, match="must be a full ISO-8601 datetime string with explicit timezone"):
        sign_capability_manifest(base)

def test_expires_at_timezone_naive_string_rejection(monkeypatch):
    """Reject timezone‑naive datetime string (no Z or offset)."""
    base = {
        "task_id": "TASK_001",
        "user_id": "USER_ALICE",
        "task_type": "SUMMARIZE_EMAIL",
        "allowed_operations": ["read_email"],
        "allowed_resource_ids": ["EMAIL_001"],
        "permitted_recipients": [],
        "expires_at": "2026-11-13T13:00:00",
    }
    with pytest.raises(ValueError, match="must be a full ISO-8601 datetime string with explicit timezone"):
        sign_capability_manifest(base)

def test_expires_at_valid_utc_string_acceptance(monkeypatch):
    """Accept a proper UTC ISO string and sign correctly."""
    base = {
        "task_id": "TASK_001",
        "user_id": "USER_ALICE",
        "task_type": "SUMMARIZE_EMAIL",
        "allowed_operations": ["read_email"],
        "allowed_resource_ids": ["EMAIL_001"],
        "permitted_recipients": [],
        "expires_at": "2026-11-13T13:00:00Z",
    }
    # Should not raise
    sig = sign_capability_manifest(base)
    assert isinstance(sig, str)
    # Verify that verification succeeds
    assert verify_capability_manifest(base, sig) is True

def test_expires_at_naive_datetime_rejection(monkeypatch):
    """Reject a timezone‑naive datetime object for expires_at."""
    base = {
        "task_id": "TASK_001",
        "user_id": "USER_ALICE",
        "task_type": "SUMMARIZE_EMAIL",
        "allowed_operations": ["read_email"],
        "allowed_resource_ids": ["EMAIL_001"],
        "permitted_recipients": [],
        "expires_at": datetime(2026, 11, 13, 13, 0, 0),  # naive datetime
    }
    with pytest.raises(ValueError, match="must be a timezone-aware datetime object"):
        sign_capability_manifest(base)

def test_expires_at_tzinfo_none_offset_rejection(monkeypatch):
    """Reject a datetime with tzinfo but utcoffset() returns None."""
    from datetime import tzinfo

    class NoOffset(tzinfo):
        def utcoffset(self, dt):
            return None
        def tzname(self, dt):
            return "NoOffset"
        def dst(self, dt):
            return None

    base = {
        "task_id": "TASK_001",
        "user_id": "USER_ALICE",
        "task_type": "SUMMARIZE_EMAIL",
        "allowed_operations": ["read_email"],
        "allowed_resource_ids": ["EMAIL_001"],
        "permitted_recipients": [],
        "expires_at": datetime(2026, 11, 13, 13, 0, 0, tzinfo=NoOffset()),
    }
    with pytest.raises(ValueError, match="must have a valid UTC offset"):
        sign_capability_manifest(base)

def test_expires_at_valid_offset_normalization(monkeypatch):
    """Offset timestamp should normalize to same UTC as equivalent Z timestamp."""
    manifest_utc = {
        "task_id": "TASK_001",
        "user_id": "USER_ALICE",
        "task_type": "SUMMARIZE_EMAIL",
        "allowed_operations": ["read_email"],
        "allowed_resource_ids": ["EMAIL_001"],
        "permitted_recipients": [],
        "expires_at": "2026-11-13T13:00:00Z",
    }
    manifest_offset = {
        "task_id": "TASK_001",
        "user_id": "USER_ALICE",
        "task_type": "SUMMARIZE_EMAIL",
        "allowed_operations": ["read_email"],
        "allowed_resource_ids": ["EMAIL_001"],
        "permitted_recipients": [],
        "expires_at": "2026-11-13T08:00:00-05:00",
    }
    sig_utc = sign_capability_manifest(manifest_utc)
    sig_offset = sign_capability_manifest(manifest_offset)
    assert sig_utc == sig_offset
    assert verify_capability_manifest(manifest_offset, sig_utc) is True


def test_expires_at_tzinfo_none_offset_rejection(monkeypatch):
    """Reject a datetime with tzinfo but utcoffset() returns None."""
    from datetime import tzinfo

    class NoOffset(tzinfo):
        def utcoffset(self, dt):
            return None
        def tzname(self, dt):
            return "NoOffset"
        def dst(self, dt):
            return None

    base = {
        "task_id": "TASK_001",
        "user_id": "USER_ALICE",
        "task_type": "SUMMARIZE_EMAIL",
        "allowed_operations": ["read_email"],
        "allowed_resource_ids": ["EMAIL_001"],
        "permitted_recipients": [],
        "expires_at": datetime(2026, 11, 13, 13, 0, 0, tzinfo=NoOffset()),
    }
    with pytest.raises(ValueError, match="must have a valid UTC offset"):
        sign_capability_manifest(base)

# Existing tests continue below...


def test_canonicalize_json_key_order_independence():
    """Verify RFC 8785 serialization produces identical bytes regardless of key insertion order."""
    dict_a = {"zebra": "last", "alpha": "first", "middle": 42}
    dict_b = {"alpha": "first", "middle": 42, "zebra": "last"}

    bytes_a = canonicalize_json(dict_a)
    bytes_b = canonicalize_json(dict_b)

    assert bytes_a == bytes_b
    assert bytes_a == b'{"alpha":"first","middle":42,"zebra":"last"}'


def test_canonicalize_json_rejects_non_string_keys():
    """Verify that non-string dictionary keys are strictly rejected with TypeError."""
    with pytest.raises(TypeError, match="dictionary keys must be strings"):
        canonicalize_json({1: "integer_key"})

    with pytest.raises(TypeError, match="dictionary keys must be strings"):
        canonicalize_json({True: "bool_key"})


def test_canonicalize_json_rejects_unordered_sets():
    """Verify that Python sets are strictly rejected to prevent nondeterministic output."""
    with pytest.raises(TypeError, match="Unordered Python sets are not permitted"):
        canonicalize_json({"tags": {"tag1", "tag2"}})


def test_canonicalize_json_datetime_normalization_to_utc():
    """Verify that timezone-aware datetimes with different offsets normalize to identical UTC output."""
    # 12:00:00 UTC
    dt_utc = datetime(2026, 11, 13, 12, 0, 0, tzinfo=timezone.utc)
    # 07:00:00 EST (UTC-5) -> equivalent to 12:00:00 UTC
    tz_est = timezone(timedelta(hours=-5))
    dt_est = datetime(2026, 11, 13, 7, 0, 0, tzinfo=tz_est)

    bytes_utc = canonicalize_json({"time": dt_utc})
    bytes_est = canonicalize_json({"time": dt_est})

    assert bytes_utc == bytes_est
    assert b"2026-11-13T12:00:00+00:00" in bytes_utc


def test_canonicalize_json_types_supported():
    """Verify support for lists, tuples, dates, datetimes, and Enums."""
    class StateEnum(str, Enum):
        ACTIVE = "active"

    data = {
        "status": StateEnum.ACTIVE,
        "date": date(2026, 11, 13),
        "items": (1, "two", 3.5, None, False),
    }

    serialized = canonicalize_json(data)
    assert b'"status":"active"' in serialized
    assert b'"date":"2026-11-13"' in serialized
    assert b'"items":[1,"two",3.5,null,false]' in serialized


# --- 5. TASK CAPABILITY MANIFEST HMAC TESTS ---


def test_capability_manifest_signing_and_verification():
    """Verify signing and verifying an untampered TaskCapabilityManifest."""
    manifest = {
        "task_id": "TASK_001",
        "user_id": "USER_ALICE",
        "task_type": "SUMMARIZE_EMAIL",
        "allowed_operations": ["read_email", "summarize_email"],
        "allowed_resource_ids": ["EMAIL_001", "EMAIL_002"],
        "permitted_recipients": ["alice@company.com"],
        "expires_at": datetime(2026, 11, 13, 13, 0, 0, tzinfo=timezone.utc),
    }

    sig = sign_capability_manifest(manifest)
    assert isinstance(sig, str)
    assert len(sig) == 64

    assert verify_capability_manifest(manifest, sig) is True


def test_capability_manifest_deterministic_sorting():
    """Verify that different list ordering in manifest fields produces identical signatures."""
    manifest_a = {
        "task_id": "TASK_001",
        "user_id": "USER_ALICE",
        "task_type": "SUMMARIZE_EMAIL",
        "allowed_operations": ["read_email", "summarize_email"],
        "allowed_resource_ids": ["B", "A"],
        "permitted_recipients": ["z@company.com", "a@company.com"],
        "expires_at": "2026-11-13T13:00:00+00:00",
    }
    manifest_b = {
        "task_id": "TASK_001",
        "user_id": "USER_ALICE",
        "task_type": "SUMMARIZE_EMAIL",
        "allowed_operations": ["summarize_email", "read_email"],  # reversed order
        "allowed_resource_ids": ["A", "B"],                       # reversed order
        "permitted_recipients": ["a@company.com", "z@company.com"],# reversed order
        "expires_at": "2026-11-13T13:00:00+00:00",
    }

    sig_a = sign_capability_manifest(manifest_a)
    sig_b = sign_capability_manifest(manifest_b)

    assert sig_a == sig_b
    assert verify_capability_manifest(manifest_a, sig_b) is True


def test_capability_manifest_tamper_detection():
    """Verify that tampering with any field in the manifest breaks the signature."""
    manifest = {
        "task_id": "TASK_001",
        "user_id": "USER_ALICE",
        "task_type": "SUMMARIZE_EMAIL",
        "allowed_operations": ["read_email", "summarize_email"],
        "allowed_resource_ids": ["EMAIL_001"],
        "permitted_recipients": [],
        "expires_at": "2026-11-13T13:00:00+00:00",
    }

    sig = sign_capability_manifest(manifest)

    # 1. Tamper operations (privilege escalation)
    tampered_ops = dict(manifest)
    tampered_ops["allowed_operations"] = ["read_email", "summarize_email", "forward_email"]
    assert verify_capability_manifest(tampered_ops, sig) is False

    # 2. Tamper user ID
    tampered_user = dict(manifest)
    tampered_user["user_id"] = "USER_ATTACKER"
    assert verify_capability_manifest(tampered_user, sig) is False

    # 3. Tamper task ID
    tampered_task = dict(manifest)
    tampered_task["task_id"] = "TASK_999"
    assert verify_capability_manifest(tampered_task, sig) is False

    # 4. Tamper expiry
    tampered_exp = dict(manifest)
    tampered_exp["expires_at"] = "2026-11-13T14:00:00+00:00"
    assert verify_capability_manifest(tampered_exp, sig) is False


def test_capability_manifest_type_validation():
    """Verify that manifest validation rejects invalid types instead of converting them silently."""
    base_manifest = {
        "task_id": "TASK_001",
        "user_id": "USER_ALICE",
        "task_type": "SUMMARIZE_EMAIL",
        "allowed_operations": ["read_email"],
        "allowed_resource_ids": ["EMAIL_001"],
        "permitted_recipients": [],
        "expires_at": "2026-11-13T13:00:00+00:00",
    }

    # 1. Non-string identifier
    inv_id = dict(base_manifest, task_id="")
    with pytest.raises(ValueError, match="must be a non-empty string"):
        sign_capability_manifest(inv_id)

    # 2. Non-list for list field (e.g. integer instead of list)
    inv_ops_type = dict(base_manifest, allowed_operations=12345)
    with pytest.raises(TypeError, match="must be a list or tuple"):
        sign_capability_manifest(inv_ops_type)

    # 3. Non-string element inside list field
    inv_ops_item = dict(base_manifest, allowed_operations=["read_email", 999])
    with pytest.raises(TypeError, match="must be a string"):
        sign_capability_manifest(inv_ops_item)

    # 4. Missing required field
    missing_field = dict(base_manifest)
    del missing_field["allowed_operations"]
    with pytest.raises(ValueError, match="missing required keys"):
        sign_capability_manifest(missing_field)

    # 5. Unknown manifest keys rejected
    unknown_key_manifest = dict(base_manifest, unauthorized_privilege="bypass_auth")
    with pytest.raises(ValueError, match="Unknown manifest keys not permitted"):
        sign_capability_manifest(unknown_key_manifest)

    # 6. Malformed expires_at string
    malformed_date = dict(base_manifest, expires_at="not_a_valid_iso_datetime")
    with pytest.raises(ValueError, match="malformed ISO datetime"):
        sign_capability_manifest(malformed_date)

    # 7. Empty expires_at string
    empty_date = dict(base_manifest, expires_at="   ")
    with pytest.raises(ValueError, match="cannot be empty"):
        sign_capability_manifest(empty_date)

    # 8. Invalid expires_at type (integer)
    invalid_date_type = dict(base_manifest, expires_at=1731500000)
    with pytest.raises(TypeError, match="must be a datetime object or ISO string"):
        sign_capability_manifest(invalid_date_type)


def test_capability_manifest_timezone_normalization():
    """Verify that equivalent timezone-aware timestamps produce identical manifest signatures."""
    manifest_utc = {
        "task_id": "TASK_001",
        "user_id": "USER_ALICE",
        "task_type": "SUMMARIZE_EMAIL",
        "allowed_operations": ["read_email"],
        "allowed_resource_ids": ["EMAIL_001"],
        "permitted_recipients": [],
        "expires_at": datetime(2026, 11, 13, 13, 0, 0, tzinfo=timezone.utc),
    }
    manifest_est = dict(
        manifest_utc,
        expires_at=datetime(2026, 11, 13, 8, 0, 0, tzinfo=timezone(timedelta(hours=-5))),
    )

    sig_utc = sign_capability_manifest(manifest_utc)
    sig_est = sign_capability_manifest(manifest_est)

    assert sig_utc == sig_est
    assert verify_capability_manifest(manifest_utc, sig_est) is True


def test_capability_manifest_wrong_secret():
    """Verify that verifying manifest with a different secret returns False."""
    manifest = {
        "task_id": "TASK_001",
        "user_id": "USER_ALICE",
        "task_type": "SUMMARIZE_EMAIL",
        "allowed_operations": ["read_email"],
        "allowed_resource_ids": ["EMAIL_001"],
        "permitted_recipients": [],
        "expires_at": "2026-11-13T13:00:00+00:00",
    }
    sig = sign_capability_manifest(manifest)
    wrong_key = "different_manifest_secret_at_least_32_bytes_ok!"
    assert verify_capability_manifest(manifest, sig, secret_key=wrong_key) is False


# --- 6. COMPLETE OBJECT AUDIT LOG HASH TESTS ---


def test_audit_log_hash_complete_object():
    """Verify calculation and constant-time verification over complete audit entry objects."""
    genesis_hash = "0" * 64

    entry_hash = compute_audit_entry_hash(
        sequence_number=1,
        previous_hash=genesis_hash,
        timestamp_iso="2026-11-13T12:00:00+00:00",
        event_type="AUTH_LOGIN",
        actor_id="USER_ALICE",
        payload_dict={"ip": "127.0.0.1", "action": "login_success"},
    )
    assert len(entry_hash) == 64

    # Verify matching
    assert verify_audit_entry_hash(
        sequence_number=1,
        previous_hash=genesis_hash,
        timestamp_iso="2026-11-13T12:00:00+00:00",
        event_type="AUTH_LOGIN",
        actor_id="USER_ALICE",
        payload_dict={"ip": "127.0.0.1", "action": "login_success"},
        expected_entry_hash=entry_hash,
    ) is True


def test_audit_log_header_field_changes_break_hash():
    """Verify that modifying ANY header field or payload alters the computed hash."""
    base_args = {
        "sequence_number": 1,
        "previous_hash": "0" * 64,
        "timestamp_iso": "2026-11-13T12:00:00+00:00",
        "event_type": "AUTH_LOGIN",
        "actor_id": "USER_ALICE",
        "payload_dict": {"data": "original"},
    }
    base_hash = compute_audit_entry_hash(**base_args)

    # 1. Modify sequence_number
    args_seq = dict(base_args, sequence_number=2)
    assert compute_audit_entry_hash(**args_seq) != base_hash

    # 2. Modify previous_hash
    args_prev = dict(base_args, previous_hash="1" * 64)
    assert compute_audit_entry_hash(**args_prev) != base_hash

    # 3. Modify timestamp_iso
    args_time = dict(base_args, timestamp_iso="2026-11-13T12:00:01+00:00")
    assert compute_audit_entry_hash(**args_time) != base_hash

    # 4. Modify event_type
    args_evt = dict(base_args, event_type="AUTH_LOGOUT")
    assert compute_audit_entry_hash(**args_evt) != base_hash

    # 5. Modify actor_id
    args_actor = dict(base_args, actor_id="USER_BOB")
    assert compute_audit_entry_hash(**args_actor) != base_hash

    # 6. Modify payload_dict
    args_payload = dict(base_args, payload_dict={"data": "tampered"})
    assert compute_audit_entry_hash(**args_payload) != base_hash


def test_audit_log_ambiguous_delimiter_scenario():
    """
    Verify that fields containing delimiter characters ('|', ',', ':')
    cannot produce collision attacks under complete RFC 8785 canonical object serialization.
    """
    # Scenario A: event_type contains pipe
    hash_a = compute_audit_entry_hash(
        sequence_number=1,
        previous_hash="0" * 64,
        timestamp_iso="2026-11-13T12:00:00+00:00",
        event_type="AUTH|LOGIN",
        actor_id="USER",
        payload_dict={"key": "val"},
    )

    # Scenario B: actor_id shifted into event_type under ambiguous pipe parsing
    hash_b = compute_audit_entry_hash(
        sequence_number=1,
        previous_hash="0" * 64,
        timestamp_iso="2026-11-13T12:00:00+00:00",
        event_type="AUTH",
        actor_id="LOGIN|USER",
        payload_dict={"key": "val"},
    )

    # In canonical JSON, these are distinct key-value pairs and MUST NOT collide
    assert hash_a != hash_b
