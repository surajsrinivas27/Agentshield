"""
AgentShield Common Infrastructure Package
Modular Monolith: Database, Security Primitives, and Shared Utilities.
"""

from backend.common.database import (
    Base,
    DATABASE_URL,
    SessionLocal,
    begin_immediate,
    engine,
    get_db,
    get_sqlite_pragmas,
    init_db,
)
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

__all__ = [
    # Database Infrastructure
    "Base",
    "DATABASE_URL",
    "SessionLocal",
    "begin_immediate",
    "engine",
    "get_db",
    "get_sqlite_pragmas",
    "init_db",
    # Security Utilities
    "canonicalize_json",
    "compute_audit_entry_hash",
    "create_access_token",
    "decode_access_token",
    "get_jwt_algorithm",
    "get_jwt_secret_key",
    "get_manifest_signing_secret",
    "hash_password",
    "sign_capability_manifest",
    "validate_security_configuration",
    "verify_audit_entry_hash",
    "verify_capability_manifest",
    "verify_password",
]
