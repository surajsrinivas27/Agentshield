"""
Interactive User Bootstrap CLI — AgentShield Stage 3

Command:
    python -m backend.authorization.bootstrap_user

Provides secure, interactive account creation for bootstrapping initial users.
Invariants:
- Never creates hardcoded or default credentials.
- Prompts securely for password using getpass (hidden input).
- Validates password confirmation and rejects empty values.
- Enforces supported role constraints (Employee, Manager, Administrator).
- Hashes password using Argon2id (hash_password).
- Rejects creation if username already exists (never overwrites).
- Never prints or logs the plaintext password.
"""

import getpass
import sys
import uuid
from typing import Optional

from sqlalchemy import select

import backend.model_registry  # noqa: F401
from backend.authorization.models import SUPPORTED_ROLES, User
from backend.common.database import SessionLocal, init_db
from backend.common.security import hash_password


def create_user_record(
    username: str,
    password: str,
    role: str,
    department: Optional[str] = None,
) -> User:
    """
    Programmatic helper for creating a user record with strict validation.
    Used by CLI runner and automated integration tests.
    """
    if not username or not username.strip():
        raise ValueError("Username cannot be empty.")
    if not password:
        raise ValueError("Password cannot be empty.")

    matched_role = None
    for r in SUPPORTED_ROLES:
        if r.lower() == role.strip().lower():
            matched_role = r
            break
    if not matched_role:
        raise ValueError(
            f"Invalid role {role!r}. Supported roles: {', '.join(sorted(SUPPORTED_ROLES))}"
        )

    init_db()
    db = SessionLocal()
    try:
        stmt = select(User).where(User.username == username.strip())
        existing = db.execute(stmt).scalar_one_or_none()
        if existing is not None:
            raise ValueError(f"User with username {username!r} already exists.")

        hashed_pwd = hash_password(password)

        new_user = User(
            id=str(uuid.uuid4()),
            username=username.strip(),
            password_hash=hashed_pwd,
            role=matched_role,
            department=department.strip() if department else None,
            is_active=True,
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user
    finally:
        db.close()


def main():
    """Main CLI entrypoint for interactive bootstrap."""
    print("==========================================")
    print(" AgentShield — Secure User Bootstrap CLI  ")
    print("==========================================")

    try:
        username = input("Enter username: ").strip()
        if not username:
            print("Error: Username cannot be empty.", file=sys.stderr)
            sys.exit(1)

        password = getpass.getpass("Enter password: ")
        if not password:
            print("Error: Password cannot be empty.", file=sys.stderr)
            sys.exit(1)

        password_confirm = getpass.getpass("Confirm password: ")
        if password != password_confirm:
            print("Error: Passwords do not match.", file=sys.stderr)
            sys.exit(1)

        roles_list = ", ".join(sorted(SUPPORTED_ROLES))
        print(f"Supported roles: {roles_list}")
        role = input("Enter role [Employee/Manager/Administrator]: ").strip()

        dept_input = input("Enter department (optional, press Enter to skip): ").strip()
        department = dept_input or None

        user = create_user_record(
            username=username,
            password=password,
            role=role,
            department=department,
        )
        print(f"\n[+] Success: User '{user.username}' created successfully with role '{user.role}'.")
        print(f"    User ID: {user.id}")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(f"\n[-] Bootstrap failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
