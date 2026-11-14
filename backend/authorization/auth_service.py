"""
Authentication Service & Endpoints — AgentShield Stage 3

Handles:
- POST /api/auth/login using Argon2id verification and signed JWT token issuance.
- Dependency injection for authenticated API endpoints using AuthenticatedUserContext.
- Explicit documentation of JWT revocation limitations (jti revocation storage pending).
"""

from typing import Tuple

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.agent.dtos import AuthenticatedUserContext
from backend.agent.exceptions import ProvenanceError
from backend.authorization.audit import record_audit_event
from backend.authorization.models import User
from backend.authorization.schemas import LoginRequest, LoginResponse
from backend.common.database import get_db
from backend.common.security import create_access_token, get_access_token_expire_minutes, verify_password


router = APIRouter(prefix="/api/auth", tags=["Authentication"])
http_bearer = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Login Endpoint
# ---------------------------------------------------------------------------

@router.post("/login", response_model=LoginResponse)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    """
    Authenticate user credentials and issue a signed Bearer JWT token.

    SECURITY INVARIANTS:
    - Never accepts a signing secret or algorithm from the client.
    - Uses Stage 1 verify_password (Argon2id in constant time).
    - Generic 401 error message prevents user enumeration.
    - Role claims are informational; server-side database lookup remains authoritative.
    - Suspended/inactive users are strictly rejected.
    """
    stmt = select(User).where(User.username == request.username)
    user = db.execute(stmt).scalar_one_or_none()

    if user is None or not verify_password(request.password, user.password_hash):
        # Generic message avoids revealing whether the username exists
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended or inactive",
        )

    expire_minutes = get_access_token_expire_minutes()
    token = create_access_token(
        subject=user.id,
        role=user.role,
        username=user.username,
        department=user.department,
    )

    # Log successful login event to tamper-evident audit log
    record_audit_event(
        db=db,
        actor_id=user.id,
        event_type="AUTH_LOGIN",
        decision="SUCCESS",
        reason=f"User {user.username!r} authenticated successfully via password",
    )
    db.commit()

    return LoginResponse(
        access_token=token,
        token_type="bearer",
        user_id=user.id,
        username=user.username,
        role=user.role,
        expires_in=expire_minutes * 60,
    )


# ---------------------------------------------------------------------------
# Bearer Token Dependency for Protected Routes
# ---------------------------------------------------------------------------

def get_current_user_context(
    credentials: HTTPAuthorizationCredentials = Depends(http_bearer),
    db: Session = Depends(get_db),
) -> Tuple[AuthenticatedUserContext, User]:
    """
    FastAPI dependency enforcing Bearer JWT authentication on protected routes.

    VERIFICATION GUARANTEES:
    - Requires Authorization: Bearer <token>.
    - Verifies token signature and claims via AuthenticatedUserContext.from_bearer_token(token, db).
    - Checks user exists and is_active in the database.
    - Verifies token issued-at against user.token_valid_after (supports password change / forced logout).

    LIMITATION DISCLOSURE:
    - Single token revocation via 'jti' blacklist/revocation table is an explicit future dependency.
      The token is currently checked against user.token_valid_after and expiration time, but individual
      jti tracking storage is not yet implemented. Do not claim complete real-time jti revocation.
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing or invalid format. Expected 'Bearer <token>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials

    try:
        auth_context = AuthenticatedUserContext.from_bearer_token(token=token, db=db)
    except ProvenanceError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {str(exc)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {str(exc)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.get(User, auth_context.user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated user record not found in database",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive or suspended",
        )

    return auth_context, user
