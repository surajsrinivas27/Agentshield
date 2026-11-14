"""
Deterministic Authorization Gateway — AgentShield Stage 3

Independent policy enforcement point executing strictly deterministic rules.
The LLM is NEVER permitted to make or influence authorization decisions.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from backend.agent.models import ORIGIN_EXTERNAL, TASK_STATUS_ACTIVE
from backend.agent.provenance_repository import ProvenanceRepository
from backend.authorization.capabilities import get_role_capabilities
from backend.authorization.models import User
from backend.agent.models import Task
from backend.common.security import verify_capability_manifest


DECISION_ALLOW = "ALLOW"
DECISION_BLOCK = "BLOCK"


@dataclass(frozen=True)
class AuthorizationDecision:
    """Immutable result of an authorization evaluation."""
    decision: str
    explanation: str

    @property
    def is_allowed(self) -> bool:
        return self.decision == DECISION_ALLOW

    @property
    def is_blocked(self) -> bool:
        return self.decision == DECISION_BLOCK


def evaluate_authorization(
    db: Session,
    principal_id: str,
    task_id: str,
    operation: str,
    resource_id: str,
    recipient: Optional[str] = None,
) -> AuthorizationDecision:
    """
    Evaluate requested operation against deterministic security policies.

    INVARIANTS EVALUATED:
    1. Principal exists and is_active is True.
    2. Task exists and is owned by the authenticated principal.
    3. Task status is currently ACTIVE.
    4. Task has not expired (UTC timestamp check).
    5. Stored capability manifest has valid HMAC-SHA256 signature.
    6. Manifest identity matches task record and owner.
    7. Requested operation is in manifest allowed_operations.
    8. Requested resource is in manifest allowed_resource_ids.
    9. Recipient is in manifest permitted_recipients (mandatory for FORWARD_EMAIL).
    10. Principal's current database role permits the operation.
    11. Untrusted Provenance Rule:
        - External/tainted content is always untrusted.
        - READ_DOCUMENT and SUMMARIZE_DOCUMENT may process untrusted content.
        - FORWARD_EMAIL is strictly BLOCKED if any external or untrusted provenance
          is associated with the task (prevents exfiltration via indirect prompt injection).
        - Instructions in external content never grant authorization.
    """
    # 1. Principal existence and active verification
    user = db.get(User, principal_id)
    if user is None:
        return AuthorizationDecision(DECISION_BLOCK, f"Principal '{principal_id}' does not exist.")
    if not user.is_active:
        return AuthorizationDecision(DECISION_BLOCK, f"Principal '{principal_id}' account is suspended or inactive.")

    # 2. Task existence and ownership verification
    task = db.get(Task, task_id)
    if task is None:
        return AuthorizationDecision(DECISION_BLOCK, f"Task '{task_id}' not found.")
    if task.principal_id != principal_id:
        return AuthorizationDecision(
            DECISION_BLOCK,
            f"Task ownership violation: Task '{task_id}' is not owned by principal '{principal_id}'."
        )

    # 3. Task status check (must be ACTIVE)
    if task.status != TASK_STATUS_ACTIVE:
        return AuthorizationDecision(
            DECISION_BLOCK,
            f"Task '{task_id}' status is '{task.status}', but must be 'ACTIVE'."
        )

    # 4. Task expiration check (UTC aware)
    now_utc = datetime.now(timezone.utc)
    if task.expires_at <= now_utc:
        return AuthorizationDecision(
            DECISION_BLOCK,
            f"Task '{task_id}' capability manifest has expired at {task.expires_at.isoformat()}."
        )

    # 5. Cryptographic HMAC signature check on stored capability manifest
    manifest = task.capability_manifest
    if not isinstance(manifest, dict):
        return AuthorizationDecision(
            DECISION_BLOCK,
            f"Task '{task_id}' contains malformed capability manifest structure."
        )

    sig = manifest.get("manifest_signature")
    if not sig or not isinstance(sig, str):
        return AuthorizationDecision(
            DECISION_BLOCK,
            f"Task '{task_id}' capability manifest lacks cryptographic signature."
        )

    # Extract manifest_signature separately and exclude it from the unsigned payload.
    # The signed payload must contain exactly the 7 expected canonical fields.
    unsigned_manifest = {
        "task_id": manifest.get("task_id"),
        "user_id": manifest.get("user_id"),
        "task_type": manifest.get("task_type"),
        "allowed_operations": manifest.get("allowed_operations"),
        "allowed_resource_ids": manifest.get("allowed_resource_ids"),
        "permitted_recipients": manifest.get("permitted_recipients"),
        "expires_at": manifest.get("expires_at"),
    }

    if not verify_capability_manifest(unsigned_manifest, sig):
        return AuthorizationDecision(
            DECISION_BLOCK,
            f"Task '{task_id}' capability manifest signature verification failed (tampered manifest)."
        )


    # 6. Manifest identity matches task record
    if manifest.get("user_id") != principal_id or manifest.get("task_id") != task_id:
        return AuthorizationDecision(
            DECISION_BLOCK,
            "Manifest identity mismatch: user_id or task_id does not match task record."
        )

    # 7. Requested operation is within capability manifest
    allowed_ops = manifest.get("allowed_operations", [])
    if operation not in allowed_ops:
        return AuthorizationDecision(
            DECISION_BLOCK,
            f"Operation '{operation}' is not permitted by task capability manifest (allowed: {allowed_ops})."
        )

    # 8. Requested resource is within permitted resources
    allowed_resources = manifest.get("allowed_resource_ids", [])
    if resource_id not in allowed_resources:
        return AuthorizationDecision(
            DECISION_BLOCK,
            f"Resource '{resource_id}' is not permitted by task capability manifest (allowed: {allowed_resources})."
        )

    # 9. Recipient validation (mandatory for FORWARD_EMAIL)
    permitted_recipients = manifest.get("permitted_recipients", [])
    if operation == "FORWARD_EMAIL":
        if not recipient:
            return AuthorizationDecision(
                DECISION_BLOCK,
                "Recipient email is required for FORWARD_EMAIL operation."
            )
        if recipient not in permitted_recipients:
            return AuthorizationDecision(
                DECISION_BLOCK,
                f"Recipient '{recipient}' is not permitted by task capability manifest (permitted: {permitted_recipients})."
            )
    elif recipient and recipient not in permitted_recipients:
        return AuthorizationDecision(
            DECISION_BLOCK,
            f"Recipient '{recipient}' is not permitted by task capability manifest."
        )

    # 10. Principal's current database role permits the requested operation
    role_allowed_ops = get_role_capabilities(user.role)
    if operation not in role_allowed_ops:
        return AuthorizationDecision(
            DECISION_BLOCK,
            f"Principal's current role '{user.role}' does not permit operation '{operation}'."
        )

    # 11. Untrusted Provenance Rule (Exfiltration Defense)
    # External content is untrusted by default.
    # If the task has any untrusted or external provenance records, FORWARD_EMAIL is BLOCKED.
    prov_records = ProvenanceRepository.list_provenance_for_task(
        db=db,
        task_id=task_id,
        principal_id=principal_id,
    )
    has_untrusted_provenance = any(
        not r.is_trusted() or r.has_taint() or r.source_origin == ORIGIN_EXTERNAL
        for r in prov_records
    )

    if has_untrusted_provenance and operation == "FORWARD_EMAIL":
        return AuthorizationDecision(
            DECISION_BLOCK,
            f"Operation 'FORWARD_EMAIL' is BLOCKED: Task '{task_id}' contains external or untrusted "
            f"provenance records. Data exfiltration defense policy prohibits external transmission "
            f"when untrusted input is present."
        )

    # 12. Policy evaluation passed
    return AuthorizationDecision(
        DECISION_ALLOW,
        f"Operation '{operation}' on resource '{resource_id}' authorized by deterministic policy."
    )
