"""
Secure Simulated Tool Execution Controller — AgentShield Stage 3

Executes simulated operations strictly under Authorization Gateway supervision.
Zero real side-effects: no external network requests, file writes, or actual emails.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from backend.authorization.gateway import AuthorizationDecision, DECISION_ALLOW


def execute_simulated_operation(
    decision: AuthorizationDecision,
    operation: str,
    resource_id: str,
    recipient: Optional[str] = None,
    content: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute a simulated tool operation under strict gateway authorization.

    STRICT INVARIANT:
    - MUST ONLY execute if decision.decision is strictly ALLOW.
    - If decision is BLOCK, raises PermissionError immediately.
    - Simulated execution produces no destructive effects or real network traffic.
    """
    if decision is None or not decision.is_allowed:
        explanation = decision.explanation if decision else "No authorization decision provided"
        raise PermissionError(
            f"Execution refused by Authorization Gateway. Decision: BLOCK. Reason: {explanation}"
        )

    now_iso = datetime.now(timezone.utc).isoformat()

    if operation == "READ_DOCUMENT":
        return {
            "status": "success",
            "operation": "READ_DOCUMENT",
            "resource_id": resource_id,
            "simulated_output": (
                f"[SIMULATED DOCUMENT CONTENT: {resource_id}]\n"
                f"Confidential Report: Q3 financial metrics indicate 14% YoY revenue growth. "
                f"Operating margin remains stable at 22%."
            ),
            "executed_at": now_iso,
        }

    elif operation == "SUMMARIZE_DOCUMENT":
        return {
            "status": "success",
            "operation": "SUMMARIZE_DOCUMENT",
            "resource_id": resource_id,
            "simulated_output": (
                f"[SIMULATED SUMMARY: {resource_id}]\n"
                f"Summary: Strong performance in Q3 with positive cash flows and low risk profile."
            ),
            "executed_at": now_iso,
        }

    elif operation == "FORWARD_EMAIL":
        return {
            "status": "success",
            "operation": "FORWARD_EMAIL",
            "resource_id": resource_id,
            "recipient": recipient,
            "simulated_output": (
                f"[SIMULATED FORWARD TRANSMISSION]\n"
                f"Email regarding {resource_id} forwarded to authorized recipient '{recipient}'."
            ),
            "executed_at": now_iso,
        }

    else:
        raise ValueError(f"Unknown simulated operation: {operation!r}")
