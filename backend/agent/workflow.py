"""
Integrated Agent Workflow Orchestration — AgentShield Stage 3

Coordinates:
- Verified Bearer JWT principal resolution (never caller-controlled)
- Pre-execution privacy inspection (rejects unmasked sensitive PII)
- Provenance registration (USER_PROVIDED vs. untrusted EXTERNAL)
- Local deterministic AI fallback when Sarvam credentials are absent
- Deterministic Authorization Gateway evaluation
- Strictly supervised tool execution (execution only after ALLOW)
- Tamper-evident audit logging
"""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.agent.dtos import AuthenticatedUserContext
from backend.agent.exceptions import ProvenanceError
from backend.agent.models import Task
from backend.agent.provenance_registry import ProvenanceRegistry
from backend.authorization.audit import record_audit_event
from backend.authorization.auth_service import get_current_user_context
from backend.authorization.execution import execute_simulated_operation
from backend.authorization.gateway import evaluate_authorization
from backend.authorization.models import User
from backend.authorization.schemas import WorkflowRunRequest, WorkflowRunResponse
from backend.common.database import get_db
from backend.privacy.detector import detect_sensitive_data
from backend.privacy.sarvam_client import analyze_sanitized_context


router = APIRouter(prefix="/api/workflow", tags=["Workflow"])


@router.post("/run", response_model=WorkflowRunResponse)
def run_workflow(
    request: WorkflowRunRequest,
    auth_data: tuple = Depends(get_current_user_context),
    db: Session = Depends(get_db),
):
    """
    Execute an Agent workflow under strict deterministic security and privacy controls.

    INVARIANTS:
    - Principal derived strictly from AuthenticatedUserContext.
    - User cannot supply arbitrary user_id, trust_level, or permissions.
    - Submitted content analyzed for PII; rejected if sensitive entities remain.
    - Direct human input registered via ProvenanceRegistry.register_user_input.
    - External content registered via register_external_content (always untrusted).
    - Gateway independently evaluates authorization.
    - Simulated execution occurs ONLY if gateway outputs ALLOW.
    """
    auth_context, user = auth_data
    principal_id = user.id

    # 1. Enforce Task Existence and Ownership
    task = db.get(Task, request.task_id)
    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task with id {request.task_id!r} not found.",
        )
    if task.principal_id != principal_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Task ownership violation: Task {request.task_id!r} is not owned by principal {principal_id!r}.",
        )

    # 2. Privacy Check: Inspect submitted content for residual PII/sensitive data
    entities_in_content = detect_sensitive_data(request.sanitized_content)
    if entities_in_content:
        record_audit_event(
            db=db,
            actor_id=principal_id,
            event_type="WORKFLOW_PRIVACY_BLOCKED",
            task_id=request.task_id,
            operation=request.operation,
            decision="BLOCK",
            reason=f"Residual sensitive data detected ({len(entities_in_content)} entities found)",
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Sensitive information detected in sanitized_content. Data must be redacted.",
                "entities": entities_in_content,
            },
        )

    # 3. Provenance Registration
    try:
        # A. Register direct human user input
        ProvenanceRegistry.register_user_input(
            db=db,
            auth_context=auth_context,
            task_id=request.task_id,
            sanitized_content=request.sanitized_content,
            origin="human_prompt",
        )

        # B. If external content provided, register via external intake (automatically UNTRUSTED)
        if request.external_content and request.external_content.strip():
            ProvenanceRegistry.register_external_content(
                db=db,
                task_id=request.task_id,
                principal_id=principal_id,
                sanitized_content=request.external_content,
                origin="external_feed",
                source_type="email",
            )
    except ProvenanceError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Provenance registration error: {str(exc)}",
        )

    # 4. Privacy / Context Assessment (Sarvam AI with local deterministic fallback)
    privacy_assessment = analyze_sanitized_context(request.sanitized_content)

    # 5. Deterministic Authorization Gateway Evaluation
    decision = evaluate_authorization(
        db=db,
        principal_id=principal_id,
        task_id=request.task_id,
        operation=request.operation,
        resource_id=request.resource_id,
        recipient=request.recipient,
    )

    # 6. Audit Decision
    record_audit_event(
        db=db,
        actor_id=principal_id,
        event_type="AUTHORIZATION_DECISION",
        task_id=request.task_id,
        operation=request.operation,
        decision=decision.decision,
        reason=decision.explanation,
    )

    # 7. Simulated Tool Execution (Strictly only after ALLOW)
    execution_result = None
    if decision.is_allowed:
        execution_result = execute_simulated_operation(
            decision=decision,
            operation=request.operation,
            resource_id=request.resource_id,
            recipient=request.recipient,
            content=request.sanitized_content,
        )
        agent_response = (
            f"Operation '{request.operation}' authorized and successfully executed "
            f"for resource '{request.resource_id}'."
        )
        record_audit_event(
            db=db,
            actor_id=principal_id,
            event_type="WORKFLOW_EXECUTE_SUCCESS",
            task_id=request.task_id,
            operation=request.operation,
            decision="SUCCESS",
            reason=f"Executed {request.operation}",
        )
    else:
        agent_response = (
            f"Operation '{request.operation}' was BLOCKED by Authorization Gateway: "
            f"{decision.explanation}"
        )
        record_audit_event(
            db=db,
            actor_id=principal_id,
            event_type="WORKFLOW_EXECUTE_BLOCKED",
            task_id=request.task_id,
            operation=request.operation,
            decision="BLOCK",
            reason=decision.explanation,
        )

    db.commit()

    # 8. Collect Updated Provenance Records for Response Summary
    prov_records = ProvenanceRegistry.get_task_provenance(
        db=db,
        task_id=request.task_id,
        principal_id=principal_id,
    )
    provenance_summary = [
        {
            "source_id": r.source_id,
            "origin": r.origin,
            "source_type": r.source_type,
            "source_origin": r.source_origin,
            "trust_level": r.trust_level,
            "content_hash": r.content_hash,
            "taint_labels": list(r.taint_labels),
        }
        for r in prov_records
    ]

    return WorkflowRunResponse(
        task_id=request.task_id,
        decision=decision.decision,
        explanation=decision.explanation,
        agent_response=agent_response,
        provenance_summary=provenance_summary,
        execution_result=execution_result,
        privacy_assessment=privacy_assessment,
    )
