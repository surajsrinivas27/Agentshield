"""
Pydantic Schemas for Authorization, Tasks, Workflow, and Audit — AgentShield Stage 3
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Authentication Schemas
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    """Credentials submitted to POST /api/auth/login."""
    model_config = ConfigDict(extra="forbid")

    username: str = Field(..., min_length=1, max_length=64, description="User login handle")
    password: str = Field(..., min_length=1, description="Plaintext password for verification")


class LoginResponse(BaseModel):
    """Successful authentication response containing signed Bearer JWT."""
    model_config = ConfigDict(extra="forbid")

    access_token: str
    token_type: str = "bearer"
    user_id: str
    username: str
    role: str
    expires_in: int


# ---------------------------------------------------------------------------
# Task & Capability Schemas
# ---------------------------------------------------------------------------

class CreateTaskRequest(BaseModel):
    """
    Task creation request.
    Notice: Callers CANNOT specify permissions, resource IDs, or recipients;
    these are strictly bound server-side from the user's database role.
    """
    model_config = ConfigDict(extra="forbid")

    task_type: str = Field(default="document_processing", max_length=50)


class CreateTaskResponse(BaseModel):
    """Task creation response returning server-generated ID and bound capabilities."""
    model_config = ConfigDict(extra="forbid")

    task_id: str
    principal_id: str
    task_type: str
    allowed_operations: List[str]
    allowed_resource_ids: List[str]
    permitted_recipients: List[str]
    expires_at: str
    status: str


# ---------------------------------------------------------------------------
# Workflow Run Schemas
# ---------------------------------------------------------------------------

class WorkflowRunRequest(BaseModel):
    """
    Request submitted to POST /api/workflow/run.
    Principal identity is derived exclusively from the verified Bearer token.
    """
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(..., min_length=1, description="Target task ID")
    user_task: str = Field(..., min_length=1, description="High-level description of user goal")
    sanitized_content: str = Field(..., min_length=1, description="Sanitized human prompt/text")
    operation: str = Field(..., min_length=1, description="Requested operation (e.g. READ_DOCUMENT)")
    resource_id: str = Field(..., min_length=1, description="Requested resource ID (e.g. demo-document-001)")
    recipient: Optional[str] = Field(default=None, description="Optional recipient email for forwarding")
    external_content: Optional[str] = Field(
        default=None,
        description="Optional external content (email/document) automatically classified as untrusted",
    )


class WorkflowRunResponse(BaseModel):
    """Response returned from POST /api/workflow/run."""
    model_config = ConfigDict(extra="forbid")

    task_id: str
    decision: str  # ALLOW or BLOCK
    explanation: str
    agent_response: Optional[str] = None
    provenance_summary: List[Dict[str, Any]] = Field(default_factory=list)
    execution_result: Optional[Dict[str, Any]] = None
    privacy_assessment: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Audit Schemas
# ---------------------------------------------------------------------------

class AuditLogEntrySchema(BaseModel):
    """Single audit log entry."""
    model_config = ConfigDict(extra="forbid")

    audit_id: str
    sequence_number: int
    task_id: Optional[str] = None
    actor_id: str
    event_type: str
    operation: Optional[str] = None
    decision: Optional[str] = None
    reason: Optional[str] = None
    timestamp: str
    previous_hash: str
    entry_hash: str


class AuditLogsResponse(BaseModel):
    """List of audit records scoped to the requesting principal."""
    model_config = ConfigDict(extra="forbid")

    items: List[AuditLogEntrySchema]
    total: int
