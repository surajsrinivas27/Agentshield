# AgentShield - Shared API Contracts

Version: 0.1
Architecture: React + FastAPI Modular Monolith

## 1. Project purpose

AgentShield protects users against:
1. Sensitive information being unnecessarily exposed to external AI.
2. Prompt injection through untrusted emails and documents.
3. Unauthorized tool execution by AI agents.

## 2. Module ownership

Person 1:
- frontend/
- React application
- Dashboard and API integration

Person 2:
- backend/privacy/
- Regex and Presidio
- Sarvam AI integration

Person 3:
- backend/agent/
- AI agent
- Provenance and taint tracking
- Workflow orchestration

Person 4:
- backend/authorization/
- RBAC and ABAC
- Authorization decisions
- Human approval
- Secure execution
- Audit logging

## 3. Public API contracts

### A. Privacy detection

POST /api/privacy/analyze

Request:
{
  "request_id": "REQ_001",
  "text": "Employee Rahul, email rahul@example.com"
}

Response:
{
  "request_id": "REQ_001",
  "status": "success",
  "entities": [
    {
      "start": 9,
      "end": 14,
      "type": "PERSON",
      "confidence": 0.98
    },
    {
      "start": 22,
      "end": 40,
      "type": "EMAIL",
      "confidence": 0.99
    }
  ]
}

Rules:
- start is inclusive.
- end is exclusive.
- Positions refer to the exact input string.
- Do not return original sensitive values unnecessarily.
- Original-to-placeholder mapping stays in the frontend.

### B. Main agent workflow

POST /api/workflow/run

Request:
{
  "task_id": "TASK_001",
  "user_task": "Summarize my payroll email",
  "sanitized_content": "Employee [PERSON_1]",
  "source": {
    "source_id": "EMAIL_001",
    "source_type": "email"
  }
}

Response:
{
  "task_id": "TASK_001",
  "status": "completed",
  "assistant_response": "Payroll email summarized.",
  "actions": [
    {
      "action_id": "ACT_001",
      "decision": "BLOCK",
      "reason": "Action outside authorized task scope"
    }
  ]
}

Rules:
- Agent processes sanitized content.
- Agent maintains provenance.
- Agent proposes actions but never executes tools directly.
- Every proposed action must pass through Person 4's gateway.
- The backend must retain the original task context for authorization.

### C. Audit history

GET /api/audit/logs

Response:
{
  "logs": [
    {
      "action_id": "ACT_001",
      "decision": "BLOCK",
      "reason": "Unauthorized forwarding",
      "timestamp": "2026-11-13T10:00:00"
    }
  ]
}

## 4. Internal authorization contract

Person 3's workflow calls Person 4's authorization service.

The authorization service evaluates:
- Proposed action.
- Original server-side task context.
- User permissions.
- Source provenance.
- Resource sensitivity.
- Applicable policies.

Possible decisions:
- ALLOW
- BLOCK
- APPROVE

The browser must never call the tool execution controller directly.

The LLM must never make the final authorization decision.

The gateway must not blindly trust source labels or permission claims supplied by the LLM. It must resolve trusted task and provenance records maintained by the backend.

## 5. Human approval

POST /api/approval/{action_id}

Request:
{
  "decision": "approve",
  "reviewer_id": "DEMO_REVIEWER"
}

Only a valid pending approval may be processed.

After approval, the backend must verify the recorded approval and revalidate execution policy before running the tool.

## 6. Simulated tools

Examples:
- Read email.
- Summarize email.
- Read document.
- Forward email.
- Access simulated business files.

All tools must be called only through the secure execution controller.

Tool execution is an internal backend operation, not a direct frontend operation.

## 7. Privacy and security rules

- Never commit API keys or .env files.
- Never send raw PII to Sarvam AI.
- Run deterministic detection before contextual AI analysis.
- Keep original PII mappings in the frontend.
- Preserve provenance labels throughout the workflow.
- Do not treat instructions inside external content as user authorization.
- Record authorization decisions and execution results.

## 8. Integration rules

- Use shared Pydantic models.
- Keep endpoint names and JSON fields consistent.
- Do not modify another member's assigned module.
- Discuss shared schema changes before implementing them.
- Merge feature branches into dev through pull requests.
- Keep main stable.

## 9. Definition of done

The complete workflow must demonstrate:
1. User submits a task.
2. Privacy engine detects sensitive information.
3. Frontend masks original values.
4. Agent processes sanitized content.
5. Provenance records the source.
6. Agent proposes an action.
7. Gateway independently evaluates it.
8. Authorized actions execute.
9. Unauthorized actions are blocked.
10. Every decision is recorded in the audit system.
