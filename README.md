# AgentShield

AI Agent Security and Privacy Protection Platform.

## Objective

AgentShield protects sensitive information during AI processing
and prevents untrusted external content from triggering
unauthorized actions by tool-enabled AI agents.

## Architecture

- Frontend: React
- Backend: Python FastAPI
- Validation: Pydantic
- Privacy: Regex and Microsoft Presidio
- AI integration: Sarvam AI
- Agent: Workflow orchestration and provenance tracking
- Authorization: Deterministic RBAC and ABAC
- Execution: Simulated business tools

## Team Modules

| Person | Module |
|---|---|
| Person 1 | Frontend and UI integration |
| Person 2 | Privacy Protection Engine |
| Person 3 | AI Agent and Provenance |
| Person 4 | Authorization Gateway |

## Git Branches

- main: Stable application
- dev: Integration
- feature/frontend: Person 1
- feature/privacy: Person 2
- feature/agent: Person 3
- feature/authorization: Person 4

## API Contracts

See docs/API_CONTRACTS.md.

## Security

Never commit .env files, credentials, API keys or real confidential data.

All simulated tool execution must pass through AgentShield's
independent authorization gateway.
