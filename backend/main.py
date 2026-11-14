"""
AgentShield — Main FastAPI Application Entrypoint (Stage 3 MVP)

Coordinates:
- Database initialization with complete table registration
- Cross-Origin Resource Sharing (CORS) for localhost development
- Privacy inspection API (/api/privacy)
- Authentication API (/api/auth)
- Task capability creation (/api/tasks)
- Agent workflow execution (/api/workflow)
- Tamper-evident audit logs (/api/audit)
- System health status (/health)
- OpenAPI Swagger documentation (/docs)
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.agent.workflow import router as workflow_router
from backend.authorization.audit import router as audit_router
from backend.authorization.auth_service import router as auth_router
from backend.authorization.capabilities import router as tasks_router
from backend.privacy.router import router as privacy_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup and shutdown lifecycle management.
    Explicitly imports model_registry and audit models before calling init_db.
    """
    # 1. Register all ORM models on declarative Base
    import backend.model_registry  # noqa: F401
    import backend.authorization.audit  # noqa: F401

    # 2. Initialize database schema
    from backend.common.database import init_db
    init_db()

    yield


# ---------------------------------------------------------------------------
# FastAPI Application Declaration
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AgentShield",
    description="Deterministic Authorization, Privacy Enforcement & Provenance Architecture for AI Agents",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# CORS Configuration for Localhost Development
# ---------------------------------------------------------------------------

CORS_ORIGINS = [
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:8000",
    "http://127.0.0.1",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Health Check Endpoint
# ---------------------------------------------------------------------------

@app.get("/health", tags=["Health"])
def health():
    """System health check endpoint."""
    return {
        "status": "healthy",
        "service": "AgentShield",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Mount Application Routers
# ---------------------------------------------------------------------------

app.include_router(privacy_router)
app.include_router(auth_router)
app.include_router(tasks_router)
app.include_router(workflow_router)
app.include_router(audit_router)
