
from fastapi import FastAPI

from .router import router as privacy_router

app = FastAPI(
    title="AgentShield Privacy Protection API",
    description="Sensitive information detection service",
    version="1.0.0"
)

app.include_router(privacy_router)


@app.get("/")
def home():
    return {
        "message": "AgentShield Privacy API is running"
    }
