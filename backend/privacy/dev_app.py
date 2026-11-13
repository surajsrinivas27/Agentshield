
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .router import router as privacy_router


app = FastAPI(
    title="AgentShield Privacy Protection API",
    description="Sensitive information detection service",
    version="1.0.0"
)

# Allow Person 1's React development server
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"]
)

app.include_router(privacy_router)


@app.get("/")
def home():
    return {
        "message": "AgentShield Privacy API is running"
    }
