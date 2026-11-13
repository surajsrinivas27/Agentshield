
from fastapi import APIRouter

from .schemas import PrivacyRequest, PrivacyResponse
from .detector import detect_sensitive_data


# Create Privacy API router
router = APIRouter(
    prefix="/api/privacy",
    tags=["Privacy"]
)


# POST /api/privacy/analyze
@router.post("/analyze", response_model=PrivacyResponse)
def analyze_privacy(request: PrivacyRequest):

    # Detect sensitive information
    entities = detect_sensitive_data(request.text)

    # Return results according to the team API contract
    return PrivacyResponse(
        request_id=request.request_id,
        status="success",
        entities=entities
    )
