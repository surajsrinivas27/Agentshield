
from pydantic import BaseModel, Field


class PrivacyRequest(BaseModel):
    request_id: str
    text: str


class Entity(BaseModel):
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    type: str
    confidence: float = Field(ge=0.0, le=1.0)


class PrivacyResponse(BaseModel):
    request_id: str
    status: str
    entities: list[Entity]
