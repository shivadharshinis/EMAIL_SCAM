from pydantic import BaseModel, Field


class MLDetectionResult(BaseModel):
    available: bool
    prediction: str | None = None
    probability: float | None = Field(default=None, ge=0, le=1)
    model: str
    message: str | None = None
