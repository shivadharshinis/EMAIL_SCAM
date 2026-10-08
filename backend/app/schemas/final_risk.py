from typing import Literal

from pydantic import BaseModel, Field


class FinalRisk(BaseModel):
    score: int = Field(ge=0, le=100)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    verdict: Literal["MALICIOUS", "BENIGN"]
    confidence: Literal["LOW", "MEDIUM", "HIGH"]
    explanation: str
