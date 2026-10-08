from enum import StrEnum

from pydantic import BaseModel, Field


class IndicatorSeverity(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"


class ThreatIndicator(BaseModel):
    type: str
    severity: IndicatorSeverity
    title: str
    description: str
    evidence: str
    confidence: float = Field(ge=0, le=1)


class ThreatDetectionResult(BaseModel):
    rule_score: int = Field(ge=0, le=100)
    indicators: list[ThreatIndicator] = Field(default_factory=list)
    summary: str
