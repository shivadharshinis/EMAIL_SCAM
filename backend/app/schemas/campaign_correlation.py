from typing import Literal

from pydantic import BaseModel, Field


class CampaignCorrelation(BaseModel):
    available: bool
    matched: bool
    confidence: Literal["LOW", "MEDIUM", "HIGH"] | None = None
    related_analysis_count: int = 0
    similarity_score: int | None = None
    signals: list[str] = Field(default_factory=list)
    message: str | None = None
