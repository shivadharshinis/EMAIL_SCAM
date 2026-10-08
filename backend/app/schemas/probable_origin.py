from typing import Literal

from pydantic import BaseModel


class ProbableOrigin(BaseModel):
    available: bool
    confidence: Literal["LOW", "MEDIUM", "HIGH"] | None = None
    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: str | None = None
    organization: str | None = None
    isp: str | None = None
    source_ip: str | None = None
    reason: str
