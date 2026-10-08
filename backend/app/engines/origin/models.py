from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OriginCandidate:
    ip: str
    country: str | None
    country_code: str | None
    region: str | None
    city: str | None
    latitude: float | None
    longitude: float | None
    asn: str | None
    organization: str | None
    isp: str | None
    evidence_count: int

