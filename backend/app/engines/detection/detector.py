from __future__ import annotations

from app.engines.detection.rules import (
    detect_attachments,
    detect_authentication,
    detect_identity,
    detect_social_engineering,
    detect_urls,
)
from app.schemas.threat_detection import ThreatDetectionResult, ThreatIndicator

SEVERITY_POINTS = {"low": 5, "medium": 10, "high": 20}


def detect_threats(parsed: dict) -> dict:
    """Run local explainable rules over parser facts; never performs network I/O."""
    indicators: list[ThreatIndicator] = []
    indicators.extend(detect_identity(parsed))
    indicators.extend(detect_authentication(parsed.get("headers") or {}))
    indicators.extend(detect_social_engineering(parsed))
    indicators.extend(detect_urls(parsed))
    indicators.extend(detect_attachments(parsed))
    score = min(
        100,
        sum(SEVERITY_POINTS.get(item.severity.value, 0) for item in indicators),
    )
    if not indicators:
        summary = "No rule-based suspicious indicators were detected."
    elif score >= 50:
        summary = "Multiple suspicious indicators were detected."
    else:
        summary = "Some suspicious indicators were detected; review the evidence."
    return ThreatDetectionResult(
        rule_score=score,
        indicators=indicators,
        summary=summary,
    ).model_dump()
