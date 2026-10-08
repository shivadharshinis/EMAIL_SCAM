from app.schemas.threat_detection import IndicatorSeverity, ThreatIndicator


def indicator(
    indicator_type: str,
    severity: IndicatorSeverity,
    title: str,
    description: str,
    evidence: str,
    confidence: float,
) -> ThreatIndicator:
    return ThreatIndicator(
        type=indicator_type,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        confidence=confidence,
    )
