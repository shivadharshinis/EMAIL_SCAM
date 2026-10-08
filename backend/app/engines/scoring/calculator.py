from __future__ import annotations

from app.engines.scoring.models import ScoreEvidence


def calculate(evidence: ScoreEvidence) -> dict:
    score = round(
        0.45 * max(0, min(100, evidence.rule_score))
        + 0.35 * max(0, min(1, evidence.ml_probability or 0)) * 100
        + 0.10 * max(0, min(100, evidence.infrastructure_signal_score))
        + 0.10 * max(0, min(100, evidence.campaign_signal_score))
    )
    score = max(0, min(100, score))
    severity = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    verdict = "MALICIOUS" if severity in {"HIGH", "CRITICAL"} else "BENIGN"
    confidence = "HIGH" if evidence.rule_score >= 50 and evidence.ml_probability is not None else "MEDIUM" if evidence.rule_score or evidence.ml_probability is not None else "LOW"
    return {
        "score": score,
        "severity": severity,
        "verdict": verdict,
        "confidence": confidence,
        "explanation": _explanation(evidence, severity),
    }


def _explanation(evidence: ScoreEvidence, severity: str) -> str:
    verdict = "MALICIOUS" if severity in {"HIGH", "CRITICAL"} else "BENIGN"
    if evidence.evidence_reasons:
        reasons = " ".join(evidence.evidence_reasons[:6])
        return f"{verdict} verdict based on the combined analysis. Contributing evidence: {reasons}"
    return (
        f"{verdict} verdict based on the combined analysis. "
        "No contributing evidence was recorded by the available analysis engines."
    )
