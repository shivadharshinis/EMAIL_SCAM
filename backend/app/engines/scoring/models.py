from dataclasses import dataclass


@dataclass(frozen=True)
class ScoreEvidence:
    rule_score: int
    ml_probability: float | None
    infrastructure_signal_score: int
    campaign_signal_score: int
    evidence_reasons: tuple[str, ...] = ()
