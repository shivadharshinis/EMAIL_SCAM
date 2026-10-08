from app.engines.campaign.correlator import correlate
from app.engines.campaign.models import AnalysisRecord
from app.engines.campaign.normalizer import address_domains
from app.engines.scoring.calculator import calculate
from app.engines.scoring.models import ScoreEvidence


def test_same_sender_and_subject_correlate_without_raw_content():
    current = AnalysisRecord(sender_domains={"example.test"}, subject="verify account")
    previous = AnalysisRecord(sender_domains={"example.test"}, subject="verify account")
    result = correlate(current, [previous])
    assert result["matched"] is True
    assert "Same sender domain" in result["signals"]
    assert "Similar subject" in result["signals"]


def test_address_domain_normalization_ignores_missing_optional_addresses():
    assert address_domains([None, "", "Analyst <person@example.test>"]) == {
        "example.test"
    }


def test_unrelated_records_do_not_correlate():
    result = correlate(
        AnalysisRecord(sender_domains={"one.test"}, public_ips={"8.8.8.8"}),
        [AnalysisRecord(sender_domains={"two.test"}, public_ips={"1.1.1.1"})],
    )
    assert result["matched"] is False
    assert result["similarity_score"] == 0


def test_final_risk_is_bounded_and_deterministic():
    evidence = ScoreEvidence(100, 1.0, 100, 100)
    first = calculate(evidence)
    second = calculate(evidence)
    assert first == second
    assert 0 <= first["score"] <= 100
    assert first["severity"] == "CRITICAL"
    assert first["verdict"] == "MALICIOUS"


def test_final_risk_thresholds():
    assert calculate(ScoreEvidence(0, 0, 0, 0))["verdict"] == "BENIGN"
    assert calculate(ScoreEvidence(60, 0, 0, 0))["severity"] == "MEDIUM"
    assert calculate(ScoreEvidence(100, 0.5, 0, 0))["verdict"] == "MALICIOUS"


def test_final_risk_explanation_uses_only_supplied_evidence():
    result = calculate(
        ScoreEvidence(
            60,
            0.9,
            0,
            0,
            evidence_reasons=("Reply-To mismatch detected.",),
        )
    )
    assert "Reply-To mismatch detected." in result["explanation"]
    assert "public IP" not in result["explanation"]
