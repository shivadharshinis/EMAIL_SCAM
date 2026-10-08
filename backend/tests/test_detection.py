from pathlib import Path

from app.engines.detection import detect_threats
from app.engines.parser import parse_eml

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "samples"


def detect(raw: bytes | str) -> dict:
    return detect_threats(parse_eml(raw))


def types(result: dict) -> set[str]:
    return {item["type"] for item in result["indicators"]}


def test_reply_to_and_return_path_mismatch():
    result = detect(
        b"From: Brand <sender@brand.example>\n"
        b"Reply-To: replies@other.example\n"
        b"Return-Path: <bounce@third.example>\n\nHello"
    )
    assert {"reply_to_mismatch", "return_path_mismatch"} <= types(result)


def test_authentication_failure_is_explicit_only():
    failed = detect(
        b"From: sender@example.test\n"
        b"Authentication-Results: mx.example.test; spf=fail; dkim=fail; dmarc=fail\n\nHello"
    )
    assert "authentication_results_failure" in types(failed)
    missing = detect(b"From: sender@example.test\n\nHello")
    assert not any("failure" in item["type"] for item in missing["indicators"])


def test_social_engineering_categories():
    result = detect(
        b"From: Security <security@example.test>\n"
        b"Subject: Urgent verification required\n\n"
        b"Act now to avoid account suspension. Confirm your password immediately."
    )
    assert {"urgent_action", "credential_request", "account_suspension", "verification_request"} <= types(result)


def test_suspicious_sender_domain_and_punycode():
    result = detect(
        b"From: PayPal <service@xn--paypa1-9za.example>\n\nHello"
    )
    assert "display_name_impersonation" in types(result)
    assert "punycode_domain" in types(result)


def test_ip_based_and_suspicious_url_indicators():
    result = detect(
        b"From: sender@example.test\n\n"
        b"Visit http://192.0.2.10/login?token=%2Fabc for verification."
    )
    assert {"ip_based_url", "suspicious_url_keyword", "insecure_http_url"} <= types(result)


def test_risky_attachment_is_metadata_only():
    parsed = parse_eml(
        b"From: sender@example.test\n"
        b"Content-Type: multipart/mixed; boundary=x\n\n"
        b"--x\nContent-Type: text/plain\n\nSee file\n"
        b"--x\nContent-Type: application/octet-stream\n"
        b"Content-Disposition: attachment; filename=\"update.ps1\"\n\n"
        b"not executed\n--x--\n"
    )
    result = detect_threats(parsed)
    assert "risky_attachment_extension" in types(result)


def test_clean_legitimate_sample_has_no_high_confidence_identity_or_auth_failures():
    result = detect((SAMPLES_DIR / "legitimate.eml").read_bytes())
    assert not any(
        item["type"].endswith("_failure")
        or item["type"] in {"reply_to_mismatch", "return_path_mismatch"}
        for item in result["indicators"]
    )


def test_existing_samples_are_detected_without_network_access():
    result = detect((SAMPLES_DIR / "suspicious_phishing.eml").read_bytes())
    assert result["rule_score"] > 0
    assert "credential_request" in types(result)
    assert "suspicious_url_keyword" in types(result)
