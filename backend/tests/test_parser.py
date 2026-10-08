from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path

import pytest

from app.engines.parser import EmailParseError, parse_eml
from app.engines.parser.sanitizer import html_to_text, sanitize_html

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "samples"


def test_normal_email_identities():
    parsed = parse_eml((SAMPLES_DIR / "legitimate.eml").read_bytes())
    assert parsed["message"]["subject"] == "Scheduled maintenance window this Sunday"
    assert any("it-helpdesk@acme.example.com" in item for item in parsed["message"]["from"])
    assert any("jordan.lee@acme.example.com" in item for item in parsed["message"]["to"])
    assert parsed["message"]["return_path"] == "<it-helpdesk@acme.example.com>"
    assert parsed["message"]["message_id"]


def test_multipart_html_and_plain():
    parsed = parse_eml((SAMPLES_DIR / "suspicious_phishing.eml").read_bytes())
    assert "account will be locked" in parsed["body"]["plain_text"]
    assert "<script>" in parsed["body"]["html"]
    assert "alert(" not in parsed["body"]["sanitized_text"]
    assert "<script>" not in parsed["body"]["sanitized_html"]


def test_missing_optional_headers():
    parsed = parse_eml(b"From: alice@example.com\nTo: bob@example.com\nSubject: Hi\n\nHello\n")
    assert parsed["message"]["cc"] == []
    assert parsed["message"]["reply_to"] == []
    assert parsed["message"]["return_path"] is None
    assert parsed["headers"]["received"] == []
    assert parsed["headers"]["dkim_signature"] == []


def test_multiple_received_headers():
    parsed = parse_eml((SAMPLES_DIR / "relay_authenticated.eml").read_bytes())
    assert len(parsed["headers"]["received"]) == 3
    assert parsed["headers"]["authentication_results"]
    assert parsed["headers"]["received_spf"]
    assert parsed["headers"]["dkim_signature"]
    assert parsed["headers"]["dmarc"]


def test_url_extraction_does_not_fetch():
    parsed = parse_eml((SAMPLES_DIR / "suspicious_phishing.eml").read_bytes())
    urls = parsed["urls"]
    assert any("paypal-secure.example/login" in item["url"] for item in urls)
    assert any(item["hostname"] == "paypal-secure.example" for item in urls)
    assert any(item["hostname"] == "www.paypal-secure.example" for item in urls)


def test_attachment_metadata_only():
    message = EmailMessage()
    message["From"] = "alice@example.com"
    message["To"] = "bob@example.com"
    message["Subject"] = "Invoice"
    message.set_content("Please see attached notes.")
    message.add_attachment(
        b"example-attachment-bytes",
        maintype="text",
        subtype="plain",
        filename="notes.txt",
    )
    parsed = parse_eml(message.as_bytes(policy=SMTP))
    assert len(parsed["attachments"]) == 1
    attachment = parsed["attachments"][0]
    assert attachment["filename"] == "notes.txt"
    assert attachment["mime_type"] == "text/plain"
    assert attachment["size"] == len(b"example-attachment-bytes")
    assert len(attachment["sha256"]) == 64


def test_empty_input_rejected():
    with pytest.raises(EmailParseError, match="empty"):
        parse_eml("   ")


def test_malformed_input_does_not_crash():
    parsed = parse_eml(b"\xff\xfe this is not a well-formed header block")
    assert "message" in parsed
    assert "headers" in parsed
    assert "body" in parsed


def test_html_sanitization_strips_script_and_resources():
    html = '<script>alert(1)</script><p onclick="x">Safe</p><img src="http://evil.example/x.png">'
    text = html_to_text(html)
    safe_html = sanitize_html(html)
    assert "alert(1)" not in text
    assert "Safe" in text
    assert "<script>" not in safe_html
    assert "onclick" not in safe_html
    assert "src=" not in safe_html
    assert "http://evil.example/x.png" not in safe_html
