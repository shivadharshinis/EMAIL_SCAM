import csv
from pathlib import Path

from app.engines.ml.data.prepare_dataset import (
    _record,
    deduplicate,
    html_to_text,
    normalize_text,
    parse_raw_email,
    prepare_dataset,
)


def test_normalization_and_html_fallback():
    assert normalize_text(" A\n  B ") == "A B"
    assert html_to_text("<p>Hello</p><script>alert(1)</script> world") == "Hello world"


def test_empty_and_exact_cross_source_duplicates_are_removed():
    rows = [
        _record("Subject", "Same body", 1, "a", 1),
        _record("Subject", "Same body", 1, "b", 2),
        _record("", "", 0, "c", 3),
    ]
    kept, stats = deduplicate(rows)
    assert len(kept) == 1
    assert stats["counts"]["duplicates_removed"] == 1
    assert stats["counts"]["cross_source_duplicates"] == 1
    assert stats["counts"]["empty"] == 1


def test_preparation_is_deterministic_and_keeps_smoke_fixture(tmp_path: Path):
    raw = tmp_path / "raw"
    raw.mkdir()
    with (raw / "Phishing_validation_emails.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Email Text", "Email Type"])
        writer.writerow(["Visit http://example.test", "Phishing Email"])
        writer.writerow(["Routine project update", "Safe Email"])
    report = prepare_dataset(raw, tmp_path)
    assert report["final_validation_count"] == 0
    assert (tmp_path / "derived" / "email_dataset.csv").exists()


def test_raw_email_extracts_text_and_preserves_url_without_network_access():
    subject, body, has_headers = parse_raw_email(
        b"Subject: Test\nFrom: sender@example.test\n\nVisit https://example.test/path"
    )
    assert subject == "Test"
    assert "https://example.test/path" in body
    assert has_headers is True


def test_attachment_is_not_decoded_or_executed():
    subject, body, has_headers = parse_raw_email(
        b"Subject: Attachment\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=x\n\n"
        b"--x\nContent-Type: text/plain\n\nhello\n--x\n"
        b"Content-Type: application/octet-stream\nContent-Disposition: attachment; filename=x.exe\n"
        b"Content-Transfer-Encoding: base64\n\nZmFrZQ==\n--x--\n"
    )
    assert subject == "Attachment"
    assert body == "hello"
    assert has_headers is True
