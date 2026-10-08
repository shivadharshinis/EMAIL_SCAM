from pathlib import Path

from fastapi.testclient import TestClient

from app.engines.report import clear_analyses
from app.main import app

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "samples"
client = TestClient(app)


def setup_function():
    clear_analyses()


def test_analyze_json_raw_email():
    raw = (SAMPLES_DIR / "legitimate.eml").read_text(encoding="utf-8")
    response = client.post("/api/v1/analyze", json={"raw_eml": raw})
    assert response.status_code == 200
    data = response.json()
    assert data["message"]["subject"] == "Scheduled maintenance window this Sunday"
    assert "threat_detection" in data
    assert "header_intelligence" in data
    assert "infrastructure_intelligence" in data
    assert data["infrastructure_intelligence"]["enabled"] is False
    assert "probable_origin" in data
    assert data["probable_origin"]["available"] is False
    assert "campaign_correlation" in data
    assert "final_risk" in data
    assert 0 <= data["final_risk"]["score"] <= 100
    assert data["final_risk"]["verdict"] in {"MALICIOUS", "BENIGN"}
    assert 0 <= data["threat_detection"]["rule_score"] <= 100
    assert "ml_detection" in data
    assert data["ml_detection"]["model"] == "TF-IDF + Logistic Regression"
    assert data["ml_detection"]["available"] is True
    assert data["ml_detection"]["prediction"] in {"PHISHING", "LEGITIMATE"}
    assert 0 <= data["ml_detection"]["probability"] <= 1
    assert "final_risk_score" not in data
    assert any(
        item.get("hostname") == "intranet.acme.example.com" for item in data["urls"]
    )
    assert data["analyzed_at"]
    assert data["filename"] is None


def test_case_list_and_detail_return_stored_analysis():
    raw = (SAMPLES_DIR / "legitimate.eml").read_bytes()
    analyzed = client.post(
        "/api/v1/analyze",
        files={"file": ("maintenance.eml", raw, "message/rfc822")},
    )
    assert analyzed.status_code == 200
    data = analyzed.json()

    listed = client.get("/api/v1/analyses")
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert listed.json()[0] == {
        "analysis_id": data["analysis_id"],
        "filename": "maintenance.eml",
        "sender": data["message"]["from"],
        "subject": data["message"]["subject"],
        "prediction": data["ml_detection"]["prediction"],
        "verdict": data["final_risk"]["verdict"],
        "threat_score": data["final_risk"]["score"],
        "severity": data["final_risk"]["severity"],
        "analyzed_at": data["analyzed_at"],
    }

    detail = client.get(f"/api/v1/analyses/{data['analysis_id']}")
    assert detail.status_code == 200
    assert detail.json()["analysis_id"] == data["analysis_id"]
    assert detail.json()["final_risk"] == data["final_risk"]
    assert detail.json()["filename"] == "maintenance.eml"


def test_case_detail_not_found():
    response = client.get("/api/v1/analyses/not-found")
    assert response.status_code == 404


def test_model_info_uses_saved_evaluation_metrics():
    response = client.get("/api/v1/model-info")
    assert response.status_code == 200
    info = response.json()
    assert info["model"] == "TF-IDF + Logistic Regression"
    assert info["feature_extraction"] == "TF-IDF"
    assert info["status"] in {"available", "unavailable"}
    metrics_path = (
        Path(__file__).resolve().parents[1]
        / "app"
        / "engines"
        / "ml"
        / "artifacts"
        / "metrics.json"
    )
    if metrics_path.is_file():
        import json

        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        assert info["test_metrics"] == metrics["test_metrics"]
    else:
        assert info["test_metrics"] is None


def test_analyze_multipart_file_upload():
    raw = (SAMPLES_DIR / "relay_authenticated.eml").read_bytes()
    response = client.post(
        "/api/v1/analyze",
        files={"file": ("relay_authenticated.eml", raw, "message/rfc822")},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data["headers"]["received"]) == 3
    assert "threat_detection" in data
    assert "header_intelligence" in data
    assert "probable_origin" in data
    assert "campaign_correlation" in data
    assert "final_risk" in data
    assert "final_risk_score" not in data
    assert data["filename"] == "relay_authenticated.eml"


def test_analyze_rejects_empty_json():
    response = client.post("/api/v1/analyze", json={"raw_eml": "  "})
    assert response.status_code == 400


def test_analyze_rejects_unsupported_extension():
    response = client.post(
        "/api/v1/analyze",
        files={"file": ("notes.pdf", b"%PDF-fake", "application/pdf")},
    )
    assert response.status_code == 400


def test_analyze_rejects_malformed_email():
    response = client.post(
        "/api/v1/analyze",
        content=b"this is not an RFC 822 email",
        headers={"content-type": "text/plain"},
    )
    assert response.status_code == 400
    assert "header block" in response.json()["detail"]


def test_analyze_email_without_optional_return_path():
    raw = (
        "From: analyst@example.test\r\n"
        "To: recipient@example.test\r\n"
        "Subject: No Return-Path header\r\n"
        "\r\n"
        "A plain message body.\r\n"
    )
    response = client.post("/api/v1/analyze", json={"raw_eml": raw})
    assert response.status_code == 200
    data = response.json()
    assert data["message"]["return_path"] is None
    assert data["campaign_correlation"]["available"] is True
    assert data["final_risk"]["verdict"] in {"MALICIOUS", "BENIGN"}


def test_analyze_rejects_oversized_upload():
    raw = b"From: sender@example.test\n\n" + (b"x" * (5 * 1024 * 1024))
    response = client.post(
        "/api/v1/analyze",
        files={"file": ("large.eml", raw, "message/rfc822")},
    )
    assert response.status_code == 413


def test_analyze_keeps_parser_and_rules_when_ml_artifacts_are_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "app.engines.ml.service.ARTIFACTS_DIR",
        tmp_path,
    )
    raw = (SAMPLES_DIR / "legitimate.eml").read_text(encoding="utf-8")
    response = client.post("/api/v1/analyze", json={"raw_eml": raw})
    assert response.status_code == 200
    data = response.json()
    assert data["threat_detection"] is not None
    assert data["ml_detection"]["available"] is False
    assert data["ml_detection"]["prediction"] is None
    assert data["ml_detection"]["probability"] is None


def test_analyze_keeps_parser_and_rules_when_ml_artifacts_are_corrupt(
    monkeypatch, tmp_path
):
    (tmp_path / "tfidf_vectorizer.joblib").write_bytes(b"not a vectorizer")
    (tmp_path / "logistic_regression.joblib").write_bytes(b"not a classifier")
    monkeypatch.setattr("app.engines.ml.service.ARTIFACTS_DIR", tmp_path)
    raw = (SAMPLES_DIR / "suspicious_phishing.eml").read_text(encoding="utf-8")
    response = client.post("/api/v1/analyze", json={"raw_eml": raw})
    assert response.status_code == 200
    data = response.json()
    assert data["threat_detection"] is not None
    assert data["ml_detection"]["available"] is False
    assert data["ml_detection"]["prediction"] is None
    assert data["ml_detection"]["probability"] is None
