from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.engines.report import clear_analyses


client = TestClient(app)
SAMPLES_DIR = Path(__file__).resolve().parents[2] / "samples"


def setup_function():
    clear_analyses()


def test_report_generation_returns_pdf_with_actual_analysis_result(monkeypatch):
    from app.engines.report import generator

    captured_sections = []
    build_section = generator._section

    def capture_section(title, rows, styles):
        captured_sections.append((title, dict(rows)))
        return build_section(title, rows, styles)

    monkeypatch.setattr(generator, "_section", capture_section)
    raw = (SAMPLES_DIR / "legitimate.eml").read_text(encoding="utf-8")
    analyzed = client.post("/api/v1/analyze", json={"raw_eml": raw})
    assert analyzed.status_code == 200
    data = analyzed.json()
    analysis_id = data["analysis_id"]
    response = client.get(f"/api/v1/reports/{analysis_id}")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.content.startswith(b"%PDF")
    assert "email_forensic_report_" in response.headers["content-disposition"]

    sections = dict(captured_sections)
    assert sections["Final Threat Assessment"]["Threat score"] == data["final_risk"]["score"]
    assert sections["Final Threat Assessment"]["Verdict"] == data["final_risk"]["verdict"]
    assert sections["Final Threat Assessment"]["Threat level"] == data["final_risk"]["severity"]
    assert sections["Final Threat Assessment"]["Confidence"] == data["final_risk"]["confidence"]
    assert sections["Final Threat Assessment"]["Explanation"] == data["final_risk"]["explanation"]
    assert sections["Email Metadata"]["Subject"] == data["message"]["subject"]
    assert sections["Email Metadata"]["From"] == ", ".join(data["message"]["from"])
    assert sections["Email Metadata"]["Reply-To"] == ", ".join(data["message"]["reply_to"])
    assert (
        sections["Email Metadata"]["Analysis timestamp"].isoformat().replace("+00:00", "Z")
        == data["analyzed_at"]
    )
    assert sections["Email Metadata"]["Body summary"]
    assert sections["ML Classification"]["Prediction"] == data["ml_detection"]["prediction"]
    assert sections["ML Classification"]["Model"] == data["ml_detection"]["model"]
    assert sections["Threat Detection"]["Rule score"] == data["threat_detection"]["rule_score"]
    assert (
        sections["Extracted Indicators of Compromise"]["Observed URLs"]
        == generator._items(data["urls"])
    )
    assert (
        sections["Extracted Indicators of Compromise"]["Observed IP addresses"]
        == generator._items(data["header_intelligence"]["ips"])
    )
    assert (
        sections["Infrastructure Intelligence"]["IP metadata"]
        == generator._items(data["infrastructure_intelligence"]["ip_intelligence"])
    )
    assert sections["Probable Origin"]["Reason"] == data["probable_origin"]["reason"]
    assert sections["Campaign Correlation"]["Matched"] == data["campaign_correlation"]["matched"]
    assert (
        sections["Campaign Correlation"]["Signals"]
        == generator._items(data["campaign_correlation"]["signals"])
    )


def test_missing_report_id_returns_404():
    response = client.get("/api/v1/reports/does-not-exist")
    assert response.status_code == 404


def test_case_list_and_detail_require_report_auth_when_enabled(monkeypatch):
    from types import SimpleNamespace

    import app.auth
    import app.api.routers.auth as auth_router

    settings = SimpleNamespace(
        report_auth_required=True,
        jwt_secret_key="test-secret-with-at-least-32-bytes",
        jwt_algorithm="HS256",
        jwt_expire_minutes=60,
        demo_username="analyst",
        demo_password="test-password",
    )
    monkeypatch.setattr(
        app.auth,
        "get_settings",
        lambda: settings,
    )
    monkeypatch.setattr(auth_router, "get_settings", lambda: settings)

    for path in (
        "/api/v1/analyses",
        "/api/v1/analyses/not-found",
        "/api/v1/model-info",
    ):
        response = client.get(path)
        assert response.status_code == 401

    auth_response = client.post(
        "/api/v1/auth/token",
        json={"username": "analyst", "password": "test-password"},
    )
    assert auth_response.status_code == 200
    token = auth_response.json()["access_token"]
    response = client.get(
        "/api/v1/analyses",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200


def test_report_includes_actual_stored_analysis_fields():
    raw = (SAMPLES_DIR / "suspicious_phishing.eml").read_text(encoding="utf-8")
    analyzed = client.post("/api/v1/analyze", json={"raw_eml": raw})
    assert analyzed.status_code == 200
    data = analyzed.json()

    response = client.get(f"/api/v1/reports/{data['analysis_id']}")
    assert response.status_code == 200
    assert response.content.startswith(b"%PDF")
