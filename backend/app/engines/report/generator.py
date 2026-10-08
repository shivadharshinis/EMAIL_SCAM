from __future__ import annotations

from io import BytesIO

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.lib import colors


def generate_pdf(analysis_id: str, data: dict) -> bytes:
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.6 * inch,
        leftMargin=0.6 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
    )
    styles = getSampleStyleSheet()
    story = [
        Paragraph("Email Threat Detection &amp; Forensic Analysis Report", styles["Title"]),
        Paragraph(f"Analysis ID: {_safe(analysis_id)}", styles["Normal"]),
        Spacer(1, 12),
    ]
    message = data.get("message") or {}
    risk = data.get("final_risk") or {}
    story += _section("Final Threat Assessment", [
        ("Verdict", risk.get("verdict")),
        ("Threat score", risk.get("score")),
        ("Threat level", risk.get("severity")),
        ("Confidence", risk.get("confidence")),
        ("Explanation", risk.get("explanation")),
    ], styles)
    story += _section("Email Metadata", [
        ("Filename", data.get("filename")),
        ("Analysis timestamp", data.get("analyzed_at")),
        ("Subject", message.get("subject")),
        ("From", ", ".join(message.get("from") or [])),
        ("To", ", ".join(message.get("to") or [])),
        ("Cc", ", ".join(message.get("cc") or [])),
        ("Reply-To", ", ".join(message.get("reply_to") or [])),
        ("Return-Path", message.get("return_path")),
        ("Date", message.get("date")),
        ("Message-ID", message.get("message_id")),
        ("Body summary", _body_summary(data)),
    ], styles)
    threat = data.get("threat_detection") or {}
    ml = data.get("ml_detection") or {}
    story += _section("ML Classification", [
        ("Prediction", ml.get("prediction")),
        ("Phishing probability", _percentage(ml.get("probability"))),
        ("Model", ml.get("model")),
        ("Note", "ML probability is evidence, not certainty."),
    ], styles)
    story += _section("Threat Detection", [
        ("Rule score", threat.get("rule_score")),
        ("Summary", threat.get("summary")),
        ("Indicators", _items(threat.get("indicators"))),
    ], styles)
    header = data.get("header_intelligence") or {}
    domains = header.get("domains") or []
    ips = header.get("ips") or []
    story += _section("Extracted Indicators of Compromise", [
        ("Observed URLs", _items(data.get("urls"))),
        ("Observed domains", _items(domains)),
        ("Observed IP addresses", _items(ips)),
        ("Punycode domains", _items([item for item in domains if item.get("is_punycode")])),
        ("IP-literal domains", _items([item for item in domains if item.get("is_ip_literal")])),
        ("Sender / Reply-To domains", _items([
            item for item in domains
            if "message.from" in item.get("source", "") or "message.reply_to" in item.get("source", "")
        ])),
        ("Evidence note", "Observed values are extracted from the email; intelligence enrichment is listed separately."),
    ], styles)
    story += _section("Header Intelligence", [
        ("Received hops", _items(header.get("received_chain"))),
        ("Authentication-Results", _items((data.get("headers") or {}).get("authentication_results"))),
        ("Received-SPF", _items((data.get("headers") or {}).get("received_spf"))),
        ("DKIM-Signature", _items((data.get("headers") or {}).get("dkim_signature"))),
        ("DMARC-related", _items((data.get("headers") or {}).get("dmarc"))),
        ("Anomalies", _items(header.get("anomalies"))),
    ], styles)
    infrastructure = data.get("infrastructure_intelligence") or {}
    story += _section("Infrastructure Intelligence", [
        ("Provider", infrastructure.get("provider")),
        ("Status", infrastructure.get("message") or "Available"),
        ("IP metadata", _items(infrastructure.get("ip_intelligence"))),
        ("Domain metadata", _items(infrastructure.get("domain_intelligence"))),
    ], styles)
    origin = data.get("probable_origin") or {}
    story += _section("Probable Origin", [
        ("Confidence", origin.get("confidence")),
        ("Source IP", origin.get("source_ip")),
        ("Country", origin.get("country")),
        ("Region", origin.get("region")),
        ("City", origin.get("city")),
        ("ASN / Organization / ISP", " / ".join(str(origin.get(key) or "") for key in ("asn", "organization", "isp")).strip(" /")),
        ("Reason", origin.get("reason")),
    ], styles)
    campaign = data.get("campaign_correlation") or {}
    story += _section("Campaign Correlation", [
        ("Matched", campaign.get("matched")),
        ("Similarity", campaign.get("similarity_score")),
        ("Confidence", campaign.get("confidence")),
        ("Related analyses", campaign.get("related_analysis_count")),
        ("Signals", _items(campaign.get("signals"))),
    ], styles)
    story += [
        Spacer(1, 12),
        Paragraph(
            "Limitations: passive intelligence only. URLs were not visited and attachments were not executed. "
            "Probable origin describes observed infrastructure, not a person's physical location. "
            "Campaign correlation indicates similarity, not common ownership.",
            styles["Normal"],
        ),
    ]
    document.build(story)
    return buffer.getvalue()


def _section(title: str, rows: list[tuple[str, object]], styles) -> list:
    data = [[Paragraph(f"<b>{_safe(key)}</b>", styles["Normal"]), Paragraph(_safe(value), styles["Normal"])] for key, value in rows]
    table = Table([[Paragraph(f"<b>{title}</b>", styles["Heading2"]), ""]] + data, colWidths=[1.7 * inch, 5.8 * inch])
    table.setStyle(TableStyle([
        ("SPAN", (0, 0), (1, 0)),
        ("BACKGROUND", (0, 0), (1, 0), colors.HexColor("#e2e8f0")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return [table, Spacer(1, 10)]


def _items(value: object) -> str:
    if not value:
        return "None"
    if isinstance(value, list):
        return "; ".join(_safe(item) for item in value)
    return _safe(value)


def _body_summary(data: dict) -> str:
    body = data.get("body") or {}
    summary = " ".join((body.get("sanitized_text") or body.get("plain_text") or "").split())
    if len(summary) > 500:
        return f"{summary[:497]}..."
    return summary or "No plain-text body was available."


def _percentage(value: object) -> str:
    if not isinstance(value, (int, float)):
        return "—"
    return f"{value:.1%}"


def _safe(value: object) -> str:
    return str(value if value is not None else "—").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
