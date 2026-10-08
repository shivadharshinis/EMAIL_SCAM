from datetime import datetime, timezone
import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, status
from starlette.datastructures import UploadFile as StarletteUploadFile

from app.auth import require_report_access
from app.core.config import get_settings
from app.engines.campaign import correlate_and_record
from app.engines.campaign.models import AnalysisRecord
from app.engines.campaign.normalizer import address_domains, normalize_subject
from app.engines.detection import detect_threats
from app.engines.headers import analyze_headers
from app.engines.intel.service import enrich_infrastructure
from app.engines.origin import resolve_probable_origin
from app.engines.ml import classify_email
from app.engines.ml.model import MODEL_NAME
from app.engines.ml.service import ARTIFACTS_DIR, get_model_status
from app.engines.parser import EmailParseError, parse_eml
from app.engines.report import store_analysis
from app.engines.scoring.service import ScoreEvidence, calculate
from app.schemas.parsed_email import AnalyzeRawRequest, ParsedEmail

router = APIRouter()
settings = get_settings()

ALLOWED_SUFFIXES = {".eml", ".txt"}
ALLOWED_CONTENT_TYPES = {
    "",
    "application/octet-stream",
    "message/rfc822",
    "text/plain",
    "text/x-eml",
}


@router.post("/analyze", response_model=ParsedEmail)
async def analyze_email(request: Request) -> ParsedEmail:
    _reject_oversized_request(request)
    payload, filename = await _read_payload(request)
    if len(payload) > settings.max_email_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Email exceeds the {settings.max_email_bytes} byte limit.",
        )
    if not _contains_header_block(payload):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The email is malformed: no RFC 822 header block was found.",
        )
    try:
        parsed = parse_eml(payload)
    except EmailParseError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    parsed["threat_detection"] = detect_threats(parsed)
    parsed["ml_detection"] = classify_email(parsed)
    parsed["header_intelligence"] = analyze_headers(parsed)
    parsed["infrastructure_intelligence"] = await enrich_infrastructure(
        parsed["header_intelligence"]
    )
    parsed["probable_origin"] = resolve_probable_origin(
        parsed["infrastructure_intelligence"],
        parsed["header_intelligence"],
    )
    record = _analysis_record(parsed)
    parsed["campaign_correlation"] = correlate_and_record(record)
    parsed["final_risk"] = calculate(
        ScoreEvidence(
            rule_score=parsed["threat_detection"]["rule_score"],
            ml_probability=parsed["ml_detection"].get("probability")
            if parsed["ml_detection"].get("available")
            else None,
            infrastructure_signal_score=_infrastructure_score(parsed),
            campaign_signal_score=parsed["campaign_correlation"].get("similarity_score") or 0,
            evidence_reasons=_evidence_reasons(parsed),
        )
    )
    parsed["filename"] = filename
    parsed["analyzed_at"] = datetime.now(timezone.utc)
    result = ParsedEmail.model_validate(parsed)
    result.analysis_id = store_analysis(result.model_dump(by_alias=True))
    return result


@router.get("/model-info", dependencies=[Depends(require_report_access)])
async def get_model_info() -> dict:
    model_status, status_message = get_model_status(ARTIFACTS_DIR)

    metrics_path = ARTIFACTS_DIR / "metrics.json"
    metrics = None
    trained_at = None
    if metrics_path.is_file():
        try:
            with metrics_path.open(encoding="utf-8") as metrics_file:
                metrics_data = json.load(metrics_file)
        except (OSError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="The model metrics file could not be read.",
            ) from exc
        metrics = metrics_data.get("test_metrics")
        trained_at = metrics_data.get("training_timestamp_utc")

    return {
        "model": MODEL_NAME,
        "feature_extraction": "TF-IDF",
        "status": model_status,
        "status_message": status_message,
        "test_metrics": metrics,
        "trained_at": trained_at,
    }


def _analysis_record(parsed: dict) -> AnalysisRecord:
    message = parsed.get("message") or {}
    headers = parsed.get("header_intelligence") or {}
    return AnalysisRecord(
        sender_domains=address_domains(message.get("from")),
        reply_to_domains=address_domains(message.get("reply_to")),
        return_path_domains=address_domains([message.get("return_path")]),
        public_ips={
            item["ip"] for item in headers.get("ips", [])
            if item.get("scope") == "public" and item.get("ip")
        },
        url_domains={
            item.get("domain") or item.get("hostname")
            for item in parsed.get("urls", [])
            if item.get("domain") or item.get("hostname")
        },
        subject=normalize_subject(message.get("subject")),
        rule_score=(parsed.get("threat_detection") or {}).get("rule_score", 0),
        ml_probability=(parsed.get("ml_detection") or {}).get("probability"),
    )


def _infrastructure_score(parsed: dict) -> int:
    headers = parsed.get("header_intelligence") or {}
    score = 0
    if any(item.get("scope") == "public" for item in headers.get("ips", [])):
        score += 25
    score += min(50, 10 * sum(
        bool(item.get("is_punycode") or item.get("is_ip_literal"))
        for item in headers.get("domains", [])
    ))
    score += min(25, 10 * len(headers.get("anomalies", [])))
    return min(score, 100)


def _evidence_reasons(parsed: dict) -> tuple[str, ...]:
    reasons = [
        f"{item['title']}: {item['evidence']}"
        for item in (parsed.get("threat_detection") or {}).get("indicators", [])
        if item.get("evidence")
    ][:2]
    header = parsed.get("header_intelligence") or {}
    anomalies = [
        f"Header anomaly — {item['title']}: {item['evidence']}"
        for item in header.get("anomalies", [])
        if item.get("evidence")
    ]
    reasons.extend(anomalies[:1])
    ml = parsed.get("ml_detection") or {}
    if ml.get("available") and ml.get("probability") is not None:
        reasons.append(
            f"ML phishing probability: {ml['probability']:.0%}."
        )
    flagged_domains = [
        item.get("domain")
        for item in header.get("domains", [])
        if item.get("is_punycode") or item.get("is_ip_literal")
    ]
    public_ips = [
        item.get("ip")
        for item in header.get("ips", [])
        if item.get("scope") == "public"
    ]
    infrastructure = parsed.get("infrastructure_intelligence") or {}
    available_ip_intel = [
        item.get("ip")
        for item in infrastructure.get("ip_intelligence", [])
        if item.get("status") == "available"
    ]
    available_domain_intel = [
        item.get("domain")
        for item in infrastructure.get("domain_intelligence", [])
        if item.get("status") == "available"
    ]
    if flagged_domains or public_ips or available_ip_intel or available_domain_intel:
        observations = []
        if flagged_domains:
            observations.append(f"domain traits observed: {', '.join(flagged_domains[:3])}")
        if public_ips:
            observations.append(f"public IPs observed: {', '.join(public_ips[:3])}")
        if available_ip_intel or available_domain_intel:
            observations.append("passive infrastructure metadata was available")
        reasons.append(f"Infrastructure evidence — {'; '.join(observations)}.")
    campaign = parsed.get("campaign_correlation") or {}
    if campaign.get("matched"):
        signals = ", ".join(campaign.get("signals") or [])
        if signals:
            reasons.append(f"Campaign correlation signals: {signals}.")
    return tuple(reasons[:6])


def _reject_oversized_request(request: Request) -> None:
    content_length = request.headers.get("content-length")
    if not content_length:
        return
    try:
        length = int(content_length)
    except ValueError:
        return
    if length > settings.max_email_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Email exceeds the {settings.max_email_bytes} byte limit.",
        )


def _contains_header_block(data: bytes) -> bool:
    header_block = data.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
    return any(
        b":" in line and not line.startswith((b" ", b"\t"))
        for line in header_block.splitlines()
    )


async def _read_payload(request: Request) -> tuple[bytes, str | None]:
    content_type = (request.headers.get("content-type") or "").lower()

    if "application/json" in content_type:
        try:
            body = await request.json()
            data = AnalyzeRawRequest.model_validate(body)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="JSON body must include a non-empty raw_eml string.",
            ) from exc
        if not data.raw_eml.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email content is empty.",
            )
        return data.raw_eml.encode("utf-8", errors="replace"), None

    if "multipart/form-data" in content_type or "application/x-www-form-urlencoded" in content_type:
        form = await request.form()
        upload = form.get("file")
        raw_eml = form.get("raw_eml")

        if isinstance(upload, (UploadFile, StarletteUploadFile)) and upload.filename:
            _validate_upload(upload)
            content = await upload.read()
            if len(content) > settings.max_email_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail=f"Email exceeds the {settings.max_email_bytes} byte limit.",
                )
            if not content.strip():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Uploaded email is empty.",
                )
            return content, upload.filename

        if isinstance(raw_eml, str):
            if not raw_eml.strip():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email content is empty.",
                )
            return raw_eml.encode("utf-8", errors="replace"), None

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide an .eml file upload or raw_eml text.",
        )

    body = await request.body()
    if body.strip():
        return body, None

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Provide an .eml file upload or raw_eml text.",
    )


def _validate_upload(file: UploadFile | StarletteUploadFile) -> None:
    suffix = Path(file.filename or "").suffix.lower()
    content_type = (file.content_type or "").split(";")[0].strip().lower()
    if suffix and suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .eml or .txt email files are accepted.",
        )
    if content_type and content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported email content type.",
        )
