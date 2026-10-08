from __future__ import annotations

import ipaddress
import re
from email.utils import parseaddr
from urllib.parse import urlparse

from app.engines.detection.indicators import indicator
from app.schemas.threat_detection import IndicatorSeverity, ThreatIndicator

BRAND_DOMAINS = {
    "amazon": {"amazon.com"},
    "apple": {"apple.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com"},
    "paypal": {"paypal.com"},
    "google": {"google.com"},
}
BRAND_NAMES = set(BRAND_DOMAINS)
RISKY_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".hta"}
SOCIAL_PATTERNS = {
    "urgent_action": (
        re.compile(r"\b(act now|urgent|immediately|within \d+ minutes?|final notice)\b", re.I),
        "urgent action",
    ),
    "credential_request": (
        re.compile(r"\b(password|passcode|credentials?|security code|login details)\b", re.I),
        "credential request",
    ),
    "account_suspension": (
        re.compile(r"\b(account|access).{0,30}\b(lock|suspend|suspension|disabled|closed)\b", re.I),
        "account suspension",
    ),
    "payment_request": (
        re.compile(r"\b(payment|pay|wire transfer|bank details|invoice)\b", re.I),
        "payment request",
    ),
    "verification_request": (
        re.compile(r"\b(verify|verification|confirm)\b", re.I),
        "verification request",
    ),
    "security_alert": (
        re.compile(r"\b(security alert|suspicious sign[- ]?in|unusual activity)\b", re.I),
        "security alert",
    ),
}
SUSPICIOUS_URL_KEYWORDS = re.compile(
    r"\b(login|verify|verification|secure|password|credential|reset|wallet|payment)\b",
    re.I,
)
AUTH_FAILURE = re.compile(r"\b(?:fail|failed|failure|softfail|permerror|temperror|invalid)\b", re.I)
AUTH_MISMATCH = re.compile(r"\b(?:mismatch|misaligned|does not align|alignment failed)\b", re.I)


def detect_identity(parsed: dict) -> list[ThreatIndicator]:
    message = parsed.get("message") or {}
    senders = _addresses(message.get("from", []))
    replies = _addresses(message.get("reply_to", []))
    return_paths = _addresses([message.get("return_path") or ""])
    results: list[ThreatIndicator] = []

    if senders and replies and not _same_domain(senders[0], replies[0]):
        results.append(indicator(
            "reply_to_mismatch", IndicatorSeverity.high,
            "Reply-To differs from sender",
            "The reply destination uses a different email domain than the visible sender.",
            f"From: {senders[0]}; Reply-To: {replies[0]}",
            0.95,
        ))
    if senders and return_paths and not _same_domain(senders[0], return_paths[0]):
        results.append(indicator(
            "return_path_mismatch", IndicatorSeverity.medium,
            "Return-Path differs from sender",
            "The envelope return address uses a different email domain than the visible sender.",
            f"From: {senders[0]}; Return-Path: {return_paths[0]}",
            0.9,
        ))

    from_text = " ".join(message.get("from", []))
    domains = [_domain(value) for value in senders + replies + return_paths]
    for brand in BRAND_NAMES:
        if re.search(rf"\b{re.escape(brand)}\b", from_text, re.I) and not any(
            domain in BRAND_DOMAINS[brand] for domain in domains
        ):
            results.append(indicator(
                "display_name_impersonation", IndicatorSeverity.medium,
                "Brand-like display name uses another domain",
                "The sender display name resembles a known brand, but the address domain is not its known domain.",
                f"Display name/address: {from_text}",
                0.82,
            ))
            break

    for value in senders + replies + return_paths:
        domain = _domain(value)
        if not domain:
            continue
        if domain.startswith("xn--") or ".xn--" in domain:
            results.append(indicator(
                "punycode_domain", IndicatorSeverity.medium,
                "Sender domain uses punycode",
                "The sender domain contains an internationalized label encoded with punycode.",
                domain, 0.95,
            ))
        try:
            ipaddress.ip_address(domain.strip("[]"))
        except ValueError:
            continue
        results.append(indicator(
            "ip_literal_domain", IndicatorSeverity.medium,
            "Sender uses an IP-literal domain",
            "The sender address uses an IP address instead of a DNS domain.",
            value, 0.95,
        ))
    return _unique(results)


def detect_authentication(headers: dict) -> list[ThreatIndicator]:
    results: list[ThreatIndicator] = []
    groups = (
        ("authentication_results", "Authentication-Results"),
        ("received_spf", "Received-SPF"),
        ("dkim_signature", "DKIM-Signature"),
        ("dmarc", "DMARC"),
    )
    for key, label in groups:
        for value in headers.get(key, []) or []:
            if AUTH_FAILURE.search(value) or AUTH_MISMATCH.search(value):
                results.append(indicator(
                    f"{key}_failure", IndicatorSeverity.high,
                    f"{label} reports a failure",
                    f"The receiving server explicitly reported a {label} failure or mismatch.",
                    value, 0.94,
                ))
    return results


def detect_social_engineering(parsed: dict) -> list[ThreatIndicator]:
    body = " ".join(
        str(parsed.get("body", {}).get(key, ""))
        for key in ("plain_text", "sanitized_text")
    )
    subject = str(parsed.get("message", {}).get("subject") or "")
    text = f"{subject}\n{body}"
    results = []
    for category, (pattern, label) in SOCIAL_PATTERNS.items():
        matches = list(dict.fromkeys(match.group(0).strip() for match in pattern.finditer(text)))
        if matches:
            results.append(indicator(
                category, IndicatorSeverity.medium,
                f"{label.title()} language detected",
                "The message contains language commonly used for this social-engineering theme.",
                ", ".join(matches[:3]), 0.78,
            ))
    return results


def detect_urls(parsed: dict) -> list[ThreatIndicator]:
    results: list[ThreatIndicator] = []
    for item in parsed.get("urls", []) or []:
        url = str(item.get("url") or "")
        hostname = str(item.get("hostname") or "").lower()
        parsed_url = urlparse(url if "://" in url else f"http://{url}")
        evidence = url
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            results.append(indicator(
                "ip_based_url", IndicatorSeverity.high,
                "URL uses an IP address",
                "The extracted URL points directly to an IP address rather than a hostname.",
                evidence, 0.95,
            ))
        if hostname.startswith("xn--") or ".xn--" in hostname:
            results.append(indicator(
                "url_punycode", IndicatorSeverity.medium,
                "URL hostname uses punycode",
                "The URL hostname contains an internationalized label encoded with punycode.",
                evidence, 0.95,
            ))
        if "%" in url or len(url) > 150:
            results.append(indicator(
                "suspicious_url_encoding", IndicatorSeverity.low,
                "URL contains unusual encoding or length",
                "The URL contains percent encoding or is unusually long and deserves review.",
                evidence, 0.7,
            ))
        if len(hostname.split(".")) > 4:
            results.append(indicator(
                "excessive_url_subdomains", IndicatorSeverity.low,
                "URL has many subdomains",
                "The hostname contains more than four labels.",
                evidence, 0.68,
            ))
        if SUSPICIOUS_URL_KEYWORDS.search(f"{hostname}{parsed_url.path}"):
            results.append(indicator(
                "suspicious_url_keyword", IndicatorSeverity.medium,
                "URL contains a sensitive-action keyword",
                "The URL contains a keyword associated with login, verification, credentials, or payment.",
                evidence, 0.75,
            ))
        if parsed_url.scheme.lower() == "http":
            results.append(indicator(
                "insecure_http_url", IndicatorSeverity.low,
                "URL uses HTTP",
                "The extracted URL does not use transport encryption.",
                evidence, 0.9,
            ))
    return _unique(results)


def detect_attachments(parsed: dict) -> list[ThreatIndicator]:
    results = []
    for attachment in parsed.get("attachments", []) or []:
        filename = str(attachment.get("filename") or "")
        extension = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if extension in RISKY_EXTENSIONS:
            results.append(indicator(
                "risky_attachment_extension", IndicatorSeverity.high,
                "Attachment uses a potentially risky file extension",
                "The attachment extension can be used to deliver executable or script content.",
                filename, 0.92,
            ))
    return results


def _addresses(values: list[str]) -> list[str]:
    result = []
    for value in values:
        address = parseaddr(str(value))[1].lower()
        if address:
            result.append(address)
    return result


def _domain(value: str) -> str:
    return value.rsplit("@", 1)[-1].strip(" <>[]").lower() if "@" in value else ""


def _same_domain(left: str, right: str) -> bool:
    return _domain(left) == _domain(right)


def _unique(items: list[ThreatIndicator]) -> list[ThreatIndicator]:
    seen: set[tuple[str, str]] = set()
    unique = []
    for item in items:
        key = (item.type, item.evidence)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique
