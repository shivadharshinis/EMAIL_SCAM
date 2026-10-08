from __future__ import annotations

import hashlib
import re
from email.message import Message
from urllib.parse import urlparse

URL_PATTERN = re.compile(
    r"""(?xi)
    \b(
        (?:https?://|ftp://)[^\s<>"'\\)]+
        |
        www\.[^\s<>"'\\)]+
    )
    """
)

UNSAFE_URL_SCHEMES = {"javascript", "data", "vbscript", "file"}

INTERESTING_HEADER_MAP = {
    "received": "received",
    "authentication-results": "authentication_results",
    "arc-authentication-results": "authentication_results",
    "received-spf": "received_spf",
    "dkim-signature": "dkim_signature",
}


def decode_header_value(message: Message, name: str) -> str | None:
    value = message.get(name)
    if value is None:
        return None
    return str(value).strip() or None


def get_all_headers(message: Message, name: str) -> list[str]:
    values: list[str] = []
    for key, value in message.raw_items() if hasattr(message, "raw_items") else message.items():
        if key.lower() == name.lower():
            text = str(value).strip()
            if text:
                values.append(text)
    if values:
        return values
    return [str(v).strip() for v in message.get_all(name, []) if str(v).strip()]


def collect_raw_headers(message: Message) -> dict[str, list[str]]:
    raw: dict[str, list[str]] = {}
    for key, value in message.items():
        raw.setdefault(key, []).append(str(value))
    return raw


def collect_named_headers(message: Message) -> dict[str, list[str]]:
    grouped = {
        "received": [],
        "authentication_results": [],
        "received_spf": [],
        "dkim_signature": [],
        "dmarc": [],
    }
    for key, value in message.items():
        lower = key.lower()
        text = str(value).strip()
        if not text:
            continue
        mapped = INTERESTING_HEADER_MAP.get(lower)
        if mapped:
            grouped[mapped].append(text)
        if "dmarc" in lower or (mapped == "authentication_results" and "dmarc" in text.lower()):
            grouped["dmarc"].append(f"{key}: {text}" if "dmarc" in lower else text)
    return grouped


def extract_urls(*texts: str) -> list[dict[str, str | None]]:
    found: list[dict[str, str | None]] = []
    seen: set[str] = set()
    for text in texts:
        if not text:
            continue
        for match in URL_PATTERN.finditer(text):
            raw = match.group(1).rstrip(".,;:!?)]}>\"'")
            parsed = describe_url(raw)
            key = parsed["url"]
            if key in seen:
                continue
            seen.add(key)
            found.append(parsed)
    return found


def describe_url(raw: str) -> dict[str, str | None]:
    candidate = raw.strip()
    if candidate.lower().startswith("www."):
        candidate = f"http://{candidate}"
    try:
        parsed = urlparse(candidate)
    except Exception:
        return {"url": raw, "hostname": None, "domain": None}

    scheme = (parsed.scheme or "").lower()
    if scheme in UNSAFE_URL_SCHEMES:
        return {"url": raw, "hostname": None, "domain": None}

    hostname = parsed.hostname
    domain = hostname.lower() if hostname else None
    return {
        "url": raw,
        "hostname": hostname,
        "domain": domain,
    }


def extract_attachment_metadata(message: Message) -> list[dict[str, str | int | None]]:
    attachments: list[dict[str, str | int | None]] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        if not _is_attachment(part):
            continue
        filename = part.get_filename() or "unnamed"
        mime_type = part.get_content_type() or "application/octet-stream"
        payload = b""
        try:
            decoded = part.get_payload(decode=True)
            if isinstance(decoded, bytes):
                payload = decoded
            elif decoded is not None:
                payload = str(decoded).encode("utf-8", errors="replace")
        except Exception:
            payload = b""
        attachments.append(
            {
                "filename": str(filename),
                "mime_type": mime_type,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return attachments


def _is_attachment(part: Message) -> bool:
    filename = part.get_filename()
    disposition = str(part.get("Content-Disposition") or "").lower()
    if "attachment" in disposition:
        return True
    if filename and "inline" in disposition:
        return True
    if filename and part.get_content_maintype() not in {"text"}:
        return True
    return bool(filename and "attachment" in disposition)


def get_body_parts(message: Message) -> tuple[str, str]:
    plain_chunks: list[str] = []
    html_chunks: list[str] = []

    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart():
                continue
            if _is_attachment(part):
                continue
            content_type = part.get_content_type()
            text = _decode_part_text(part)
            if not text:
                continue
            if content_type == "text/plain":
                plain_chunks.append(text)
            elif content_type == "text/html":
                html_chunks.append(text)
    else:
        content_type = message.get_content_type()
        text = _decode_part_text(message)
        if content_type == "text/html":
            html_chunks.append(text)
        else:
            plain_chunks.append(text)

    return "\n\n".join(plain_chunks).strip(), "\n\n".join(html_chunks).strip()


def _decode_part_text(part: Message) -> str:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = part.get_payload()
    if payload is None:
        return ""
    if isinstance(payload, bytes):
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            return payload.decode("utf-8", errors="replace")
    return str(payload)
