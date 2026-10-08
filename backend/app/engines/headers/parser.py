from __future__ import annotations

import re
from email.utils import parsedate_to_datetime

from app.schemas.header_intelligence import ReceivedHop

_CLAUSE_RE = re.compile(
    r"\b(from|by|with|id|for)\s+(.+?)(?=\s+\b(?:from|by|with|id|for)\b|;|$)",
    re.IGNORECASE,
)
_IP_RE = re.compile(r"(?<![A-Za-z0-9])(?:\[[^\]]+\]|[0-9A-Fa-f:.]+)(?![A-Za-z0-9])")
_HOST_RE = re.compile(r"(?<![@\w])(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}(?![\w-])")
_TIMESTAMP_RE = re.compile(r";\s*(.+?)\s*$")


def parse_received_headers(parsed_email: dict) -> list[ReceivedHop]:
    values = (parsed_email.get("headers") or {}).get("received") or []
    return [parse_received_header(value, index + 1) for index, value in enumerate(values)]


def parse_received_header(raw: str, hop: int) -> ReceivedHop:
    text = str(raw or "").strip()
    clauses = {name.lower(): value.strip() for name, value in _CLAUSE_RE.findall(text)}
    timestamp = _timestamp(text)
    hostnames = _hostnames(text)
    ips = _ips(text)
    return ReceivedHop(
        hop=hop,
        raw=text,
        from_host=_host_clause(clauses.get("from")),
        by_host=_host_clause(clauses.get("by")),
        with_protocol=clauses.get("with"),
        message_id=clauses.get("id"),
        for_address=clauses.get("for"),
        timestamp=timestamp,
        hostnames=hostnames,
        ips=ips,
    )


def _host_clause(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.split("(", 1)[0].strip()
    return cleaned.split()[0].strip("[]") if cleaned else None


def _timestamp(text: str) -> str | None:
    match = _TIMESTAMP_RE.search(text)
    if not match:
        return None
    value = match.group(1).strip()
    try:
        parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    return value


def _ips(text: str) -> list[str]:
    import ipaddress

    found: list[str] = []
    for candidate in _IP_RE.findall(text):
        candidate = candidate.strip("[]")
        try:
            value = str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
        if value not in found:
            found.append(value)
    return found


def _hostnames(text: str) -> list[str]:
    found: list[str] = []
    for candidate in _HOST_RE.findall(text):
        value = candidate.lower().rstrip(".")
        if value not in found:
            found.append(value)
    return found
