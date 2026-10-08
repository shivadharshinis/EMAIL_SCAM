from __future__ import annotations

import ipaddress
import re
from email.utils import parseaddr

from app.schemas.header_intelligence import ObservedDomain, ObservedIp, ReceivedHop

_IP_RE = re.compile(r"(?<![A-Za-z0-9])(?:\[[^\]]+\]|[0-9A-Fa-f:.]+)(?![A-Za-z0-9])")
_DOMAIN_RE = re.compile(r"(?<!\w)(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}(?![\w-])")
_DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def classify_ip(value: str) -> tuple[str, str] | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.is_loopback:
        scope = "loopback"
    elif any(address in network for network in _DOCUMENTATION_NETWORKS):
        scope = "reserved"
    elif address.is_private or address.is_link_local:
        scope = "private"
    elif address.is_reserved or address.is_multicast or not address.is_global:
        scope = "reserved"
    else:
        scope = "public"
    return ("ipv4" if address.version == 4 else "ipv6", scope)


def extract_ips(parsed_email: dict, hops: list[ReceivedHop]) -> list[ObservedIp]:
    evidence: dict[str, set[str]] = {}
    for hop in hops:
        for value in hop.ips:
            evidence.setdefault(value, set()).add(f"received[{hop.hop - 1}]")
    headers = parsed_email.get("headers") or {}
    for field in ("authentication_results", "received_spf"):
        for index, value in enumerate(headers.get(field) or []):
            for candidate in _valid_ips(str(value)):
                evidence.setdefault(candidate, set()).add(f"{field}[{index}]")
    return [
        ObservedIp(
            ip=value,
            version=class_info[0],
            scope=class_info[1],
            sources=sorted(sources),
        )
        for value, sources in sorted(evidence.items())
        if (class_info := classify_ip(value)) is not None
    ]


def extract_domains(parsed_email: dict, hops: list[ReceivedHop]) -> list[ObservedDomain]:
    found: dict[tuple[str, str], ObservedDomain] = {}
    message = parsed_email.get("message") or {}
    for field in ("from", "reply_to"):
        for index, value in enumerate(message.get(field) or []):
            _add_address_domains(found, str(value), f"message.{field}[{index}]")
    for field in ("return_path", "message_id"):
        value = message.get(field)
        if value:
            _add_domains(found, str(value), f"message.{field}")
    for hop in hops:
        for host in hop.hostnames:
            _add_domain(found, host, f"received[{hop.hop - 1}]")
    for index, item in enumerate(parsed_email.get("urls") or []):
        host = item.get("hostname") or item.get("domain")
        if host:
            _add_domain(found, str(host), f"urls[{index}]")
    return list(found.values())


def _valid_ips(text: str) -> list[str]:
    values: list[str] = []
    for candidate in _IP_RE.findall(text):
        candidate = candidate.strip("[]")
        if classify_ip(candidate) and candidate not in values:
            values.append(str(ipaddress.ip_address(candidate)))
    return values


def _add_address_domains(found: dict, value: str, source: str) -> None:
    _, address = parseaddr(value)
    _add_domains(found, address or value, source)


def _add_domain(found: dict, value: str, source: str) -> None:
    _add_domains(found, value, source)


def _add_domains(found: dict, value: str, source: str) -> None:
    for candidate in _DOMAIN_RE.findall(value):
        domain = candidate.lower().rstrip(".")
        if not _valid_domain(domain):
            continue
        key = (domain, source)
        labels = domain.split(".")
        found[key] = ObservedDomain(
            domain=domain,
            source=source,
            is_punycode=any(label.startswith("xn--") for label in labels),
            is_ip_literal=classify_ip(domain) is not None,
            subdomain=".".join(labels[:-2]) or None,
        )


def _valid_domain(domain: str) -> bool:
    return len(domain) <= 253 and all(
        label and len(label) <= 63 and not label.startswith("-") and not label.endswith("-")
        for label in domain.split(".")
    )
