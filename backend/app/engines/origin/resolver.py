from __future__ import annotations

import ipaddress

from app.engines.origin.models import OriginCandidate


def build_candidates(
    infrastructure_intelligence: dict,
    header_intelligence: dict | None = None,
) -> list[OriginCandidate]:
    public_ips = {
        item.get("ip")
        for item in (header_intelligence or {}).get("ips", [])
        if item.get("scope") == "public" and item.get("ip")
    }
    candidates: list[OriginCandidate] = []
    for item in infrastructure_intelligence.get("ip_intelligence", []):
        ip = item.get("ip")
        if not ip or item.get("status") != "available":
            continue
        if not _is_public_ip(ip):
            continue
        if public_ips and ip not in public_ips:
            continue
        country = _text(item.get("country"))
        country_code = _text(item.get("country_code"))
        if not any(
            value is not None
            for value in (
                country,
                country_code,
                item.get("region"),
                item.get("city"),
                item.get("latitude"),
                item.get("longitude"),
            )
        ):
            continue
        candidates.append(
            OriginCandidate(
                ip=ip,
                country=country,
                country_code=country_code,
                region=_text(item.get("region")),
                city=_text(item.get("city")),
                latitude=_number(item.get("latitude")),
                longitude=_number(item.get("longitude")),
                asn=_text(item.get("asn")),
                organization=_text(item.get("organization")),
                isp=_text(item.get("isp")),
                evidence_count=len(item.get("sources") or []),
            )
        )
    return candidates


def select_candidate(candidates: list[OriginCandidate]) -> OriginCandidate | None:
    if not candidates:
        return None
    return max(
        enumerate(candidates),
        key=lambda pair: (
            _metadata_score(pair[1]),
            pair[1].evidence_count,
            -pair[0],
        ),
    )[1]


def _metadata_score(candidate: OriginCandidate) -> int:
    return sum(
        value is not None
        for value in (
            candidate.country,
            candidate.country_code,
            candidate.region,
            candidate.city,
            candidate.latitude,
            candidate.longitude,
            candidate.asn,
            candidate.organization,
            candidate.isp,
        )
    )


def _text(value: object) -> str | None:
    return str(value).strip() or None if value is not None else None


def _number(value: object) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global
