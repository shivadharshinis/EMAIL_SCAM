from __future__ import annotations

from app.engines.origin.resolver import build_candidates, select_candidate


def resolve_probable_origin(
    infrastructure_intelligence: dict,
    header_intelligence: dict | None = None,
) -> dict:
    try:
        candidates = build_candidates(infrastructure_intelligence, header_intelligence)
        candidate = select_candidate(candidates)
    except (AttributeError, TypeError, ValueError):
        candidate = None
        candidates = []

    if candidate is None:
        return {
            "available": False,
            "confidence": None,
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "asn": None,
            "organization": None,
            "isp": None,
            "source_ip": None,
            "reason": "No usable public IP geolocation data is available.",
        }

    confidence = "LOW"
    if candidate.country or candidate.country_code:
        confidence = "MEDIUM"
    if (
        candidate.country
        and candidate.country_code
        and (candidate.asn or candidate.organization or candidate.isp)
    ):
        confidence = "HIGH"

    return {
        "available": True,
        "confidence": confidence,
        "country": candidate.country,
        "country_code": candidate.country_code,
        "region": candidate.region,
        "city": candidate.city,
        "latitude": candidate.latitude,
        "longitude": candidate.longitude,
        "asn": candidate.asn,
        "organization": candidate.organization,
        "isp": candidate.isp,
        "source_ip": candidate.ip,
        "reason": (
            f"Estimated originating infrastructure from {len(candidates)} "
            "public IP candidate(s) and passive provider metadata. "
            "This does not identify a person's physical location."
        ),
    }
