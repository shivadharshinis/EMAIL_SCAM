from __future__ import annotations

from app.core.config import Settings, get_settings
from app.engines.intel.models import LookupResult
from app.engines.intel.provider import PassiveIntelProvider
from app.engines.intel.rdap_client import RdapClient
from app.engines.intel.ipapi_client import IpapiIsClient


async def enrich_infrastructure(
    header_intelligence: dict,
    settings: Settings | None = None,
    provider: PassiveIntelProvider | None = None,
) -> dict:
    settings = settings or get_settings()
    if not settings.passive_intel_enabled:
        return {
            "enabled": False,
            "provider": None,
            "ip_intelligence": [],
            "domain_intelligence": [],
            "message": "Passive enrichment is disabled.",
        }

    provider = provider or _configured_provider(settings)
    ip_results: list[dict] = []
    domain_results: list[dict] = []
    lookups = 0
    max_lookups = max(0, settings.passive_intel_max_lookups)
    seen_ips: set[str] = set()
    seen_domains: set[str] = set()

    for item in header_intelligence.get("ips", []):
        ip = item.get("ip")
        if (
            lookups >= max_lookups
            or item.get("scope") != "public"
            or not ip
            or ip in seen_ips
        ):
            continue
        seen_ips.add(ip)
        result = await _safe_lookup(provider.lookup_ip, ip)
        ip_results.append(_ip_result(ip, result, settings.passive_intel_provider))
        lookups += 1
    for item in header_intelligence.get("domains", []):
        domain = item.get("domain")
        if lookups >= max_lookups:
            break
        if not domain or domain in seen_domains:
            continue
        seen_domains.add(domain)
        result = await _safe_lookup(provider.lookup_domain, domain)
        domain_results.append(_domain_result(domain, result, settings.passive_intel_provider))
        lookups += 1
    return {
        "enabled": True,
        "provider": settings.passive_intel_provider,
        "ip_intelligence": ip_results,
        "domain_intelligence": domain_results,
        "message": None if lookups else "No eligible identifiers were available for passive lookup.",
    }


def _configured_provider(settings: Settings) -> PassiveIntelProvider:
    if settings.passive_intel_provider.lower() == "ipapi.is":
        return IpapiIsClient(
            settings.ipapi_is_api_key,
            settings.passive_intel_timeout_seconds,
        )
    return RdapClient(settings.passive_intel_timeout_seconds)


async def _safe_lookup(function, value: str) -> LookupResult:
    try:
        result = await function(value)
        if isinstance(result, LookupResult):
            return result
        return LookupResult("error", {}, "Passive provider returned an invalid result.")
    except Exception:
        return LookupResult("error", {}, "Passive provider lookup failed.")


def _ip_result(ip: str, result: LookupResult, provider: str) -> dict:
    return {
        "ip": ip,
        "status": result.status,
        "asn": result.data.get("asn"),
        "organization": result.data.get("organization"),
        "network": result.data.get("network"),
        "country": result.data.get("country"),
        "country_code": result.data.get("country_code"),
        "region": result.data.get("region"),
        "city": result.data.get("city"),
        "latitude": result.data.get("latitude"),
        "longitude": result.data.get("longitude"),
        "isp": result.data.get("isp"),
        "provider": provider,
        "message": result.message,
    }


def _domain_result(domain: str, result: LookupResult, provider: str) -> dict:
    return {
        "domain": domain,
        "status": result.status,
        "registrar": result.data.get("registrar"),
        "created_at": result.data.get("created_at"),
        "expires_at": result.data.get("expires_at"),
        "nameservers": result.data.get("nameservers", []),
        "provider": provider,
        "message": result.message,
    }
