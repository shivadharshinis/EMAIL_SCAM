from __future__ import annotations

import ipaddress

import httpx

from app.engines.intel.models import LookupResult


class IpapiIsClient:
    def __init__(self, api_key: str, timeout_seconds: float = 3.0) -> None:
        self.api_key = api_key
        self.timeout = httpx.Timeout(timeout_seconds)

    async def lookup_ip(self, ip: str) -> LookupResult:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return LookupResult("error", {}, "Invalid IP address.")
        if not self.api_key:
            return LookupResult("unavailable", {}, "IP geolocation provider API key is not configured.")
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                response = await client.get(
                    "https://api.ipapi.is",
                    params={"q": ip, "key": self.api_key},
                    headers={"Accept": "application/json"},
                )
                if response.status_code == 429:
                    return LookupResult("unavailable", {}, "IP geolocation provider rate limit reached.")
                if response.status_code >= 400:
                    return LookupResult("unavailable", {}, f"IP geolocation provider returned HTTP {response.status_code}.")
                payload = response.json()
        except (httpx.HTTPError, TimeoutError):
            return LookupResult("unavailable", {}, "IP geolocation provider is unavailable.")
        except ValueError:
            return LookupResult("error", {}, "IP geolocation provider returned invalid JSON.")
        if not isinstance(payload, dict):
            return LookupResult("error", {}, "IP geolocation provider returned an invalid object.")
        location = payload.get("location") if isinstance(payload.get("location"), dict) else {}
        asn = payload.get("asn") if isinstance(payload.get("asn"), dict) else {}
        company = payload.get("company") if isinstance(payload.get("company"), dict) else {}
        return LookupResult(
            "available",
            {
                "country": location.get("country"),
                "country_code": location.get("country_code"),
                "region": location.get("state") or location.get("region"),
                "city": location.get("city"),
                "latitude": location.get("latitude"),
                "longitude": location.get("longitude"),
                "asn": asn.get("asn") or payload.get("asn"),
                "organization": company.get("name") or payload.get("organization"),
                "isp": payload.get("isp") or company.get("name"),
                "network": asn.get("route"),
            },
        )

    async def lookup_domain(self, domain: str) -> LookupResult:
        return LookupResult(
            "not_requested",
            {},
            "This provider is configured for IP geolocation only.",
        )
