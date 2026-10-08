from __future__ import annotations

import ipaddress
from urllib.parse import quote

import httpx

from app.engines.intel.models import LookupResult

MAX_RESPONSE_BYTES = 512 * 1024


class RdapClient:
    def __init__(self, timeout_seconds: float = 3.0) -> None:
        self.timeout = httpx.Timeout(timeout_seconds)

    async def lookup_ip(self, ip: str) -> LookupResult:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return LookupResult("error", {}, "Invalid IP address.")
        url = f"https://rdap.org/ip/{quote(str(address))}"
        return await self._request(url, "ip")

    async def lookup_domain(self, domain: str) -> LookupResult:
        if not domain or any(character in domain for character in "/?#"):
            return LookupResult("error", {}, "Invalid domain.")
        return await self._request(
            f"https://rdap.org/domain/{quote(domain, safe='.-')}",
            "domain",
        )

    async def _request(self, url: str, kind: str) -> LookupResult:
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
                headers={"Accept": "application/rdap+json, application/json"},
            ) as client:
                response = await client.get(url)
                if response.status_code == 429:
                    return LookupResult("unavailable", {}, "Passive provider rate limit reached.")
                if response.status_code >= 400:
                    return LookupResult("unavailable", {}, f"Passive provider returned HTTP {response.status_code}.")
                if len(response.content) > MAX_RESPONSE_BYTES:
                    return LookupResult("error", {}, "Passive provider response was too large.")
                try:
                    payload = response.json()
                except ValueError:
                    return LookupResult("error", {}, "Passive provider returned invalid JSON.")
        except (httpx.HTTPError, TimeoutError) as exc:
            return LookupResult("unavailable", {}, f"Passive provider unavailable: {type(exc).__name__}.")
        if not isinstance(payload, dict):
            return LookupResult("error", {}, "Passive provider returned an invalid object.")
        return LookupResult("available", _normalize(payload, kind))


def _normalize(payload: dict, kind: str) -> dict:
    events = {
        str(item.get("eventAction")): item.get("eventDate")
        for item in payload.get("events", [])
        if isinstance(item, dict)
    }
    entities = payload.get("entities") or []
    nameservers = [
        str(item.get("ldhName"))
        for item in payload.get("nameservers", [])
        if isinstance(item, dict) and item.get("ldhName")
    ]
    result = {
        "asn": str(payload.get("asn")) if payload.get("asn") is not None else None,
        "organization": _entity_name(entities),
        "network": payload.get("handle") or payload.get("name"),
        "registrar": _entity_name(entities) if kind == "domain" else None,
        "created_at": events.get("registration") or events.get("created"),
        "expires_at": events.get("expiration"),
        "nameservers": nameservers,
    }
    return result


def _entity_name(entities: list) -> str | None:
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        for item in entity.get("vcardArray", [None, []])[1] if isinstance(entity.get("vcardArray"), list) else []:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                return str(item[3])
    return None
