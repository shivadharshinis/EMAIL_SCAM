import asyncio

from app.engines.headers import analyze_headers
from app.engines.intel.models import LookupResult
from app.engines.intel.service import enrich_infrastructure
from app.core.config import Settings


def _email(received):
    return {
        "message": {
            "from": ["Alice <alice@mail.example.test>"],
            "reply_to": ["Alice <alice@mail.example.test>"],
            "return_path": "<bounce@mail.example.test>",
            "message_id": "<abc@mail.example.test>",
        },
        "headers": {
            "received": received,
            "authentication_results": ["mx.example.test; client-ip=203.0.113.9"],
            "received_spf": ["pass (client-ip=2001:db8::9)"],
        },
        "urls": [{"hostname": "login.mail.example.test", "domain": "login.mail.example.test"}],
    }


def test_received_chain_extracts_fields_and_preserves_order():
    result = analyze_headers(
        _email(
            [
                "from relay.example.test (relay.example.test [203.0.113.10]) by mx.example.test with ESMTP id one; Tue, 06 Oct 2026 10:00:00 +0000",
                "from [192.168.1.2] by relay.example.test with SMTP; Tue, 06 Oct 2026 09:00:00 +0000",
            ]
        )
    )
    assert [item["hop"] for item in result["received_chain"]] == [1, 2]
    assert result["received_chain"][0]["from_host"] == "relay.example.test"
    assert result["received_chain"][0]["by_host"] == "mx.example.test"
    assert result["received_chain"][0]["with_protocol"] == "ESMTP"
    assert result["received_chain"][0]["message_id"] == "one"
    assert "203.0.113.10" in result["received_chain"][0]["ips"]


def test_ip_classification_and_domains_are_deterministic():
    result = analyze_headers(_email(["from mx.example.test by mx.example.test; not-a-date"]))
    scopes = {item["ip"]: item["scope"] for item in result["ips"]}
    assert scopes["203.0.113.9"] == "reserved"
    assert scopes["2001:db8::9"] == "reserved"
    domains = {item["domain"] for item in result["domains"]}
    assert "mail.example.test" in domains
    assert "login.mail.example.test" in domains
    assert result["anomalies"][0]["type"] == "invalid_received_timestamp"


def test_malformed_received_does_not_crash():
    result = analyze_headers(_email(["this is malformed"]))
    assert result["received_chain"][0]["raw"] == "this is malformed"
    assert result["anomalies"][0]["type"] == "unparseable_received"


class FakeProvider:
    async def lookup_ip(self, ip):
        return LookupResult("available", {"asn": "AS64500", "organization": "Example"})

    async def lookup_domain(self, domain):
        return LookupResult("available", {"registrar": "Example Registrar"})


def test_disabled_enrichment_makes_no_provider_calls():
    settings = Settings(passive_intel_enabled=False)
    result = asyncio.run(
        enrich_infrastructure({"ips": [], "domains": []}, settings, FakeProvider())
    )
    assert result["enabled"] is False
    assert result["message"] == "Passive enrichment is disabled."


def test_enrichment_skips_reserved_ips_and_returns_provider_data():
    settings = Settings(
        passive_intel_enabled=True,
        passive_intel_provider="rdap",
        passive_intel_max_lookups=5,
    )
    result = asyncio.run(
        enrich_infrastructure(
            {
                "ips": [
                    {"ip": "203.0.113.10", "scope": "reserved"},
                    {"ip": "8.8.8.8", "scope": "public"},
                ],
                "domains": [{"domain": "example.test"}],
            },
            settings,
            FakeProvider(),
        )
    )
    assert [item["ip"] for item in result["ip_intelligence"]] == ["8.8.8.8"]
    assert result["ip_intelligence"][0]["asn"] == "AS64500"
    assert result["domain_intelligence"][0]["registrar"] == "Example Registrar"
