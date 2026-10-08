from app.engines.origin import resolve_probable_origin


def _infra(items):
    return {
        "enabled": True,
        "provider": "test-provider",
        "ip_intelligence": items,
        "domain_intelligence": [],
    }


def test_no_public_ip_is_unavailable():
    result = resolve_probable_origin(
        _infra(
            [
                {"ip": "192.168.1.2", "status": "available"},
                {"ip": "203.0.113.9", "status": "available"},
            ]
        ),
        {"ips": [{"ip": "192.168.1.2", "scope": "private"}]},
    )
    assert result["available"] is False
    assert result["source_ip"] is None


def test_one_public_ip_with_metadata_is_probable_origin():
    result = resolve_probable_origin(
        _infra(
            [
                {
                    "ip": "8.8.8.8",
                    "status": "available",
                    "country": "United States",
                    "country_code": "US",
                    "region": "California",
                    "city": "Mountain View",
                    "latitude": 37.4056,
                    "longitude": -122.0775,
                    "asn": "AS15169",
                    "organization": "Google",
                    "isp": "Google LLC",
                }
            ]
        ),
        {"ips": [{"ip": "8.8.8.8", "scope": "public"}]},
    )
    assert result["available"] is True
    assert result["confidence"] == "HIGH"
    assert result["source_ip"] == "8.8.8.8"
    assert result["country_code"] == "US"


def test_multiple_public_ips_choose_candidate_with_stronger_metadata():
    result = resolve_probable_origin(
        _infra(
            [
                {
                    "ip": "198.51.100.10",
                    "status": "available",
                    "country": "Exampleland",
                },
                {
                    "ip": "8.8.8.8",
                    "status": "available",
                    "country": "United States",
                    "country_code": "US",
                    "asn": "AS15169",
                    "organization": "Google",
                },
            ]
        ),
        {
            "ips": [
                {"ip": "198.51.100.10", "scope": "public"},
                {"ip": "8.8.8.8", "scope": "public"},
            ]
        },
    )
    assert result["source_ip"] == "8.8.8.8"
    assert result["confidence"] == "HIGH"


def test_missing_or_malformed_provider_data_does_not_crash():
    assert resolve_probable_origin({}, {})["available"] is False
    assert resolve_probable_origin({"ip_intelligence": [None]}, {})["available"] is False
