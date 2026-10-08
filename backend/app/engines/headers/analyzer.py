from __future__ import annotations

from email.utils import parsedate_to_datetime

from app.engines.headers.extractors import extract_domains, extract_ips
from app.engines.headers.parser import parse_received_headers
from app.schemas.header_intelligence import HeaderAnomaly


def analyze_headers(parsed_email: dict) -> dict:
    hops = parse_received_headers(parsed_email)
    anomalies: list[HeaderAnomaly] = []
    for hop in hops:
        if not hop.from_host and not hop.by_host and not hop.ips:
            anomalies.append(
                HeaderAnomaly(
                    type="unparseable_received",
                    title="Received header has no recognizable relay data",
                    description="The header was preserved, but no relay host or IP could be parsed.",
                    evidence=hop.raw,
                    confidence=0.99,
                )
            )
        if ";" in hop.raw and hop.timestamp is None:
            anomalies.append(
                HeaderAnomaly(
                    type="invalid_received_timestamp",
                    title="Received timestamp could not be parsed",
                    description="The trailing Received timestamp is not valid RFC-style date text.",
                    evidence=hop.raw,
                    confidence=0.95,
                )
            )
    parsed_dates = [
        (hop.hop, parsedate_to_datetime(hop.timestamp))
        for hop in hops
        if hop.timestamp
    ]
    for (previous_hop, previous), (current_hop, current) in zip(
        parsed_dates, parsed_dates[1:]
    ):
        if previous < current:
            anomalies.append(
                HeaderAnomaly(
                    type="received_timestamp_order",
                    title="Received timestamps are not in observed header order",
                    description="The timestamps do not follow the usual newest-to-oldest display order.",
                    evidence=f"hop {previous_hop}={previous.isoformat()}, hop {current_hop}={current.isoformat()}",
                    confidence=0.9,
                )
            )
    return {
        "received_chain": [hop.model_dump() for hop in hops],
        "ips": [item.model_dump() for item in extract_ips(parsed_email, hops)],
        "domains": [item.model_dump() for item in extract_domains(parsed_email, hops)],
        "anomalies": [item.model_dump() for item in anomalies],
    }
