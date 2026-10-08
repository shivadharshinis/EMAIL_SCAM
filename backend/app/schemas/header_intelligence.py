from typing import Literal

from pydantic import BaseModel, Field


class ReceivedHop(BaseModel):
    hop: int
    raw: str
    from_host: str | None = None
    by_host: str | None = None
    with_protocol: str | None = None
    message_id: str | None = None
    for_address: str | None = None
    timestamp: str | None = None
    hostnames: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)


class ObservedIp(BaseModel):
    ip: str
    version: Literal["ipv4", "ipv6"]
    scope: Literal["public", "private", "reserved", "loopback", "unknown"]
    sources: list[str] = Field(default_factory=list)


class ObservedDomain(BaseModel):
    domain: str
    source: str
    is_punycode: bool = False
    is_ip_literal: bool = False
    subdomain: str | None = None


class HeaderAnomaly(BaseModel):
    type: str
    title: str
    description: str
    evidence: str
    confidence: float = Field(ge=0, le=1)


class HeaderIntelligenceResult(BaseModel):
    received_chain: list[ReceivedHop] = Field(default_factory=list)
    ips: list[ObservedIp] = Field(default_factory=list)
    domains: list[ObservedDomain] = Field(default_factory=list)
    anomalies: list[HeaderAnomaly] = Field(default_factory=list)
