from typing import Literal

from pydantic import BaseModel, Field


LookupStatus = Literal["available", "unavailable", "error", "not_requested"]


class IpIntelligence(BaseModel):
    ip: str
    status: LookupStatus
    asn: str | None = None
    organization: str | None = None
    network: str | None = None
    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    isp: str | None = None
    country: str | None = None
    region: str | None = None
    city: str | None = None
    reverse_dns: str | None = None
    provider: str | None = None
    message: str | None = None


class DomainIntelligence(BaseModel):
    domain: str
    status: LookupStatus
    registrar: str | None = None
    created_at: str | None = None
    expires_at: str | None = None
    nameservers: list[str] = Field(default_factory=list)
    provider: str | None = None
    message: str | None = None


class InfrastructureIntelligence(BaseModel):
    enabled: bool
    provider: str | None = None
    ip_intelligence: list[IpIntelligence] = Field(default_factory=list)
    domain_intelligence: list[DomainIntelligence] = Field(default_factory=list)
    message: str | None = None
