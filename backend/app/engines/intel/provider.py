from __future__ import annotations

from typing import Protocol

from app.engines.intel.models import LookupResult


class PassiveIntelProvider(Protocol):
    async def lookup_ip(self, ip: str) -> LookupResult: ...

    async def lookup_domain(self, domain: str) -> LookupResult: ...
