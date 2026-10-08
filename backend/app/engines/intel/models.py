from __future__ import annotations

from dataclasses import dataclass


@dataclass
class LookupResult:
    status: str
    data: dict
    message: str | None = None

