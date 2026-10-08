from __future__ import annotations

import re
from email.utils import parseaddr


def normalize_subject(value: str | None) -> str:
    return re.sub(r"\s+", " ", re.sub(r"^(re|fw|fwd)\s*:\s*", "", value or "", flags=re.I)).strip().lower()


def address_domains(values: list[str | None] | None) -> set[str]:
    domains: set[str] = set()
    for value in values or []:
        if not value:
            continue
        _, address = parseaddr(value)
        candidate = (address or value).rsplit("@", 1)[-1].strip(" <>.,").lower()
        if "." in candidate and " " not in candidate:
            domains.add(candidate)
    return domains


def message_id_domain(value: str | None) -> set[str]:
    if not value or "@" not in value:
        return set()
    return {value.rsplit("@", 1)[-1].strip(" <>").lower()}
