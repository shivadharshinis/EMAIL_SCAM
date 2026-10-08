from __future__ import annotations

import re


def prepare_email_text(subject: str | None, body: str | None) -> str:
    """Create stable model input while retaining useful phishing language."""
    combined = f"{subject or ''}\n{body or ''}".lower()
    return re.sub(r"\s+", " ", combined).strip()
