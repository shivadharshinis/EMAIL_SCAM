from __future__ import annotations

from uuid import uuid4

from app.engines.report.models import StoredAnalysis

_ANALYSES: dict[str, StoredAnalysis] = {}


def store_analysis(data: dict) -> str:
    analysis_id = uuid4().hex
    data["analysis_id"] = analysis_id
    _ANALYSES[analysis_id] = StoredAnalysis(analysis_id, data)
    return analysis_id


def get_analysis(analysis_id: str) -> dict | None:
    item = _ANALYSES.get(analysis_id)
    return item.data if item else None


def list_analyses() -> list[dict]:
    return [item.data for item in reversed(_ANALYSES.values())]


def clear_analyses() -> None:
    _ANALYSES.clear()
