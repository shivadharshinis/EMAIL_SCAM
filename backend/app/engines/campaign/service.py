from __future__ import annotations

from app.engines.campaign.correlator import correlate
from app.engines.campaign.models import AnalysisRecord

_HISTORY: list[AnalysisRecord] = []


def correlate_and_record(record: AnalysisRecord) -> dict:
    result = correlate(record, list(_HISTORY))
    _HISTORY.append(record)
    return result


def clear_history() -> None:
    _HISTORY.clear()


def history_size() -> int:
    return len(_HISTORY)
