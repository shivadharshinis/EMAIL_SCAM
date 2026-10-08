from dataclasses import dataclass


@dataclass
class StoredAnalysis:
    analysis_id: str
    data: dict
