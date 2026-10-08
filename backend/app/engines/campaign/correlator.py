from __future__ import annotations

from difflib import SequenceMatcher

from app.engines.campaign.models import AnalysisRecord


def correlate(current: AnalysisRecord, history: list[AnalysisRecord]) -> dict:
    best_score = 0
    best_signals: list[str] = []
    matches = 0
    for previous in history:
        score, signals = _compare(current, previous)
        if score >= 20:
            matches += 1
        if score > best_score:
            best_score, best_signals = score, signals
    if not matches:
        return {
            "available": True, "matched": False, "confidence": "LOW",
            "related_analysis_count": 0, "similarity_score": 0, "signals": [],
        }
    confidence = "HIGH" if best_score >= 70 else "MEDIUM" if best_score >= 40 else "LOW"
    return {
        "available": True, "matched": True, "confidence": confidence,
        "related_analysis_count": matches, "similarity_score": best_score,
        "signals": best_signals,
    }


def _compare(a: AnalysisRecord, b: AnalysisRecord) -> tuple[int, list[str]]:
    signals: list[str] = []
    points = 0
    if a.sender_domains & b.sender_domains:
        points += 30; signals.append("Same sender domain")
    if a.reply_to_domains & b.reply_to_domains:
        points += 25; signals.append("Same Reply-To domain")
    if a.return_path_domains & b.return_path_domains:
        points += 25; signals.append("Same Return-Path domain")
    if a.public_ips & b.public_ips:
        points += 25; signals.append("Same public IP")
    if a.url_domains & b.url_domains:
        points += 25; signals.append("Same URL domain")
    if a.subject and b.subject and SequenceMatcher(None, a.subject, b.subject).ratio() >= 0.8:
        points += 15; signals.append("Similar subject")
    return min(points, 100), signals

