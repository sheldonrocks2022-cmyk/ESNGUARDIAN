"""Guardian Intelligence V10: deterministic, explainable, dependency-free risk fusion.

Version labels describe the internal scoring pipeline, not a trained ML model.
This module never executes moderation actions; existing protections own enforcement.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ThreatAssessment:
    version: int
    score: int
    confidence: float
    severity: str
    reasons: tuple[str, ...]


def assess_threat(
    *,
    base_score: int,
    burst_count: int = 0,
    category_count: int = 0,
    surface_count: int = 0,
    subject_case_count: int = 0,
    rare_action: bool = False,
    baseline_samples: int = 0,
) -> ThreatAssessment:
    """V3-V10 scoring stages with bounded output and explicit uncertainty.

    V3 burst, V4 cross-category, V5 surface, V6 repeat actor,
    V7 rarity, V8 baseline confidence, V9 risk fusion, V10 explanation.
    Confidence describes evidence volume, not a calibrated probability.
    """
    reasons: list[str] = []
    score = max(0, min(100, int(base_score)))
    if burst_count >= 5:
        score += min(12, (burst_count - 4) * 3)
        reasons.append("rapid event burst")
    if category_count >= 3:
        score += min(12, (category_count - 2) * 6)
        reasons.append("multiple attack categories")
    if surface_count >= 3:
        score += min(10, (surface_count - 2) * 4)
        reasons.append("multiple protected surfaces")
    if subject_case_count >= 5:
        score += min(12, (subject_case_count - 4) * 3)
        reasons.append("repeat subject activity")
    if rare_action and baseline_samples >= 10:
        score += 5
        reasons.append("unusual action relative to baseline")
    score = min(100, score)
    evidence = max(0, burst_count) + max(0, subject_case_count) + max(0, baseline_samples)
    confidence = round(min(0.95, 0.2 + evidence / (evidence + 20) * 0.75), 3)
    if baseline_samples < 10:
        reasons.append("limited baseline evidence")
    severity = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "ELEVATED" if score >= 35 else "WATCH" if score >= 15 else "NORMAL"
    return ThreatAssessment(10, score, confidence, severity, tuple(reasons) or ("no significant anomalies",))
