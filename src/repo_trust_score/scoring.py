from __future__ import annotations

from dataclasses import dataclass

from .checks.base import CheckResult


@dataclass
class Score:
    total: int
    grade: str
    breakdown: dict[str, int]
    results: list[CheckResult]


def grade_for(score: int) -> str:
    if score >= 90:
        return "A - Trustworthy"
    if score >= 75:
        return "B - Mostly safe, review findings"
    if score >= 60:
        return "C - Review required"
    if score >= 40:
        return "D - High risk"
    return "F - Do not run without a full audit"


def compute_score(results: list[CheckResult]) -> Score:
    max_total = sum(r.weight for r in results) or 1
    penalty = sum(r.penalty for r in results)
    normalized = max(0, int((max_total - penalty) * 100 / max_total))
    return Score(
        total=normalized,
        grade=grade_for(normalized),
        breakdown={r.name: r.penalty for r in results},
        results=results,
    )
