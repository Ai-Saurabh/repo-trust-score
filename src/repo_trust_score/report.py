from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __author__, __version__
from .scoring import Score

console = Console()
_SEV = {
    "info": "blue",
    "low": "cyan",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
}
_GRADE = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red"}


def _fmt_penalty(penalty: int) -> str:
    return f"-{penalty}" if penalty else "0"


def print_report(score: Score) -> None:
    color = _GRADE[score.grade[0]]
    console.print(Panel.fit(
        f"[bold {color}]Trust Score: {score.total}/100[/bold {color}]\nGrade: {score.grade}",
        title="Repo Trust Score",
    ))
    table = Table(title="Check breakdown")
    table.add_column("Check")
    table.add_column("Penalty", justify="right")
    for name, penalty in score.breakdown.items():
        table.add_row(name, _fmt_penalty(penalty))
    console.print(table)
    for r in score.results:
        if r.findings:
            console.print(f"\n[bold]{r.name}[/bold]")
            for f in r.findings:
                c = _SEV[f.severity]
                console.print(f"  [{c}][{f.severity}][/{c}] {f.message}")
                if f.evidence:
                    console.print(f"      [dim]{f.evidence}[/dim]")
    console.print(
        f"\n[dim]repo-trust-score v{__version__}  |  built by {__author__}[/dim]"
    )


def print_json(score: Score) -> None:
    print(json.dumps({
        "tool": "repo-trust-score",
        "version": __version__,
        "author": __author__,
        "total": score.total,
        "grade": score.grade,
        "breakdown": score.breakdown,
        "findings": [
            {
                "check": f.check,
                "severity": f.severity,
                "message": f.message,
                "evidence": f.evidence,
                "penalty": f.penalty,
            }
            for r in score.results for f in r.findings
        ],
    }, indent=2))
