from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Finding:
    check: str
    severity: str  # info | low | medium | high | critical
    message: str
    evidence: str = ""
    penalty: int = 0


@dataclass
class CheckResult:
    name: str
    weight: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def penalty(self) -> int:
        return min(self.weight, sum(f.penalty for f in self.findings))


class BaseCheck(ABC):
    name: str = "base"
    weight: int = 10

    @abstractmethod
    def run(self, repo_path: Path, repo_url: str | None = None) -> CheckResult: ...
