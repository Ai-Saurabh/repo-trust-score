from __future__ import annotations

import math
from pathlib import Path

from .base import BaseCheck, CheckResult, Finding


class CodeSignalsCheck(BaseCheck):
    name = "code_signals"
    weight = 10

    def run(self, repo_path: Path, repo_url=None) -> CheckResult:
        result = CheckResult(name=self.name, weight=self.weight)

        binaries = []
        for ext in (".exe", ".dll", ".so", ".dylib", ".bin"):
            binaries.extend(repo_path.rglob(f"*{ext}"))
        if binaries:
            result.findings.append(Finding(
                check=self.name, severity="medium",
                message=f"{len(binaries)} binary blob(s) checked in (may hide malicious code).",
                evidence=", ".join(str(b.relative_to(repo_path)) for b in binaries[:3]),
                penalty=min(6, len(binaries)),
            ))

        minified = [p for p in repo_path.rglob("*.min.js") if p.stat().st_size > 100_000]
        if minified:
            result.findings.append(Finding(
                check=self.name, severity="low",
                message=f"{len(minified)} large minified JS file(s) - unreadable code.",
                penalty=min(4, len(minified)),
            ))

        for p in repo_path.rglob("*.py"):
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if len(text.splitlines()) < 5 and len(text) > 5000 and self._entropy(text) > 5.0:
                result.findings.append(Finding(
                    check=self.name, severity="high",
                    message=f"High-entropy obfuscated file: {p.relative_to(repo_path)}",
                    penalty=5,
                ))
        return result

    @staticmethod
    def _entropy(text: str) -> float:
        if not text:
            return 0.0
        freq: dict[str, int] = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        n = len(text)
        return -sum((v / n) * math.log2(v / n) for v in freq.values())
