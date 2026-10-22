from __future__ import annotations

from pathlib import Path

from .base import BaseCheck, CheckResult, Finding


class DocumentationCheck(BaseCheck):
    name = "documentation"
    weight = 15

    def run(self, repo_path: Path, repo_url=None) -> CheckResult:
        result = CheckResult(name=self.name, weight=self.weight)
        readme = self._find_readme(repo_path)

        if not readme:
            result.findings.append(Finding(
                check=self.name, severity="high",
                message="No README found - cannot verify project claims.",
                penalty=15,
            ))
            return result

        text = readme.read_text(encoding="utf-8", errors="ignore").lower()

        claims_tests = any(k in text for k in ("pytest", "run tests", "npm test", "make test"))
        has_tests = any((repo_path / p).exists() for p in ("tests", "test", "__tests__"))
        if claims_tests and not has_tests:
            result.findings.append(Finding(
                check=self.name, severity="medium",
                message="README mentions tests but no tests/ directory exists - claim unverified.",
                penalty=6,
            ))

        claims_lic = "license" in text
        has_lic = any((repo_path / f).exists() for f in ("LICENSE", "LICENSE.md", "COPYING"))
        if claims_lic and not has_lic:
            result.findings.append(Finding(
                check=self.name, severity="medium",
                message="README mentions a license but no LICENSE file exists.",
                penalty=5,
            ))

        if not any(k in text for k in ("install", "pip install", "npm install", "usage")):
            result.findings.append(Finding(
                check=self.name, severity="low",
                message="No install/usage section in README.",
                penalty=3,
            ))
        return result

    @staticmethod
    def _find_readme(repo_path: Path) -> Path | None:
        for n in ("README.md", "README.rst", "README.txt", "README"):
            p = repo_path / n
            if p.exists():
                return p
        return None
