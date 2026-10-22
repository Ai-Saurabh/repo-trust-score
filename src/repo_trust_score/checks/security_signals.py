from __future__ import annotations

import re
from pathlib import Path

import requests

from .base import BaseCheck, CheckResult, Finding


class SecuritySignalsCheck(BaseCheck):
    name = "security_signals"
    weight = 10

    def run(self, repo_path: Path, repo_url=None) -> CheckResult:
        result = CheckResult(name=self.name, weight=self.weight)

        has_ci = (repo_path / ".github" / "workflows").exists() or (repo_path / ".gitlab-ci.yml").exists()
        if not has_ci:
            result.findings.append(Finding(
                check=self.name, severity="low",
                message="No CI workflow - code is not automatically tested on changes.",
                penalty=3,
            ))

        if not any((repo_path / f).exists() for f in ("SECURITY.md", ".github/SECURITY.md")):
            result.findings.append(Finding(
                check=self.name, severity="low",
                message="No SECURITY.md or disclosure policy.",
                penalty=2,
            ))

        if not any((repo_path / f).exists() for f in ("LICENSE", "LICENSE.md", "COPYING")):
            result.findings.append(Finding(
                check=self.name, severity="medium",
                message="No LICENSE file - legal reuse unclear.",
                penalty=5,
            ))

        if repo_url:
            self._gh_api(repo_url, result)
        return result

    @staticmethod
    def _gh_api(repo_url: str, result: CheckResult) -> None:
        m = re.search(r"github\.com[/:]([^/]+)/([^/.]+)", repo_url)
        if not m:
            return
        try:
            r = requests.get(
                f"https://api.github.com/repos/{m.group(1)}/{m.group(2)}", timeout=8
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("archived"):
                    result.findings.append(Finding(
                        check=result.name, severity="medium",
                        message="Repository is archived (unmaintained).", penalty=5,
                    ))
        except Exception:
            pass
