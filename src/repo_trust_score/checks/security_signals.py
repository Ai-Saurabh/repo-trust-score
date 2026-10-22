from __future__ import annotations

import logging
import re
from pathlib import Path

import requests

from .base import BaseCheck, CheckResult, Finding

logger = logging.getLogger(__name__)


class SecuritySignalsCheck(BaseCheck):
    name = "security_signals"
    weight = 10

    def run(self, repo_path: Path, repo_url=None) -> CheckResult:
        result = CheckResult(
            name=self.name,
            weight=self.weight,
        )

        has_ci = (
            (repo_path / ".github" / "workflows").exists()
            or (repo_path / ".gitlab-ci.yml").exists()
        )

        if not has_ci:
            result.findings.append(
                Finding(
                    check=self.name,
                    severity="low",
                    message=(
                        "No CI workflow - code is not automatically "
                        "tested on changes."
                    ),
                    penalty=3,
                )
            )

        security_files = (
            "SECURITY.md",
            ".github/SECURITY.md",
        )

        if not any(
            (repo_path / filename).exists()
            for filename in security_files
        ):
            result.findings.append(
                Finding(
                    check=self.name,
                    severity="low",
                    message="No SECURITY.md or disclosure policy.",
                    penalty=2,
                )
            )

        license_files = (
            "LICENSE",
            "LICENSE.md",
            "COPYING",
        )

        if not any(
            (repo_path / filename).exists()
            for filename in license_files
        ):
            result.findings.append(
                Finding(
                    check=self.name,
                    severity="medium",
                    message="No LICENSE file - legal reuse unclear.",
                    penalty=5,
                )
            )

        if repo_url:
            self._gh_api(repo_url, result)

        return result

    @staticmethod
    def _gh_api(repo_url: str, result: CheckResult) -> None:
        match = re.search(
            r"github\.com[/:]([^/]+)/([^/.]+)",
            repo_url,
        )

        if not match:
            return

        owner, repository = match.groups()

        try:
            response = requests.get(
                f"https://api.github.com/repos/{owner}/{repository}",
                timeout=8,
            )

            if response.status_code == 200:
                data = response.json()

                if data.get("archived"):
                    result.findings.append(
                        Finding(
                            check=result.name,
                            severity="medium",
                            message=(
                                "Repository is archived (unmaintained)."
                            ),
                            penalty=5,
                        )
                    )

        except (
            requests.RequestException,
            ValueError,
            TypeError,
        ) as exc:
            logger.warning(
                "GitHub API request failed: %s",
                exc,
            )
