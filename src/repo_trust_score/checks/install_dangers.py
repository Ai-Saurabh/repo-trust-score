from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from .base import BaseCheck, CheckResult, Finding

logger = logging.getLogger(__name__)

DANGER_PATTERNS = [
    (r"curl\s+[^|\n]+\|\s*(?:bash|sh)", "curl-pipe-to-shell"),
    (r"wget\s+[^|\n]+\|\s*(?:bash|sh)", "wget-pipe-to-shell"),
    (
        r"base64\s+-d[^|\n]*\|\s*(?:bash|sh)",
        "base64-decode-pipe-to-shell",
    ),
    (r"rm\s+-rf\s+/(?:\s|$)", "rm -rf /"),
    (r"chmod\s+\+x\s+/tmp", "chmod +x on /tmp"),
]


class InstallDangersCheck(BaseCheck):
    name = "install_dangers"
    weight = 25

    def run(self, repo_path: Path, repo_url=None) -> CheckResult:
        result = CheckResult(
            name=self.name,
            weight=self.weight,
        )

        scripts = (
            list(repo_path.glob("*.sh"))
            + list(repo_path.glob("scripts/*.sh"))
        )

        for script in scripts:
            text = script.read_text(
                encoding="utf-8",
                errors="ignore",
            )

            for pattern, label in DANGER_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    result.findings.append(
                        Finding(
                            check=self.name,
                            severity="critical",
                            message=(
                                f"Dangerous pattern in "
                                f"{script.relative_to(repo_path)}: {label}"
                            ),
                            penalty=10,
                        )
                    )

        package_json = repo_path / "package.json"

        if package_json.exists():
            try:
                content = package_json.read_text(encoding="utf-8")
                data = json.loads(content)
                scripts_data = data.get("scripts", {})

                for hook in ("preinstall", "postinstall", "prepare"):
                    if hook in scripts_data:
                        result.findings.append(
                            Finding(
                                check=self.name,
                                severity="high",
                                message=(
                                    f"package.json runs '{hook}': "
                                    f"{scripts_data[hook][:60]}"
                                ),
                                penalty=6,
                            )
                        )

            except (
                OSError,
                ValueError,
                TypeError,
                AttributeError,
            ) as exc:
                logger.warning(
                    "Could not inspect package.json: %s",
                    exc,
                )

        setup_file = repo_path / "setup.py"

        if setup_file.exists():
            text = setup_file.read_text(
                encoding="utf-8",
                errors="ignore",
            )

            if "urllib" in text and "exec" in text:
                result.findings.append(
                    Finding(
                        check=self.name,
                        severity="high",
                        message=(
                            "setup.py downloads + executes code "
                            "at install time."
                        ),
                        penalty=8,
                    )
                )

        return result
