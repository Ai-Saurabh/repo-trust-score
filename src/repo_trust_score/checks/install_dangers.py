from __future__ import annotations

import json
import re
from pathlib import Path

from .base import BaseCheck, CheckResult, Finding

DANGER_PATTERNS = [
    (r"curl\s+[^|\n]+\|\s*(?:bash|sh)", "curl-pipe-to-shell"),
    (r"wget\s+[^|\n]+\|\s*(?:bash|sh)", "wget-pipe-to-shell"),
    (r"base64\s+-d[^|\n]*\|\s*(?:bash|sh)", "base64-decode-pipe-to-shell"),
    (r"rm\s+-rf\s+/(?:\s|$)", "rm -rf /"),
    (r"chmod\s+\+x\s+/tmp", "chmod +x on /tmp"),
]


class InstallDangersCheck(BaseCheck):
    name = "install_dangers"
    weight = 25

    def run(self, repo_path: Path, repo_url=None) -> CheckResult:
        result = CheckResult(name=self.name, weight=self.weight)

        for script in list(repo_path.glob("*.sh")) + list(repo_path.glob("scripts/*.sh")):
            text = script.read_text(encoding="utf-8", errors="ignore")
            for pattern, label in DANGER_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    result.findings.append(Finding(
                        check=self.name, severity="critical",
                        message=f"Dangerous pattern in {script.relative_to(repo_path)}: {label}",
                        penalty=10,
                    ))

        pkg = repo_path / "package.json"
        if pkg.exists():
            try:
                scripts = json.loads(pkg.read_text(encoding="utf-8")).get("scripts", {})
                for hook in ("preinstall", "postinstall", "prepare"):
                    if hook in scripts:
                        result.findings.append(Finding(
                            check=self.name, severity="high",
                            message=f"package.json runs '{hook}': {scripts[hook][:60]}",
                            penalty=6,
                        ))
            except Exception:
                pass

        setup = repo_path / "setup.py"
        if setup.exists():
            text = setup.read_text(encoding="utf-8", errors="ignore")
            if "urllib" in text and "exec" in text:
                result.findings.append(Finding(
                    check=self.name, severity="high",
                    message="setup.py downloads + executes code at install time.",
                    penalty=8,
                ))
        return result
