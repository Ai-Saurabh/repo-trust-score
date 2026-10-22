from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from pathlib import Path

import requests

from .base import BaseCheck, CheckResult, Finding

OSV_BATCH = "https://api.osv.dev/v1/querybatch"

logger = logging.getLogger(__name__)


class DependencyCheck(BaseCheck):
    name = "dependencies"
    weight = 25

    def run(self, repo_path: Path, repo_url=None) -> CheckResult:
        result = CheckResult(
            name=self.name,
            weight=self.weight,
        )

        deps = self._collect_deps(repo_path)

        if not deps:
            result.findings.append(
                Finding(
                    check=self.name,
                    severity="info",
                    message=(
                        "No dependency manifests found "
                        "(requirements.txt / pyproject.toml / package.json)."
                    ),
                )
            )
            return result

        unpinned = [
            dependency
            for dependency in deps
            if dependency["version"] is None
        ]

        if unpinned:
            percentage = len(unpinned) * 100 // len(deps)

            result.findings.append(
                Finding(
                    check=self.name,
                    severity="medium",
                    message=(
                        f"{len(unpinned)}/{len(deps)} "
                        f"({percentage}%) dependencies unpinned "
                        "- supply-chain risk."
                    ),
                    evidence=", ".join(
                        dependency["name"]
                        for dependency in unpinned[:5]
                    ),
                    penalty=min(10, len(unpinned)),
                )
            )

        for vulnerability in self._query_osv(deps):
            result.findings.append(
                Finding(
                    check=self.name,
                    severity=vulnerability["severity"],
                    message=(
                        f"{vulnerability['pkg']}: "
                        f"{vulnerability['summary']} "
                        f"[{vulnerability['id']}]"
                    ),
                    evidence=vulnerability["id"],
                    penalty=vulnerability["penalty"],
                )
            )

        return result

    def _collect_deps(self, repo_path: Path) -> list[dict]:
        deps: list[dict] = []

        requirements_file = repo_path / "requirements.txt"

        if requirements_file.exists():
            for line in requirements_file.read_text(
                encoding="utf-8",
                errors="ignore",
            ).splitlines():
                line = line.strip()

                if not line or line.startswith(("#", "-")):
                    continue

                match = re.match(
                    r"^([A-Za-z0-9_.\-]+)\s*"
                    r"(?:[><=!~]=?\s*([A-Za-z0-9_.\-]+))?",
                    line,
                )

                if match:
                    deps.append(
                        {
                            "name": match.group(1),
                            "version": match.group(2) or None,
                            "ecosystem": "PyPI",
                        }
                    )

        pyproject = repo_path / "pyproject.toml"

        if pyproject.exists():
            try:
                import tomllib
            except ModuleNotFoundError:
                import tomli as tomllib

            try:
                content = pyproject.read_text(encoding="utf-8")
                data = tomllib.loads(content)

                dependencies = (
                    data.get("project", {}).get("dependencies", [])
                )

                for dependency in dependencies:
                    match = re.match(
                        r"^([A-Za-z0-9_.\-]+)\s*"
                        r"(?:[><=!~]=?\s*([A-Za-z0-9_.\-]+))?",
                        dependency,
                    )

                    if match:
                        deps.append(
                            {
                                "name": match.group(1),
                                "version": match.group(2) or None,
                                "ecosystem": "PyPI",
                            }
                        )

            except (
                OSError,
                ValueError,
                TypeError,
                AttributeError,
            ) as exc:
                logger.warning(
                    "Could not parse pyproject.toml: %s",
                    exc,
                )

        package_json = repo_path / "package.json"

        if package_json.exists():
            try:
                content = package_json.read_text(encoding="utf-8")
                data = json.loads(content)

                merged = {
                    **data.get("dependencies", {}),
                    **data.get("devDependencies", {}),
                }

                for name, version in merged.items():
                    clean_version = version.lstrip("^~>= ")

                    deps.append(
                        {
                            "name": name,
                            "version": clean_version or None,
                            "ecosystem": "npm",
                        }
                    )

            except (
                OSError,
                ValueError,
                TypeError,
                AttributeError,
            ) as exc:
                logger.warning(
                    "Could not parse package.json: %s",
                    exc,
                )

        return deps

    @staticmethod
    def _severity(vulnerability: dict) -> str:
        database_specific = (
            vulnerability.get("database_specific") or {}
        )

        if database_specific.get("severity") in ("HIGH", "CRITICAL"):
            return "high"

        return "medium"

    @staticmethod
    def _summary(vulnerability: dict) -> str:
        summary = (
            vulnerability.get("summary")
            or (vulnerability.get("details") or "").splitlines()[0]
            or "see advisory"
        )

        return summary.strip()[:90]

    def _query_osv(self, deps: list[dict]) -> list[dict]:
        to_check = [
            dependency
            for dependency in deps
            if dependency["version"]
        ][:40]

        if not to_check:
            return []

        try:
            payload = {
                "queries": [
                    {
                        "package": {
                            "name": dependency["name"],
                            "ecosystem": dependency["ecosystem"],
                        },
                        "version": dependency["version"],
                    }
                    for dependency in to_check
                ]
            }

            response = requests.post(
                OSV_BATCH,
                json=payload,
                timeout=15,
            )

            if response.status_code != 200:
                return []

            results = response.json().get("results", [])
            per_package: dict[str, list[dict]] = defaultdict(list)

            for dependency, result in zip(to_check, results):
                for vulnerability in result.get("vulns") or []:
                    key = (
                        f"{dependency['name']}@"
                        f"{dependency['version']}"
                    )

                    per_package[key].append(
                        {
                            "id": vulnerability["id"],
                            "severity": self._severity(vulnerability),
                            "summary": self._summary(vulnerability),
                        }
                    )

            findings: list[dict] = []

            for package, items in list(per_package.items())[:6]:
                worst_severity = (
                    "high"
                    if any(
                        item["severity"] == "high"
                        for item in items
                    )
                    else "medium"
                )

                identifiers = ", ".join(
                    item["id"] for item in items[:3]
                )

                if len(items) > 3:
                    identifiers += f" (+{len(items) - 3} more)"

                findings.append(
                    {
                        "pkg": package,
                        "id": identifiers,
                        "summary": items[0]["summary"],
                        "severity": worst_severity,
                        "penalty": (
                            8
                            if worst_severity == "high"
                            else min(6, 2 + len(items))
                        ),
                    }
                )

            return findings

        except (
            requests.RequestException,
            ValueError,
            KeyError,
            TypeError,
        ) as exc:
            logger.warning(
                "OSV vulnerability lookup failed: %s",
                exc,
            )
            return []
