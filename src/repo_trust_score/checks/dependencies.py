from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

import requests

from .base import BaseCheck, CheckResult, Finding

OSV_BATCH = "https://api.osv.dev/v1/querybatch"


class DependencyCheck(BaseCheck):
    name = "dependencies"
    weight = 25

    def run(self, repo_path: Path, repo_url=None) -> CheckResult:
        result = CheckResult(name=self.name, weight=self.weight)
        deps = self._collect_deps(repo_path)

        if not deps:
            result.findings.append(Finding(
                check=self.name, severity="info",
                message="No dependency manifests found (requirements.txt / pyproject.toml / package.json).",
            ))
            return result

        unpinned = [d for d in deps if d["version"] is None]
        if unpinned:
            pct = len(unpinned) * 100 // len(deps)
            result.findings.append(Finding(
                check=self.name, severity="medium",
                message=f"{len(unpinned)}/{len(deps)} ({pct}%) dependencies unpinned - supply-chain risk.",
                evidence=", ".join(d["name"] for d in unpinned[:5]),
                penalty=min(10, len(unpinned)),
            ))

        for v in self._query_osv(deps):
            result.findings.append(Finding(
                check=self.name, severity=v["severity"],
                message=f"{v['pkg']}: {v['summary']} [{v['id']}]",
                evidence=v["id"],
                penalty=v["penalty"],
            ))
        return result

    def _collect_deps(self, repo_path: Path) -> list[dict]:
        deps: list[dict] = []
        req = repo_path / "requirements.txt"
        if req.exists():
            for line in req.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "-")):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:[><=!~]=?\s*([A-Za-z0-9_.\-]+))?", line)
                if m:
                    deps.append({"name": m.group(1), "version": m.group(2) or None, "ecosystem": "PyPI"})

        pyproject = repo_path / "pyproject.toml"
        if pyproject.exists():
            try:
                import tomllib
            except ModuleNotFoundError:
                import tomli as tomllib
            try:
                data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
                for d in data.get("project", {}).get("dependencies", []):
                    m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:[><=!~]=?\s*([A-Za-z0-9_.\-]+))?", d)
                    if m:
                        deps.append({"name": m.group(1), "version": m.group(2) or None, "ecosystem": "PyPI"})
            except Exception:
                pass

        pkg = repo_path / "package.json"
        if pkg.exists():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8"))
                merged = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for n, v in merged.items():
                    clean = v.lstrip("^~>= ")
                    deps.append({"name": n, "version": clean or None, "ecosystem": "npm"})
            except Exception:
                pass

        return deps

    @staticmethod
    def _severity(vuln: dict) -> str:
        ds = vuln.get("database_specific") or {}
        return "high" if ds.get("severity") in ("HIGH", "CRITICAL") else "medium"

    @staticmethod
    def _summary(vuln: dict) -> str:
        text = (
            vuln.get("summary")
            or (vuln.get("details") or "").splitlines()[0]
            or "see advisory"
        )
        return text.strip()[:90]

    def _query_osv(self, deps: list[dict]) -> list[dict]:
        to_check = [d for d in deps if d["version"]][:40]
        if not to_check:
            return []

        try:
            payload = {"queries": [
                {"package": {"name": d["name"], "ecosystem": d["ecosystem"]}, "version": d["version"]}
                for d in to_check
            ]}
            r = requests.post(OSV_BATCH, json=payload, timeout=15)
            if r.status_code != 200:
                return []

            per_pkg: dict[str, list[dict]] = defaultdict(list)
            for dep, res in zip(to_check, r.json().get("results", [])):
                for v in (res.get("vulns") or []):
                    key = f"{dep['name']}@{dep['version']}"
                    per_pkg[key].append({
                        "id": v["id"],
                        "severity": self._severity(v),
                        "summary": self._summary(v),
                    })

            findings: list[dict] = []
            for key, items in list(per_pkg.items())[:6]:
                worst = "high" if any(i["severity"] == "high" for i in items) else "medium"
                ids = ", ".join(i["id"] for i in items[:3])
                if len(items) > 3:
                    ids += f" (+{len(items) - 3} more)"
                findings.append({
                    "pkg": key,
                    "id": ids,
                    "summary": items[0]["summary"],
                    "severity": worst,
                    "penalty": 8 if worst == "high" else min(6, 2 + len(items)),
                })
            return findings
        except Exception:
            return []
