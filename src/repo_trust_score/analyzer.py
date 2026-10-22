from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from .checks import ALL_CHECKS
from .scoring import Score, compute_score


def analyze_repo(target: str) -> Score:
    if target.startswith(("http://", "https://", "git@")):
        repo_path, cleanup, repo_url = _clone(target), True, target
    elif "/" in target and not Path(target).exists():
        repo_url = f"https://github.com/{target}.git"
        repo_path, cleanup = _clone(repo_url), True
    else:
        repo_path, cleanup, repo_url = Path(target).resolve(), False, None

    try:
        results = [c.run(repo_path, repo_url) for c in ALL_CHECKS]
        return compute_score(results)
    finally:
        if cleanup:
            shutil.rmtree(repo_path.parent, ignore_errors=True)


def _clone(url: str) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="rts-"))
    dest = tmp / "repo"
    subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", url, str(dest)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    return dest
