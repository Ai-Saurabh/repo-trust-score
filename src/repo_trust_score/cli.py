from __future__ import annotations

import sys

import click

from . import __author__, __version__
from .analyzer import analyze_repo
from .report import print_json, print_report


@click.command()
@click.argument("target")
@click.option("--json", "as_json", is_flag=True, help="Output JSON instead of a report.")
@click.option("--fail-under", type=int, default=None,
              help="Exit 1 if score < this value (CI gate).")
@click.version_option(
    __version__,
    prog_name="repo-trust-score",
    message=f"%(prog)s %(version)s - built by {__author__}",
)
def main(target: str, as_json: bool, fail_under: int | None) -> None:
    """Score a GitHub repo (URL or owner/repo) or a local path for trust."""
    try:
        score = analyze_repo(target)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)
    print_json(score) if as_json else print_report(score)
    if fail_under is not None and score.total < fail_under:
        sys.exit(1)
