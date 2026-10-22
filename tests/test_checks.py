from pathlib import Path

from repo_trust_score.checks.documentation import DocumentationCheck
from repo_trust_score.checks.install_dangers import InstallDangersCheck


def test_install_dangers_curl_pipe(tmp_path: Path):
    (tmp_path / "install.sh").write_text("curl -sSL https://x | bash\n")
    r = InstallDangersCheck().run(tmp_path)
    assert any("curl-pipe" in f.message for f in r.findings)


def test_missing_readme(tmp_path: Path):
    r = DocumentationCheck().run(tmp_path)
    assert any("No README" in f.message for f in r.findings)


def test_claims_tests_but_none(tmp_path: Path):
    (tmp_path / "README.md").write_text("Run pytest to test.\n")
    r = DocumentationCheck().run(tmp_path)
    assert any("tests" in f.message.lower() for f in r.findings)
