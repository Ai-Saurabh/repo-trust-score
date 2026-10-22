from repo_trust_score.checks.base import CheckResult, Finding
from repo_trust_score.scoring import compute_score, grade_for


def test_perfect_score():
    results = [CheckResult(name="a", weight=10), CheckResult(name="b", weight=10)]
    assert compute_score(results).total == 100


def test_full_penalty():
    r = CheckResult(name="a", weight=10)
    r.findings.append(Finding(check="a", severity="critical", message="x", penalty=100))
    assert compute_score([r]).total == 0


def test_grade_boundaries():
    assert grade_for(100).startswith("A")
    assert grade_for(89).startswith("B")
    assert grade_for(59).startswith("D")
    assert grade_for(10).startswith("F")
