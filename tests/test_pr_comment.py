"""Tests for fedramp_auto.ci.pr_comment (PR comment rendering)"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fedramp_auto.ci.pr_comment import marker, render_comment
from fedramp_auto.ci.pr_diff import compare


def _gap(ksi_id: str, severity: str = "high", title: str = "Some title") -> dict:
    return {"ksi_id": ksi_id, "title": title, "severity": severity, "missing_controls": ["RA-5"]}


def _rem(ksi_id: str, code: str = "new ecr.Repository(this, 'R');", lang: str = "typescript"):
    return {"ksi_id": ksi_id, "risk_explanation": "risk", "remediation_action": "Do the thing.",
            "terraform_snippet": code, "snippet_language": lang, "source": "static",
            "cloud": "cdk"}


def _result(coverage, gaps, rems=(), satisfied=20):
    return {"baseline": "low", "cloud": "cdk", "coverage_pct": coverage,
            "satisfied_ksi_count": satisfied, "total_ksi_count": 29,
            "gaps": list(gaps), "remediations": list(rems)}


BASE = _result(65.5, [_gap("KSI-AU-1", "critical"), _gap("KSI-CM-4", "medium")], satisfied=19)
HEAD = _result(
    69.0,
    [_gap("KSI-CM-4", "medium"), _gap("KSI-RA-1", "critical", "Vulnerability scanning")],
    [_rem("KSI-RA-1"), _rem("KSI-CM-4")],
)


def test_starts_with_marker_for_updates():
    body = render_comment(compare(HEAD, BASE), comment_id="infra")
    assert body.splitlines()[0] == marker("infra") == "<!-- fedramp-auto:pr-comment:infra -->"


def test_headline_numbers():
    body = render_comment(compare(HEAD, BASE))
    assert "### FedRAMP-Auto · LOW baseline" in body
    assert "**KSI coverage:** 69.0% (20/29) · **+3.5 pts** vs base (65.5%)" in body
    assert "**Open gaps:** 2 (1 critical) · **New:** 1 · **Resolved:** 1" in body


def test_failing_status_for_new_critical():
    body = render_comment(compare(HEAD, BASE), policy="new-critical")
    assert "❌ **Failing:** this change opens 1 critical gap(s)" in body


def test_passing_status_when_only_resolving():
    head = _result(70.0, [_gap("KSI-CM-4", "medium")])
    body = render_comment(compare(head, BASE))
    assert "✅ This change closes 1 gap(s) and opens none." in body
    assert "#### New gaps" not in body


def test_never_policy_reports_without_failing():
    body = render_comment(compare(HEAD, BASE), policy="never")
    assert "Failing" not in body
    assert "⚠️ This change opens 1 gap(s); none block the merge." in body


def test_sections_and_tables():
    body = render_comment(compare(HEAD, BASE))
    assert "#### New gaps (1)" in body
    assert "| `KSI-RA-1` | Vulnerability scanning | 🔴 critical | RA-5 |" in body
    assert "#### Resolved gaps (1)" in body and "`KSI-AU-1`" in body
    assert "<summary>All open gaps (2)</summary>" in body


def test_fixes_only_for_new_gaps_with_language_fence():
    body = render_comment(compare(HEAD, BASE))
    assert "<summary>Suggested fixes for new gaps (1)</summary>" in body
    assert "```typescript\nnew ecr.Repository(this, 'R');\n```" in body
    assert "**`KSI-CM-4`" not in body   # pre-existing gap: no fix repeated on every PR


def test_no_base_mode():
    body = render_comment(compare(HEAD, None))
    assert "no base branch scan to compare against" in body
    assert "**New:**" not in body
    assert "<summary>Suggested fixes for open gaps (2)</summary>" in body


def test_table_cells_escape_pipes():
    head = _result(60.0, [_gap("KSI-X-1", title="a | b")])
    assert "a \\| b" in render_comment(compare(head, None))


def test_fence_outgrows_backticks_in_snippet():
    code = "```\nnested\n```"
    head = _result(60.0, [_gap("KSI-RA-1")], [_rem("KSI-RA-1", code=code, lang="hcl")])
    assert "````hcl\n```\nnested\n```\n````" in render_comment(compare(head, None))


def test_stays_under_size_limit():
    big = "x" * 5_000
    gaps = [_gap(f"KSI-Z-{i}") for i in range(30)]
    head = _result(10.0, gaps, [_rem(g["ksi_id"], code=big) for g in gaps])
    body = render_comment(compare(head, None), max_chars=20_000)
    assert len(body) <= 20_000
    assert "omitted to fit GitHub's comment size limit" in body
