"""Tests for fedramp_auto.ci.pr_diff (head vs base scan comparison)"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from fedramp_auto.ci.pr_diff import compare, load_result, should_fail


def _gap(ksi_id: str, severity: str = "high") -> dict:
    return {"ksi_id": ksi_id, "title": ksi_id, "severity": severity, "missing_controls": ["X-1"]}


def _result(coverage: float, *gaps: dict) -> dict:
    return {"baseline": "low", "cloud": "aws", "coverage_pct": coverage,
            "total_ksi_count": 29, "gaps": list(gaps), "remediations": []}


BASE = _result(50.0, _gap("KSI-AU-1", "critical"), _gap("KSI-SC-1", "critical"), _gap("KSI-CM-4"))
HEAD = _result(55.2, _gap("KSI-SC-1", "critical"), _gap("KSI-CM-4"),
               _gap("KSI-RA-1", "critical"), _gap("KSI-AC-4", "medium"))


def test_new_resolved_and_unchanged():
    diff = compare(HEAD, BASE)
    assert [g["ksi_id"] for g in diff.new_gaps] == ["KSI-RA-1", "KSI-AC-4"]
    assert [g["ksi_id"] for g in diff.resolved_gaps] == ["KSI-AU-1"]
    assert [g["ksi_id"] for g in diff.unchanged_gaps] == ["KSI-SC-1", "KSI-CM-4"]


def test_open_gaps_sorted_by_severity_then_id():
    ids = [g["ksi_id"] for g in compare(HEAD, BASE).open_gaps]
    assert ids == ["KSI-RA-1", "KSI-SC-1", "KSI-CM-4", "KSI-AC-4"]


def test_coverage_delta():
    diff = compare(HEAD, BASE)
    assert diff.coverage_base == 50.0 and diff.coverage_head == 55.2
    assert diff.coverage_delta == 5.2


def test_no_base_treats_every_gap_as_new():
    diff = compare(HEAD, None)
    assert not diff.has_base
    assert len(diff.new_gaps) == 4 and diff.resolved_gaps == []
    assert diff.coverage_delta is None


@pytest.mark.parametrize(
    ("policy", "base", "expected"),
    [
        ("new-critical", BASE, True),       # KSI-RA-1 is a new critical gap
        ("any-critical", BASE, True),
        ("never", BASE, False),
        ("new-critical", None, True),       # no base: every gap is new
    ],
)
def test_should_fail(policy, base, expected):
    assert should_fail(compare(HEAD, base), policy) is expected


def test_pre_existing_critical_gap_does_not_fail_new_critical():
    head = _result(52.0, _gap("KSI-SC-1", "critical"))
    diff = compare(head, BASE)
    assert not should_fail(diff, "new-critical")
    assert should_fail(diff, "any-critical")


def test_unknown_policy_rejected():
    with pytest.raises(ValueError):
        should_fail(compare(HEAD, BASE), "sometimes")  # type: ignore[arg-type]


def test_summary_is_json_serialisable():
    summary = compare(HEAD, BASE).summary("new-critical")
    assert json.loads(json.dumps(summary)) == summary
    assert summary["new_critical_gaps"] == 1 and summary["resolved_gaps"] == 1
    assert summary["failed"] is True


def test_load_result_missing_file_is_no_base(tmp_path):
    assert load_result(None) is None
    assert load_result(tmp_path / "nope.json") is None
    path = tmp_path / "r.json"
    path.write_text(json.dumps(BASE))
    assert load_result(path) == BASE
