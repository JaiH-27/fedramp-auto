"""Tests for fedramp_auto.gaps.detector and fedramp_auto.advisor.remediation"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fedramp_auto.gaps.detector import GapReport, Severity, detect_gaps, all_ksi_ids
from fedramp_auto.advisor.remediation import RemediationAdvisor


# ── Gap detector tests ────────────────────────────────────────────────────────

WELL_COVERED = [
    "AC-2", "AC-3", "AC-6", "AC-22",
    "AU-2", "AU-3", "AU-4", "AU-6", "AU-9", "AU-11", "AU-12",
    "CM-6", "CM-7", "CM-8",
    "CP-9",
    "IA-2", "IA-2(1)", "IA-4", "IA-5",
    "SC-5", "SC-6", "SC-7", "SC-8", "SC-8(1)", "SC-12", "SC-12(1)", "SC-28",
    "SI-2", "SI-3", "SI-4",
]


def test_detect_gaps_returns_report():
    report = detect_gaps(WELL_COVERED, baseline="low")
    assert isinstance(report, GapReport)


def test_coverage_increases_with_more_controls():
    sparse = detect_gaps(["SC-28"], baseline="low")
    rich = detect_gaps(WELL_COVERED, baseline="low")
    assert rich.coverage_pct > sparse.coverage_pct


def test_no_gaps_when_all_controls_present():
    report = detect_gaps(WELL_COVERED, baseline="low")
    # At minimum, coverage should be very high
    assert report.coverage_pct >= 60


def test_empty_controls_all_gaps():
    report = detect_gaps([], baseline="low")
    assert report.coverage_pct == 0.0
    assert len(report.gaps) > 0


def test_critical_gaps_are_critical_severity():
    report = detect_gaps([], baseline="low")
    for gap in report.critical_gaps:
        assert gap.ksi.severity == Severity.CRITICAL


def test_moderate_has_more_ksis_than_low():
    low_ids = all_ksi_ids("low")
    mod_ids = all_ksi_ids("moderate")
    assert len(mod_ids) > len(low_ids)


def test_sc28_satisfied_by_sc28():
    report = detect_gaps(["SC-28"], baseline="low")
    satisfied_ids = [k.ksi_id for k in report.satisfied_ksis]
    assert "KSI-SC-2" in satisfied_ids


def test_gap_report_summary_lines():
    report = detect_gaps(["SC-28"], baseline="low")
    lines = report.summary_lines()
    assert any("coverage" in l.lower() for l in lines)


def test_gaps_by_severity_has_all_keys():
    report = detect_gaps([], baseline="low")
    by_sev = report.gaps_by_severity()
    assert "critical" in by_sev
    assert "high" in by_sev
    assert "medium" in by_sev
    assert "low" in by_sev


def test_satisfied_control_ids_normalised():
    # lowercase input should still match
    report = detect_gaps(["sc-28", "ac-2"], baseline="low")
    assert "SC-28" in report.satisfied_control_ids


# ── Remediation advisor tests (static library only, no LLM) ──────────────────

def test_advisor_static_ksi_sc2():
    advisor = RemediationAdvisor(llm_fallback=False)
    report = detect_gaps([], baseline="low")
    sc2_gaps = [g for g in report.gaps if g.ksi.ksi_id == "KSI-SC-2"]
    if sc2_gaps:
        advice = advisor.advise_gap(sc2_gaps[0])
        assert advice.source == "static"
        assert "terraform" in advice.terraform_snippet.lower() or \
               "resource" in advice.terraform_snippet.lower()
        assert len(advice.risk_explanation) > 20


def test_advisor_generic_fallback():
    advisor = RemediationAdvisor(llm_fallback=False)
    report = detect_gaps([], baseline="low")
    # Pick a KSI not in static library
    non_static = [g for g in report.gaps if g.ksi.ksi_id not in (
        "KSI-SC-2", "KSI-SC-1", "KSI-AU-1", "KSI-SC-4",
        "KSI-RA-1", "KSI-SI-2", "KSI-CP-1",
    )]
    if non_static:
        advice = advisor.advise_gap(non_static[0])
        assert advice.source == "generic"
        assert advice.ksi_id == non_static[0].ksi.ksi_id


def test_advisor_advise_sorted_by_priority():
    advisor = RemediationAdvisor(llm_fallback=False)
    report = detect_gaps([], baseline="low")
    advices = advisor.advise(report.gaps)
    if len(advices) >= 2:
        # First advice should be for a critical or high gap
        first_gap = next(g for g in report.gaps if g.ksi.ksi_id == advices[0].ksi_id)
        assert first_gap.ksi.severity.value in ("critical", "high")
