"""The data the dashboard renders, built from real scans of all three fixture formats"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from typer.testing import CliRunner

from fedramp_auto.cli.main import app
from fedramp_auto.dashboard.loader import ScanGroup, load_scans
from fedramp_auto.dashboard.view_model import _shorten_paths, build_scan, build_view_model
from fedramp_auto.gaps.detector import all_ksi_ids

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module", params=["terraform", "arm", "cdk"])
def scan(request, tmp_path_factory):
    out = tmp_path_factory.mktemp(request.param)
    result = CliRunner().invoke(app, ["scan", str(FIXTURES / request.param), "--no-llm",
                                      "-o", str(out)])
    assert result.exit_code in (0, 2), result.output
    (group,) = load_scans(out).groups
    return group.scans[0]


def test_every_ksi_in_the_baseline_appears_once(scan):
    ids = [row["ksi_id"] for row in build_scan(scan)["ksis"]]
    assert sorted(ids) == sorted(all_ksi_ids("low"))


def test_ksi_status_agrees_with_the_scan(scan):
    view = build_scan(scan)
    satisfied = [row for row in view["ksis"] if row["satisfied"]]
    assert len(satisfied) == scan["satisfied_ksi_count"]
    assert view["gap_count"] == len(view["ksis"]) - len(satisfied)


def test_satisfied_ksis_trace_back_to_resources(scan):
    for row in build_scan(scan)["ksis"]:
        if row["satisfied"]:
            found = [r for c in row["controls"] for r in c["resources"]]
            assert found and all(r["identifier"] and r["rationale"] for r in found)


def test_severity_counts_add_up_to_the_gaps(scan):
    view = build_scan(scan)
    assert sum(view["gaps_by_severity"].values()) == view["gap_count"]


def test_remediations_are_ordered_most_severe_first(scan):
    ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    order = [ranks[r["severity"]] for r in build_scan(scan)["remediations"]]
    assert order == sorted(order)


def test_absolute_paths_never_reach_the_page(scan):
    home = str(FIXTURES.parent.parent)
    assert json.dumps(home)[1:-1] not in json.dumps(build_scan(scan))


def test_gap_missing_from_the_catalogue_is_still_shown():
    view = build_scan({
        "generated_at": "2026-11-05T10:00:00+00:00", "target": "t", "baseline": "low",
        "coverage_pct": 0.0,
        "gaps": [{"ksi_id": "KSI-RETIRED-1", "title": "Retired", "severity": "high",
                  "missing_controls": ["XX-1"]}],
    })
    row = next(r for r in view["ksis"] if r["ksi_id"] == "KSI-RETIRED-1")
    assert not row["satisfied"]
    assert row["controls"][0]["id"] == "XX-1"


def test_legacy_remediations_default_to_terraform_for_aws():
    view = build_scan({
        "generated_at": "2026-11-05T10:00:00+00:00", "target": "t", "baseline": "low",
        "coverage_pct": 0.0, "gaps": [],
        "remediations": [{"ksi_id": "KSI-AC-1", "terraform_snippet": "x"}],
    })
    assert view["remediations"][0]["language"] == "hcl"
    assert view["remediations"][0]["cloud"] == "aws"


def test_shorten_paths_handles_windows_and_posix():
    assert _shorten_paths({r"C:\Users\me\infra\a\main.tf", r"C:\Users\me\infra\b\main.tf"}) == {
        r"C:\Users\me\infra\a\main.tf": "a/main.tf",
        r"C:\Users\me\infra\b\main.tf": "b/main.tf",
    }
    assert _shorten_paths({"/home/me/infra/main.tf"}) == {"/home/me/infra/main.tf": "main.tf"}


def test_view_model_is_json_serialisable(scan):
    group = ScanGroup(scan["target"], scan["baseline"], [scan])
    assert json.dumps(build_view_model([group]))
