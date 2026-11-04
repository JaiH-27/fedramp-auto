"""End-to-end tests for `fedramp-auto pr-comment` using real scans of the fixtures"""

import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from typer.testing import CliRunner

from fedramp_auto.cli.main import app

FIXTURES = Path(__file__).parent / "fixtures"


def _scan(infra: Path, out: Path) -> Path:
    result = CliRunner().invoke(app, ["scan", str(infra), "--no-llm", "-o", str(out)])
    assert result.exit_code in (0, 2), result.output
    return out / "scan_result.json"


@pytest.fixture(scope="module")
def scans(tmp_path_factory):
    """Base = CDK app without CloudTrail and GuardDuty; head = the full CDK fixture.

    Dropping them opens KSI-AU-4 (high, AU-6 only comes from the trail) and
    KSI-SI-1 (critical, SI-3 only comes from GuardDuty).
    """
    root = tmp_path_factory.mktemp("pr")
    base_infra = root / "base-infra"
    shutil.copytree(FIXTURES / "cdk", base_infra)
    template = base_infra / "cdk.out" / "AuditStack.template.json"
    doc = json.loads(template.read_text())
    del doc["Resources"]["Trail022F0CF2"]
    del doc["Resources"]["Detector"]
    template.write_text(json.dumps(doc))
    return {
        "base": _scan(base_infra, root / "base-out"),
        "head": _scan(FIXTURES / "cdk", root / "head-out"),
        "root": root,
    }


def _run(*args):
    return CliRunner().invoke(app, ["pr-comment", *map(str, args)])


def test_head_closes_gaps_and_passes(scans, tmp_path):
    out, summary = tmp_path / "c.md", tmp_path / "s.json"
    result = _run(scans["head"], "--base", scans["base"], "-o", out, "--summary-json", summary)
    assert result.exit_code == 0, result.output
    body = out.read_text(encoding="utf-8")
    assert body.startswith("<!-- fedramp-auto:pr-comment:default -->")
    assert "#### Resolved gaps (2)" in body
    assert "`KSI-SI-1`" in body and "`KSI-AU-4`" in body
    data = json.loads(summary.read_text())
    assert data["resolved_gaps"] == 2 and data["new_gaps"] == 0 and data["failed"] is False
    assert data["coverage_delta"] > 0


def test_reverse_direction_fails_on_new_critical(scans, tmp_path):
    out = tmp_path / "c.md"
    result = _run(scans["base"], "--base", scans["head"], "-o", out)
    assert result.exit_code == 2
    body = out.read_text(encoding="utf-8")
    assert "❌ **Failing:** this change opens 1 critical gap(s)" in body
    assert "#### New gaps (2)" in body


def test_never_policy_exits_zero(scans, tmp_path):
    result = _run(scans["base"], "--base", scans["head"], "-o", tmp_path / "c.md",
                  "--fail-on", "never")
    assert result.exit_code == 0, result.output


def test_missing_base_compares_against_nothing(scans, tmp_path):
    out = tmp_path / "c.md"
    result = _run(scans["head"], "--base", tmp_path / "absent.json", "-o", out,
                  "--fail-on", "never", "--comment-id", "cdk")
    assert result.exit_code == 0, result.output
    body = out.read_text(encoding="utf-8")
    assert body.startswith("<!-- fedramp-auto:pr-comment:cdk -->")
    assert "no base branch scan to compare against" in body


def test_rejects_bad_policy(scans, tmp_path):
    result = _run(scans["head"], "-o", tmp_path / "c.md", "--fail-on", "sometimes")
    assert result.exit_code == 1
