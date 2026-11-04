"""Tests for the AWS CDK (TypeScript) remediation target"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from typer.testing import CliRunner

from fedramp_auto.advisor.remediation import (
    _STATIC_REMEDIATIONS,
    _STATIC_REMEDIATIONS_CDK,
    SNIPPET_LANGUAGE,
    SUPPORTED_CLOUDS,
    RemediationAdvisor,
    _build_remediation_prompt,
)
from fedramp_auto.cli.main import app
from fedramp_auto.gaps.detector import detect_gaps

CDK_FIXTURES = Path(__file__).parent / "fixtures" / "cdk"


def _all_gaps():
    return detect_gaps([], baseline="moderate").gaps


def _gap(ksi_id: str):
    return next(g for g in _all_gaps() if g.ksi.ksi_id == ksi_id)


# ── Target plumbing ───────────────────────────────────────────────────────────

def test_cdk_is_a_supported_target():
    assert "cdk" in SUPPORTED_CLOUDS
    assert SNIPPET_LANGUAGE["cdk"] == "typescript"
    assert SNIPPET_LANGUAGE["aws"] == SNIPPET_LANGUAGE["azure"] == "hcl"


@pytest.mark.parametrize(("cloud", "language"), [("aws", "hcl"), ("azure", "hcl")])
def test_terraform_targets_report_hcl(cloud, language):
    advice = RemediationAdvisor(llm_fallback=False, cloud=cloud).advise_gap(_gap("KSI-SC-2"))
    assert advice.snippet_language == language


def test_llm_prompt_targets_cdk_typescript():
    prompt = _build_remediation_prompt(_all_gaps()[0], "cdk")
    assert "AWS CDK v2 TypeScript" in prompt
    assert "Terraform" not in prompt
    assert "in AWS" in prompt


def test_llm_prompt_keeps_terraform_for_aws_and_azure():
    gap = _all_gaps()[0]
    assert "Terraform HCL (aws provider)" in _build_remediation_prompt(gap, "aws")
    assert "Terraform HCL (azurerm provider)" in _build_remediation_prompt(gap, "azure")


@pytest.mark.parametrize("key", ["snippet", "terraform_snippet"])
def test_llm_result_accepts_new_and_old_snippet_key(monkeypatch, key):
    def fake(gap, model, base_url, cloud="aws"):
        return {"risk_explanation": "r", "remediation_action": "a",
                key: "new s3.Bucket(this, 'B');"}

    monkeypatch.setattr("fedramp_auto.advisor.remediation._call_llm_for_remediation", fake)
    advice = RemediationAdvisor(cloud="cdk").advise_gap(_gap("KSI-AC-4"))
    assert advice.source == "llm"
    assert advice.terraform_snippet == "new s3.Bucket(this, 'B');"
    assert advice.snippet_language == "typescript"


def test_generic_fallback_uses_typescript_comment():
    advice = RemediationAdvisor(llm_fallback=False, cloud="cdk").advise_gap(_gap("KSI-AC-4"))
    assert advice.source == "generic"
    assert advice.terraform_snippet.startswith("// ")


def test_generic_fallback_uses_hcl_comment_for_terraform():
    advice = RemediationAdvisor(llm_fallback=False, cloud="aws").advise_gap(_gap("KSI-AC-4"))
    assert advice.terraform_snippet.startswith("# ")


# ── Static CDK library ────────────────────────────────────────────────────────
# Compile + synth + "does it close the KSI" is checked by
# scripts/check_cdk_snippets.py (needs Node.js); these are the fast checks.

def test_cdk_library_covers_same_ksis_as_aws():
    assert _STATIC_REMEDIATIONS_CDK.keys() == _STATIC_REMEDIATIONS.keys()


@pytest.mark.parametrize("ksi_id", sorted(_STATIC_REMEDIATIONS_CDK))
def test_cdk_snippet_shape(ksi_id):
    entry = _STATIC_REMEDIATIONS_CDK[ksi_id]
    code = entry["snippet"]
    lines = code.splitlines()
    assert lines[0].startswith("import "), "snippet must start with its imports"
    assert all("'aws-cdk-lib" in ln for ln in lines if ln.startswith("import "))
    assert "(this, '" in code, "constructs must be scoped to the stack"
    assert 'resource "' not in code and "aws_" not in code, "Terraform leaked in"
    for open_, close in ("{}", "()", "[]"):
        assert code.count(open_) == code.count(close), f"unbalanced {open_}{close}"
    assert entry["risk"] == _STATIC_REMEDIATIONS[ksi_id]["risk"]
    assert len(entry["action"]) > 40


def test_advisor_returns_static_cdk_snippet():
    advice = RemediationAdvisor(llm_fallback=False, cloud="cdk").advise_gap(_gap("KSI-SC-2"))
    assert advice.source == "static"
    assert advice.cloud == "cdk" and advice.snippet_language == "typescript"
    assert "new kms.Key(this, 'AppKey'" in advice.terraform_snippet


def test_terraform_advice_unchanged_by_cdk_library():
    advice = RemediationAdvisor(llm_fallback=False, cloud="aws").advise_gap(_gap("KSI-SC-2"))
    assert advice.terraform_snippet == _STATIC_REMEDIATIONS["KSI-SC-2"]["terraform"]


# ── CLI ───────────────────────────────────────────────────────────────────────

def _scan(args, out):
    result = CliRunner().invoke(app, ["scan", *args, "--no-llm", "--output", str(out)])
    assert result.exit_code in (0, 2), result.output
    return json.loads((out / "scan_result.json").read_text())


def test_cli_cloud_cdk_writes_typescript_snippets(tmp_path):
    data = _scan([str(CDK_FIXTURES), "--format", "cdk", "--cloud", "cdk"], tmp_path)
    assert data["cloud"] == "cdk"
    rems = data["remediations"]
    assert rems and all(r["snippet_language"] == "typescript" for r in rems)
    static = [r for r in rems if r["source"] == "static"]
    assert static and all("aws-cdk-lib" in r["terraform_snippet"] for r in static)

    report = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "**Remediation target:** AWS · CDK v2 (TypeScript)" in report
    assert "```typescript" in report and "```hcl" not in report
    assert "**AWS CDK (AWS · CDK v2 (TypeScript)):**" in report


def test_cli_terraform_targets_still_write_hcl(tmp_path):
    data = _scan([str(CDK_FIXTURES), "--format", "cdk", "--cloud", "aws"], tmp_path)
    assert all(r["snippet_language"] == "hcl" for r in data["remediations"])
    report = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "```hcl" in report and "**Terraform (AWS · aws provider):**" in report


def test_report_command_fences_by_language(tmp_path):
    _scan([str(CDK_FIXTURES), "--format", "cdk", "--cloud", "cdk"], tmp_path)
    result = CliRunner().invoke(app, ["report", str(tmp_path / "scan_result.json"), "-r"])
    assert result.exit_code == 0, result.output
    assert "```typescript" in result.output


def test_report_command_reads_results_without_snippet_language(tmp_path):
    """scan_result.json files written before snippet_language existed are HCL."""
    old = {
        "baseline": "low", "cloud": "aws", "coverage_pct": 0,
        "satisfied_ksi_count": 0, "total_ksi_count": 1, "gaps": [],
        "remediations": [{"ksi_id": "KSI-SC-2", "risk_explanation": "r",
                          "remediation_action": "a", "terraform_snippet": "resource {}",
                          "source": "static", "cloud": "aws"}],
    }
    path = tmp_path / "old.json"
    path.write_text(json.dumps(old))
    result = CliRunner().invoke(app, ["report", str(path), "-r"])
    assert result.exit_code == 0, result.output
    assert "```hcl" in result.output


def test_cli_auto_detects_cdk_for_synthesized_templates(tmp_path):
    data = _scan([str(CDK_FIXTURES)], tmp_path)
    assert data["cloud"] == "cdk"
    assert all(r["snippet_language"] == "typescript" for r in data["remediations"])
