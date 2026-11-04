"""Tests for the AWS CDK (TypeScript) remediation target"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from fedramp_auto.advisor.remediation import (
    _STATIC_REMEDIATIONS,
    _STATIC_REMEDIATIONS_CDK,
    SNIPPET_LANGUAGE,
    SUPPORTED_CLOUDS,
    RemediationAdvisor,
    _build_remediation_prompt,
)
from fedramp_auto.gaps.detector import detect_gaps


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
