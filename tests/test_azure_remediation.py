"""Tests for Azure (azurerm) remediation snippets and cloud selection"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from typer.testing import CliRunner

from fedramp_auto.advisor.remediation import (
    _STATIC_REMEDIATIONS,
    _STATIC_REMEDIATIONS_AZURE,
    RemediationAdvisor,
    _build_remediation_prompt,
    detect_cloud,
)
from fedramp_auto.cli.main import app
from fedramp_auto.gaps.detector import detect_gaps
from fedramp_auto.parser.terraform import ParsedResource

ARM_FIXTURES = Path(__file__).parent / "fixtures" / "arm"


def _res(rtype: str) -> ParsedResource:
    return ParsedResource(resource_type=rtype, resource_name="x", attributes={}, source_file="t")


def _all_gaps():
    return detect_gaps([], baseline="moderate").gaps


# ── Static library ────────────────────────────────────────────────────────────

def test_azure_library_covers_same_ksis_as_aws():
    assert _STATIC_REMEDIATIONS_AZURE.keys() == _STATIC_REMEDIATIONS.keys()


@pytest.mark.parametrize("ksi_id", sorted(_STATIC_REMEDIATIONS_AZURE))
def test_azure_snippets_use_azurerm_only(ksi_id):
    entry = _STATIC_REMEDIATIONS_AZURE[ksi_id]
    hcl = entry["terraform"]
    assert 'resource "azurerm_' in hcl
    assert "aws_" not in hcl
    assert not hcl.startswith("\\"), "line-continuation backslash leaked into snippet"
    assert hcl.count("{") == hcl.count("}"), "unbalanced braces"
    assert len(entry["risk"]) > 20 and len(entry["action"]) > 20


@pytest.mark.parametrize("ksi_id", sorted(_STATIC_REMEDIATIONS))
def test_aws_snippets_unchanged_provider(ksi_id):
    assert "azurerm_" not in _STATIC_REMEDIATIONS[ksi_id]["terraform"]


# ── Advisor ───────────────────────────────────────────────────────────────────

def test_advisor_defaults_to_aws():
    advisor = RemediationAdvisor(llm_fallback=False)
    gap = next(g for g in _all_gaps() if g.ksi.ksi_id == "KSI-SC-2")
    advice = advisor.advise_gap(gap)
    assert advice.cloud == "aws"
    assert "aws_s3_bucket" in advice.terraform_snippet


def test_advisor_azure_static():
    advisor = RemediationAdvisor(llm_fallback=False, cloud="azure")
    gap = next(g for g in _all_gaps() if g.ksi.ksi_id == "KSI-SC-2")
    advice = advisor.advise_gap(gap)
    assert advice.source == "static"
    assert advice.cloud == "azure"
    assert "azurerm_key_vault_key" in advice.terraform_snippet


def test_advisor_azure_generic_fallback_tagged():
    advisor = RemediationAdvisor(llm_fallback=False, cloud="azure")
    gap = next(g for g in _all_gaps() if g.ksi.ksi_id not in _STATIC_REMEDIATIONS_AZURE)
    advice = advisor.advise_gap(gap)
    assert advice.source == "generic"
    assert advice.cloud == "azure"


def test_advisor_rejects_unknown_cloud():
    with pytest.raises(ValueError):
        RemediationAdvisor(cloud="gcp")  # type: ignore[arg-type]


def test_llm_prompt_targets_azurerm():
    gap = _all_gaps()[0]
    prompt = _build_remediation_prompt(gap, "azure")
    assert "azurerm provider" in prompt and "in Azure" in prompt
    assert "in AWS" in _build_remediation_prompt(gap)


def test_llm_called_with_cloud(monkeypatch):
    seen = {}

    def fake(gap, model, base_url, cloud="aws"):
        seen["cloud"] = cloud
        return {"risk_explanation": "r", "remediation_action": "a", "terraform_snippet": "t"}

    monkeypatch.setattr("fedramp_auto.advisor.remediation._call_llm_for_remediation", fake)
    gap = next(g for g in _all_gaps() if g.ksi.ksi_id not in _STATIC_REMEDIATIONS_AZURE)
    advice = RemediationAdvisor(cloud="azure").advise_gap(gap)
    assert seen["cloud"] == "azure"
    assert advice.source == "llm" and advice.cloud == "azure"


# ── Cloud detection ───────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    ("types", "expected"),
    [
        ([], "aws"),
        (["aws_s3_bucket", "aws_kms_key"], "aws"),
        (["azurerm_storage_account"], "azure"),
        (["Microsoft.Storage/storageAccounts"], "azure"),
        (["microsoft.network/networkSecurityGroups"], "azure"),
        (["aws_s3_bucket", "azurerm_storage_account"], "aws"),          # tie -> aws
        (["aws_s3_bucket", "azurerm_vnet", "Microsoft.Sql/servers"], "azure"),
        (["random_id", "null_resource"], "aws"),
    ],
)
def test_detect_cloud(types, expected):
    assert detect_cloud(_res(t) for t in types) == expected


# ── CLI end-to-end ────────────────────────────────────────────────────────────

def _scan(args, out):
    result = CliRunner().invoke(app, ["scan", *args, "--no-llm", "--output", str(out)])
    assert result.exit_code in (0, 2), result.output
    return json.loads((out / "scan_result.json").read_text())


def _bare_arm_dir(tmp_path: Path) -> Path:
    """An ARM template with one unconfigured resource, so the static KSIs are gaps."""
    infra = tmp_path / "infra"
    infra.mkdir()
    (infra / "main.json").write_text(json.dumps({
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "resources": [{
            "type": "Microsoft.Web/serverfarms",
            "apiVersion": "2022-09-01",
            "name": "plan",
            "location": "eastus",
            "sku": {"name": "B1"},
        }],
    }))
    return infra


def test_cli_auto_detects_azure_for_arm(tmp_path):
    data = _scan([str(_bare_arm_dir(tmp_path))], tmp_path / "out")
    assert data["cloud"] == "azure"
    rems = data["remediations"]
    assert rems and all(r["cloud"] == "azure" for r in rems)
    static = [r for r in rems if r["source"] == "static"]
    assert static and all("azurerm_" in r["terraform_snippet"] for r in static)
    assert {"KSI-SC-2", "KSI-SC-4"} <= {r["ksi_id"] for r in static}
    report = (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    assert "Azure · azurerm provider" in report


def test_cli_auto_detects_azure_for_full_fixture(tmp_path):
    assert _scan([str(ARM_FIXTURES)], tmp_path)["cloud"] == "azure"


def test_cli_cloud_override(tmp_path):
    data = _scan([str(_bare_arm_dir(tmp_path)), "--cloud", "aws"], tmp_path / "out")
    assert data["cloud"] == "aws"
    assert all(r["cloud"] == "aws" for r in data["remediations"])


def test_cli_rejects_bad_cloud(tmp_path):
    args = ["scan", str(ARM_FIXTURES), "--cloud", "gcp", "-o", str(tmp_path)]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 1
