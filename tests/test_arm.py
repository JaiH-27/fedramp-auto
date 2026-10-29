"""Tests for fedramp_auto.parser.arm and the Azure mapper rules"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from fedramp_auto.gaps.detector import detect_gaps
from fedramp_auto.mapper.control_mapper import ControlMapper
from fedramp_auto.oscal.ssp_generator import build_ssp
from fedramp_auto.parser.arm import is_arm_template, parse_directory, parse_file
from fedramp_auto.parser.terraform import ParseResult, _sanitize_value

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "arm"
ARM_SCHEMA = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"


@pytest.fixture(scope="module")
def parsed() -> ParseResult:
    return parse_directory(FIXTURE_DIR)


@pytest.fixture(scope="module")
def mapped(parsed):
    return ControlMapper(llm_fallback=False).map_resources(parsed.resources)


def _controls_for(mapped, rtype: str) -> list[str]:
    return [c for rm in mapped if rm.resource.resource_type == rtype for c in rm.control_ids]


# ── Detection ─────────────────────────────────────────────────────────────────

def test_detects_arm_template():
    assert is_arm_template({"$schema": ARM_SCHEMA, "resources": []})

def test_rejects_non_arm_json():
    assert not is_arm_template({"name": "my-package", "version": "1.0.0"})

def test_rejects_parameters_file():
    schema = "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#"
    assert not is_arm_template({"$schema": schema, "parameters": {}})

def test_skips_unrelated_json(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "x"}')
    (tmp_path / "tsconfig.json").write_text("{ // comments are not JSON\n }")
    result = parse_directory(tmp_path)
    assert result.resources == []
    assert result.errors == []

def test_reports_malformed_template(tmp_path):
    (tmp_path / "broken.json").write_text(f'{{"$schema": "{ARM_SCHEMA}", "resources": [')
    assert parse_directory(tmp_path).errors


# ── Parsing ───────────────────────────────────────────────────────────────────

def test_no_parse_errors(parsed):
    assert parsed.errors == []

def test_finds_top_level_resources(parsed):
    for rtype in (
        "Microsoft.Storage/storageAccounts",
        "Microsoft.KeyVault/vaults",
        "Microsoft.Sql/servers",
        "Microsoft.Network/networkSecurityGroups",
    ):
        assert parsed.by_type(rtype), rtype

def test_expands_nested_child_types(parsed):
    assert parsed.by_type("Microsoft.Storage/storageAccounts/blobServices")
    assert parsed.by_type("Microsoft.Sql/servers/auditingSettings")

def test_resolves_parameter_default(parsed):
    storage = parsed.by_type("Microsoft.Storage/storageAccounts")[0]
    assert storage.resource_name == "auditlogsstore"
    assert storage.attributes["properties"]["supportsHttpsTrafficOnly"] is True

def test_resolves_variable(parsed):
    ws = parsed.by_type("Microsoft.OperationalInsights/workspaces")[0]
    assert ws.attributes["properties"]["retentionInDays"] == 365

def test_secure_parameter_not_resolved_and_redacted(parsed):
    sql = parsed.by_type("Microsoft.Sql/servers")[0]
    value = sql.attributes["properties"]["administratorLoginPassword"]
    assert "NotARealPassword" not in json.dumps(sql.attributes)
    assert value == "<REDACTED>"

def test_structural_keys_dropped(parsed):
    blob = parsed.by_type("Microsoft.Storage/storageAccounts/blobServices")[0]
    assert "dependsOn" not in blob.attributes
    assert "apiVersion" not in blob.attributes

def test_symbolic_name_resources(tmp_path):
    tpl = {
        "$schema": ARM_SCHEMA,
        "languageVersion": "2.0",
        "resources": {
            "vnet": {"type": "Microsoft.Network/virtualNetworks", "name": "core-vnet"},
        },
    }
    path = tmp_path / "main.json"
    path.write_text(json.dumps(tpl))
    result = parse_file(path)
    assert result.resources[0].identifier == "Microsoft.Network/virtualNetworks.vnet"


# ── Sanitizer: camelCase secret names ─────────────────────────────────────────

def test_redacts_camel_case_secret_name():
    assert _sanitize_value("adminPassword", "plain") == "<REDACTED>"
    assert _sanitize_value("connectionString", "Server=x") == "<REDACTED>"

def test_preserves_camel_case_safe_name():
    assert _sanitize_value("administratorLogin", "sqladmin") == "sqladmin"


# ── Mapper ────────────────────────────────────────────────────────────────────

def test_storage_controls(mapped):
    controls = _controls_for(mapped, "Microsoft.Storage/storageAccounts")
    for cid in ("SC-28", "SC-8", "SC-8(1)", "AC-3", "AC-22", "SC-7"):
        assert cid in controls, cid

def test_blob_service_backup(mapped):
    controls = _controls_for(mapped, "Microsoft.Storage/storageAccounts/blobServices")
    assert {"CP-9", "AU-9"} <= set(controls)

def test_sql_auditing_controls(mapped):
    controls = _controls_for(mapped, "Microsoft.Sql/servers/auditingSettings")
    assert {"AU-2", "AU-12", "AU-11"} <= set(controls)

def test_defender_includes_vuln_scanning(mapped):
    assert "RA-5" in _controls_for(mapped, "Microsoft.Security/pricings")

def test_rule_not_applied_when_setting_off(tmp_path):
    tpl = {
        "$schema": ARM_SCHEMA,
        "resources": [{
            "type": "Microsoft.Storage/storageAccounts",
            "name": "open",
            "properties": {"supportsHttpsTrafficOnly": False, "allowBlobPublicAccess": True},
        }],
    }
    path = tmp_path / "open.json"
    path.write_text(json.dumps(tpl))
    rm = ControlMapper(llm_fallback=False).map_resource(parse_file(path).resources[0])
    assert "SC-8" not in rm.control_ids
    assert "AC-22" not in rm.control_ids
    assert "SC-7" not in rm.control_ids

def test_type_lookup_is_case_insensitive(tmp_path):
    tpl = {"$schema": ARM_SCHEMA, "resources": [
        {"type": "microsoft.network/NETWORKSECURITYGROUPS", "name": "nsg"},
    ]}
    path = tmp_path / "nsg.json"
    path.write_text(json.dumps(tpl))
    rm = ControlMapper(llm_fallback=False).map_resource(parse_file(path).resources[0])
    assert "SC-7" in rm.control_ids


# ── End to end: gaps + SSP ────────────────────────────────────────────────────

def test_gap_report_from_arm(mapped):
    controls = sorted({c for rm in mapped for c in rm.control_ids})
    report = detect_gaps(controls, baseline="low")
    satisfied = {k.ksi_id for k in report.satisfied_ksis}
    assert {"KSI-SC-2", "KSI-AU-1", "KSI-CP-1", "KSI-SC-4"} <= satisfied

def test_ssp_uses_azure_provider_component(mapped):
    controls = sorted({c for rm in mapped for c in rm.control_ids})
    plan = build_ssp(detect_gaps(controls, baseline="low"), mapped)
    titles = [c.title for c in plan.system_implementation.components]
    assert "Microsoft Azure" in titles
    assert "Amazon Web Services (AWS)" not in titles
    assert "Azure Storage/storageAccounts" in titles


# ── Terraform: unresolved variable references don't crash numeric rules ─────

def test_terraform_numeric_rules_tolerate_variable_refs():
    from fedramp_auto.parser.terraform import ParsedResource

    db = ParsedResource(
        resource_type="aws_db_instance",
        resource_name="db",
        attributes={"backup_retention_period": "${var.retention}", "storage_encrypted": True},
        source_file="main.tf",
    )
    rm = ControlMapper(llm_fallback=False).map_resource(db)
    assert "SC-28" in rm.control_ids
    assert "SI-12" not in rm.control_ids
