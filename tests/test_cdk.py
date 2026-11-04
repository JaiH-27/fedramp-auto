"""Tests for fedramp_auto.parser.cloudformation (AWS CDK) and the AWS:: mapper rules"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from fedramp_auto.advisor.remediation import detect_cloud
from fedramp_auto.gaps.detector import detect_gaps
from fedramp_auto.mapper.control_mapper import ControlMapper
from fedramp_auto.oscal.ssp_generator import build_ssp
from fedramp_auto.parser import arm
from fedramp_auto.parser.cloudformation import (
    is_cloudformation_template,
    parse_directory,
    parse_file,
)
from fedramp_auto.parser.terraform import ParsedResource, ParseResult

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "cdk"


@pytest.fixture(scope="module")
def parsed() -> ParseResult:
    return parse_directory(FIXTURE_DIR)


@pytest.fixture(scope="module")
def mapped(parsed):
    return ControlMapper(llm_fallback=False).map_resources(parsed.resources)


def _controls_for(mapped, rtype: str) -> list[str]:
    return [c for rm in mapped if rm.resource.resource_type == rtype for c in rm.control_ids]


def _write(tmp_path: Path, resources: dict, name: str = "Stack.template.json", **extra) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({"Resources": resources, **extra}))
    return path


def _map_one(tmp_path: Path, rtype: str, props: dict):
    path = _write(tmp_path, {"R": {"Type": rtype, "Properties": props}})
    return ControlMapper(llm_fallback=False).map_resource(parse_file(path).resources[0])


# ── Detection ─────────────────────────────────────────────────────────────────

def test_detects_cdk_template_without_format_version():
    assert is_cloudformation_template({"Resources": {"B": {"Type": "AWS::S3::Bucket"}}})

def test_detects_plain_cloudformation_template():
    assert is_cloudformation_template(
        {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"X": {"Type": "Custom::Thing"}}}
    )

def test_rejects_non_cfn_json():
    assert not is_cloudformation_template({"name": "pkg", "version": "1.0.0"})
    assert not is_cloudformation_template({"Resources": {}})
    assert not is_cloudformation_template({"Resources": {"A": {"Type": "SomethingElse"}}})

def test_cdk_bookkeeping_files_skipped(parsed):
    sources = {Path(r.source_file).name for r in parsed.resources}
    assert sources == {"AuditStack.template.json"}

def test_reports_malformed_template(tmp_path):
    (tmp_path / "Broken.template.json").write_text('{"Resources": {')
    assert parse_directory(tmp_path).errors

def test_ignores_malformed_unrelated_json(tmp_path):
    (tmp_path / "tsconfig.json").write_text("{ // comments are not JSON\n }")
    result = parse_directory(tmp_path)
    assert result.resources == [] and result.errors == []

def test_formats_do_not_cross_parse(parsed):
    """ARM parser must ignore CDK output (and vice versa — see test_arm fixtures)."""
    assert arm.parse_directory(FIXTURE_DIR).resources == []
    arm_fixtures = Path(__file__).parent / "fixtures" / "arm"
    assert parse_directory(arm_fixtures).resources == []


# ── Parsing ───────────────────────────────────────────────────────────────────

def test_no_parse_errors(parsed):
    assert parsed.errors == []

def test_drops_cdk_metadata_resource(parsed):
    assert not parsed.by_type("AWS::CDK::Metadata")

def test_uses_cdk_construct_path_as_name(parsed):
    bucket = parsed.by_type("AWS::S3::Bucket")[0]
    assert bucket.identifier == "AWS::S3::Bucket.AuditStack/AuditBucket"
    policy = parsed.by_type("AWS::S3::BucketPolicy")[0]
    assert policy.resource_name == "AuditStack/AuditBucket/Policy"

def test_falls_back_to_logical_id(parsed):
    assert parsed.by_type("AWS::GuardDuty::Detector")[0].resource_name == "Detector"

def test_resolves_parameter_default(parsed):
    logs = parsed.by_type("AWS::Logs::LogGroup")[0]
    assert logs.attributes["RetentionInDays"] == 365

def test_keeps_deletion_policy(parsed):
    assert parsed.by_type("AWS::S3::Bucket")[0].attributes["DeletionPolicy"] == "Retain"

def test_noecho_parameter_not_resolved_and_redacted(parsed):
    db = parsed.by_type("AWS::RDS::DBInstance")[0]
    assert "NotARealPassword" not in json.dumps(db.attributes)
    assert "<REDACTED>" in json.dumps(db.attributes["MasterUserPassword"])

def test_intrinsics_kept_verbatim(parsed):
    trail = parsed.by_type("AWS::CloudTrail::Trail")[0]
    assert trail.attributes["S3BucketName"] == {"Ref": "AuditBucket8E3F1A2B"}


# ── Mapper ────────────────────────────────────────────────────────────────────

def test_bucket_controls(mapped):
    controls = set(_controls_for(mapped, "AWS::S3::Bucket"))
    assert {"SC-28", "CP-9", "AU-9", "AC-3", "AC-22", "SC-7"} <= controls

def test_enforce_ssl_bucket_policy(mapped):
    assert "SC-8" in _controls_for(mapped, "AWS::S3::BucketPolicy")

def test_trail_controls(mapped):
    controls = set(_controls_for(mapped, "AWS::CloudTrail::Trail"))
    assert {"AU-2", "AU-3", "AU-12", "AU-9", "AU-6", "AU-12(1)"} <= controls

def test_rds_controls(mapped):
    controls = set(_controls_for(mapped, "AWS::RDS::DBInstance"))
    assert {"SC-28", "CP-9", "SI-12", "SC-5", "SC-6"} <= controls

def test_cognito_mfa(mapped):
    controls = set(_controls_for(mapped, "AWS::Cognito::UserPool"))
    assert {"AC-2", "IA-2", "IA-2(1)", "IA-5"} <= controls

def test_bucket_rules_off_when_unconfigured(tmp_path):
    rm = _map_one(tmp_path, "AWS::S3::Bucket", {})
    assert rm.control_ids == ["SC-28"]

def test_rds_default_backup_retention_is_one_day(tmp_path):
    rm = _map_one(tmp_path, "AWS::RDS::DBInstance", {"StorageEncrypted": "true"})
    assert "SC-28" in rm.control_ids   # string booleans accepted
    assert "CP-9" in rm.control_ids    # CFN default retention = 1 day
    assert "SI-12" not in rm.control_ids

def test_rds_backups_disabled(tmp_path):
    rm = _map_one(tmp_path, "AWS::RDS::DBInstance", {"BackupRetentionPeriod": 0})
    assert "CP-9" not in rm.control_ids

def test_log_group_without_retention_never_expires(tmp_path):
    assert "AU-11" in _map_one(tmp_path, "AWS::Logs::LogGroup", {}).control_ids
    assert "AU-11" not in _map_one(
        tmp_path, "AWS::Logs::LogGroup", {"RetentionInDays": 30}
    ).control_ids

def test_listener_tls_policy(tmp_path):
    strong = _map_one(tmp_path, "AWS::ElasticLoadBalancingV2::Listener",
                      {"Protocol": "HTTPS", "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06"})
    assert {"SC-8", "SC-8(1)"} <= set(strong.control_ids)
    legacy = _map_one(tmp_path, "AWS::ElasticLoadBalancingV2::Listener",
                      {"Protocol": "HTTPS", "SslPolicy": "ELBSecurityPolicy-2016-08"})
    assert legacy.control_ids == ["SC-8"]
    plain = _map_one(tmp_path, "AWS::ElasticLoadBalancingV2::Listener", {"Protocol": "HTTP"})
    assert plain.control_ids == []

def test_bucket_policy_without_tls_deny(tmp_path):
    rm = _map_one(tmp_path, "AWS::S3::BucketPolicy", {
        "PolicyDocument": {"Statement": {"Effect": "Allow", "Action": "s3:GetObject"}},
    })
    assert rm.control_ids == []

def test_ecr_scan_on_push(tmp_path):
    rm = _map_one(tmp_path, "AWS::ECR::Repository",
                  {"ImageScanningConfiguration": {"ScanOnPush": True}})
    assert rm.control_ids == ["RA-5"]


# ── End to end: cloud detection, gaps, SSP ────────────────────────────────────

def test_detect_cloud_is_aws(parsed):
    assert detect_cloud(parsed.resources) == "aws"

def test_gap_report_from_cdk(mapped):
    controls = sorted({c for rm in mapped for c in rm.control_ids})
    report = detect_gaps(controls, baseline="low")
    satisfied = {k.ksi_id for k in report.satisfied_ksis}
    assert {
        "KSI-SC-2", "KSI-SC-3", "KSI-AU-1", "KSI-AU-2", "KSI-AU-3",
        "KSI-CP-1", "KSI-SC-4", "KSI-AC-3", "KSI-SI-1",
    } <= satisfied

def test_ssp_components_for_cdk(mapped):
    controls = sorted({c for rm in mapped for c in rm.control_ids})
    plan = build_ssp(detect_gaps(controls, baseline="low"), mapped)
    components = plan.system_implementation.components
    titles = [c.title for c in components]
    assert "Amazon Web Services (AWS)" in titles
    assert "Microsoft Azure" not in titles
    assert "AWS S3 Bucket" in titles
    assert "AWS RDS DBInstance" in titles
    bucket = next(c for c in components if c.title == "AWS S3 Bucket")
    assert bucket.description.startswith("CloudFormation-managed")


# ── AWS Backup plans (CloudFormation and Terraform) ───────────────────────────

def test_cfn_backup_plan_controls(tmp_path):
    rm = _map_one(tmp_path, "AWS::Backup::BackupPlan", {"BackupPlan": {
        "BackupPlanName": "p",
        "BackupPlanRule": [{"RuleName": "daily", "Lifecycle": {"DeleteAfterDays": 35},
                            "TargetBackupVault": {"Fn::GetAtt": ["V", "BackupVaultName"]}}],
    }})
    assert {"CP-9", "SI-12"} <= set(rm.control_ids)

def test_cfn_backup_plan_short_retention(tmp_path):
    rm = _map_one(tmp_path, "AWS::Backup::BackupPlan", {"BackupPlan": {
        "BackupPlanName": "p",
        "BackupPlanRule": [{"RuleName": "daily", "Lifecycle": {"DeleteAfterDays": 7}}],
    }})
    assert rm.control_ids == ["CP-9"]

def test_cfn_backup_plan_without_rules(tmp_path):
    rm = _map_one(tmp_path, "AWS::Backup::BackupPlan", {"BackupPlan": {"BackupPlanName": "p"}})
    assert rm.control_ids == []

def test_terraform_backup_plan_controls():
    plan = ParsedResource(
        resource_type="aws_backup_plan",
        resource_name="main",
        # python-hcl2 shape: repeated blocks become lists
        attributes={"name": "p", "rule": [{"rule_name": "daily",
                                           "lifecycle": [{"delete_after": 35}]}]},
        source_file="main.tf",
    )
    rm = ControlMapper(llm_fallback=False).map_resource(plan)
    assert {"CP-9", "SI-12"} <= set(rm.control_ids)
