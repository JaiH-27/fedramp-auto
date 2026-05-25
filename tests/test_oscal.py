"""Tests for fedramp_auto.oscal.ssp_generator and fedramp_auto.oscal.validator"""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fedramp_auto.gaps.detector import detect_gaps
from fedramp_auto.mapper.control_mapper import (
    ControlMapper, ControlMapping, ResourceMapping
)
from fedramp_auto.oscal.ssp_generator import (
    SystemInfo, build_ssp, generate_ssp, write_ssp
)
from fedramp_auto.oscal.validator import validate_ssp_file, ValidationReport
from fedramp_auto.parser.terraform import ParsedResource


# ── Test fixtures ─────────────────────────────────────────────────────────────

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "terraform"


def _make_resource(rtype: str, rname: str = "test") -> ParsedResource:
    return ParsedResource(
        resource_type=rtype,
        resource_name=rname,
        attributes={},
        source_file="test.tf",
    )


def _make_mapping(rtype: str, control_ids: list[str]) -> ResourceMapping:
    resource = _make_resource(rtype)
    controls = [
        ControlMapping(
            control_id=cid,
            control_name=f"Control {cid}",
            rationale=f"Resource satisfies {cid}",
            source="static",
        )
        for cid in control_ids
    ]
    return ResourceMapping(resource=resource, controls=controls)


def _make_test_data():
    mappings = [
        _make_mapping("aws_s3_bucket", ["SC-28", "AU-9", "CP-9"]),
        _make_mapping("aws_cloudtrail", ["AU-2", "AU-3", "AU-12", "AU-9"]),
        _make_mapping("aws_kms_key", ["SC-12", "SC-28", "SC-12(1)"]),
        _make_mapping("aws_iam_role", ["AC-2", "AC-3", "AC-6"]),
        _make_mapping("aws_guardduty_detector", ["SI-3", "SI-4"]),
    ]
    all_controls = [c.control_id for rm in mappings for c in rm.controls]
    gap_report = detect_gaps(all_controls, baseline="low")
    return mappings, gap_report


# ── SSP generator tests ───────────────────────────────────────────────────────

def test_build_ssp_returns_object():
    mappings, gap_report = _make_test_data()
    plan = build_ssp(gap_report, mappings)
    assert plan is not None
    assert plan.uuid


def test_ssp_has_metadata():
    mappings, gap_report = _make_test_data()
    plan = build_ssp(gap_report, mappings)
    assert plan.metadata.title
    assert plan.metadata.oscal_version == "1.1.2"


def test_ssp_has_import_profile():
    mappings, gap_report = _make_test_data()
    plan = build_ssp(gap_report, mappings)
    assert "fedramp" in plan.import_profile.href.lower()
    assert "low" in plan.import_profile.href.lower()


def test_ssp_moderate_profile():
    mappings, gap_report = _make_test_data()
    gap_report.baseline = "moderate"
    plan = build_ssp(gap_report, mappings, baseline="moderate")
    assert "moderate" in plan.import_profile.href.lower()


def test_ssp_has_components():
    mappings, gap_report = _make_test_data()
    plan = build_ssp(gap_report, mappings)
    assert len(plan.system_implementation.components) >= 2


def test_ssp_has_implemented_requirements():
    mappings, gap_report = _make_test_data()
    plan = build_ssp(gap_report, mappings)
    reqs = plan.control_implementation.implemented_requirements
    assert len(reqs) > 0


def test_ssp_control_ids_are_lowercase():
    mappings, gap_report = _make_test_data()
    plan = build_ssp(gap_report, mappings)
    for req in plan.control_implementation.implemented_requirements:
        assert req.control_id == req.control_id.lower(), (
            f"Control ID should be lowercase: {req.control_id}"
        )


def test_ssp_system_info_applied():
    mappings, gap_report = _make_test_data()
    si = SystemInfo(
        system_name="My Test System",
        org_name="Test Org",
    )
    plan = build_ssp(gap_report, mappings, system_info=si)
    assert "My Test System" in plan.metadata.title
    assert plan.system_characteristics.system_name == "My Test System"


def test_write_ssp_creates_file(tmp_path):
    mappings, gap_report = _make_test_data()
    plan = build_ssp(gap_report, mappings)
    out = tmp_path / "ssp.json"
    write_ssp(plan, out)
    assert out.exists()
    data = json.loads(out.read_text())
    assert "system-security-plan" in data


def test_generate_ssp_end_to_end(tmp_path):
    mappings, gap_report = _make_test_data()
    out = tmp_path / "ssp.json"
    path = generate_ssp(gap_report, mappings, out)
    assert path.exists()
    data = json.loads(path.read_text())
    ssp = data["system-security-plan"]
    assert ssp["uuid"]
    assert ssp["metadata"]["title"]
    assert ssp["control-implementation"]["implemented-requirements"]


def test_ssp_json_is_valid_json(tmp_path):
    mappings, gap_report = _make_test_data()
    out = tmp_path / "ssp.json"
    generate_ssp(gap_report, mappings, out)
    # Should not raise
    json.loads(out.read_text())


# ── Validator tests ───────────────────────────────────────────────────────────

def test_validate_generated_ssp_passes(tmp_path):
    mappings, gap_report = _make_test_data()
    out = tmp_path / "ssp.json"
    generate_ssp(gap_report, mappings, out)
    report = validate_ssp_file(out)
    assert isinstance(report, ValidationReport)
    # Generated SSP should have no errors (warnings are ok)
    errors = [i for i in report.issues if i.severity == "error"]
    assert errors == [], f"Unexpected errors: {errors}"


def test_validate_missing_envelope(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text(json.dumps({"not-an-ssp": {}}))
    report = validate_ssp_file(f)
    assert not report.passed
    codes = [i.code for i in report.errors]
    assert "MISSING_ENVELOPE" in codes


def test_validate_invalid_json(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("{not valid json")
    report = validate_ssp_file(f)
    assert not report.passed
    assert report.errors[0].code == "JSON_PARSE_ERROR"


def test_validate_missing_uuid(tmp_path):
    f = tmp_path / "ssp.json"
    f.write_text(json.dumps({
        "system-security-plan": {
            "metadata": {"title": "t", "last-modified": "2026-01-01T00:00:00Z",
                         "version": "1", "oscal-version": "1.1.2"},
        }
    }))
    report = validate_ssp_file(f)
    assert not report.passed
    codes = [i.code for i in report.errors]
    assert "MISSING_REQUIRED_FIELD" in codes


def test_validate_summary_string(tmp_path):
    mappings, gap_report = _make_test_data()
    out = tmp_path / "ssp.json"
    generate_ssp(gap_report, mappings, out)
    report = validate_ssp_file(out)
    summary = report.summary()
    assert "PASSED" in summary or "FAILED" in summary


def test_validate_from_fixture(tmp_path):
    """Full pipeline test: parse real terraform → gap → SSP → validate."""
    from fedramp_auto.parser.terraform import parse_directory
    parse_result = parse_directory(FIXTURE_DIR)
    mapper = ControlMapper(llm_fallback=False)
    mappings = mapper.map_resources(parse_result.resources)
    all_controls = [c.control_id for rm in mappings for c in rm.controls]
    gap_report = detect_gaps(all_controls, baseline="low")

    out = tmp_path / "ssp.json"
    generate_ssp(gap_report, mappings, out)
    report = validate_ssp_file(out)

    errors = [i for i in report.issues if i.severity == "error"]
    assert errors == [], f"Pipeline produced invalid SSP: {errors}"
