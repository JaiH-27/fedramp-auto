"""
fedramp_auto.oscal.validator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Validates a generated OSCAL SSP JSON file against:
  1. JSON parse check
  2. OSCAL envelope structure (system-security-plan top-level key)
  3. Required OSCAL fields (uuid, metadata, system-characteristics, etc.)
  4. FedRAMP-specific required properties (marking, authorization-type, etc.)
  5. Control implementation completeness (no empty implemented-requirements)
  6. Optional: trestle model round-trip validation (catches type errors)

The full GSA fedramp-automation validator (Java-based) is noted where
applicable and instructions for running it are included in the report.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from trestle.oscal import ssp as ssp_model


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class ValidationIssue:
    severity: str      # "error" | "warning" | "info"
    code: str          # short machine-readable code
    message: str
    path: str = ""     # JSON path where the issue was found


@dataclass
class ValidationReport:
    passed: bool
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == "warning"]

    def summary(self) -> str:
        status = "PASSED" if self.passed else "FAILED"
        return (
            f"Validation {status} — "
            f"{len(self.errors)} error(s), {len(self.warnings)} warning(s)"
        )


# ── Individual checks ─────────────────────────────────────────────────────────

def _check_envelope(data: Any) -> list[ValidationIssue]:
    issues = []
    if not isinstance(data, dict):
        issues.append(ValidationIssue(
            severity="error", code="INVALID_JSON_ROOT",
            message="Root element must be a JSON object.",
        ))
        return issues
    if "system-security-plan" not in data:
        issues.append(ValidationIssue(
            severity="error", code="MISSING_ENVELOPE",
            message="Missing required top-level key 'system-security-plan'.",
            path="$",
        ))
    return issues


def _check_required_fields(ssp: dict) -> list[ValidationIssue]:
    issues = []
    required = [
        "uuid", "metadata", "import-profile",
        "system-characteristics", "system-implementation",
        "control-implementation",
    ]
    for field_name in required:
        if field_name not in ssp:
            issues.append(ValidationIssue(
                severity="error", code="MISSING_REQUIRED_FIELD",
                message=f"Missing required SSP field: '{field_name}'.",
                path=f"system-security-plan.{field_name}",
            ))
    return issues


def _check_metadata(metadata: dict) -> list[ValidationIssue]:
    issues = []
    required_meta = ["title", "last-modified", "version", "oscal-version"]
    for f in required_meta:
        if f not in metadata:
            issues.append(ValidationIssue(
                severity="error", code="MISSING_METADATA_FIELD",
                message=f"Missing required metadata field: '{f}'.",
                path=f"system-security-plan.metadata.{f}",
            ))

    # FedRAMP requires roles
    roles = metadata.get("roles", [])
    role_ids = {r.get("id") for r in roles}
    required_roles = {"system-owner", "authorizing-official"}
    for rid in required_roles:
        if rid not in role_ids:
            issues.append(ValidationIssue(
                severity="warning", code="MISSING_ROLE",
                message=f"FedRAMP recommends role '{rid}' in metadata.",
                path="system-security-plan.metadata.roles",
            ))

    return issues


def _check_fedramp_props(ssp: dict) -> list[ValidationIssue]:
    """Check FedRAMP-specific OSCAL properties."""
    issues = []
    _FEDRAMP_NS = "https://fedramp.gov/ns/oscal"

    def get_fedramp_props(obj: dict) -> dict[str, str]:
        props = obj.get("props", [])
        return {
            p["name"]: p["value"]
            for p in props
            if isinstance(p, dict) and p.get("ns") == _FEDRAMP_NS
        }

    # Check top-level marking
    meta_props = get_fedramp_props(ssp.get("metadata", {}))
    if "marking" not in meta_props:
        issues.append(ValidationIssue(
            severity="warning", code="MISSING_FEDRAMP_MARKING",
            message="FedRAMP requires a 'marking' property (e.g. 'CUI') in metadata.",
            path="system-security-plan.metadata.props",
        ))

    # Check system-characteristics FedRAMP props
    sc_props = get_fedramp_props(ssp.get("system-characteristics", {}))
    if "authorization-type" not in sc_props:
        issues.append(ValidationIssue(
            severity="warning", code="MISSING_AUTHORIZATION_TYPE",
            message="FedRAMP requires 'authorization-type' property in system-characteristics.",
            path="system-security-plan.system-characteristics.props",
        ))

    return issues


def _check_system_characteristics(sc: dict) -> list[ValidationIssue]:
    issues = []
    for f in ["system-ids", "system-name", "description", "status",
              "authorization-boundary", "system-information"]:
        if f not in sc:
            issues.append(ValidationIssue(
                severity="error", code="MISSING_SC_FIELD",
                message=f"Missing required system-characteristics field: '{f}'.",
                path=f"system-security-plan.system-characteristics.{f}",
            ))

    # Status must have a state
    status = sc.get("status", {})
    if not status.get("state"):
        issues.append(ValidationIssue(
            severity="error", code="MISSING_STATUS_STATE",
            message="system-characteristics.status must have a 'state' value.",
            path="system-security-plan.system-characteristics.status.state",
        ))

    return issues


def _check_system_implementation(si: dict) -> list[ValidationIssue]:
    issues = []
    components = si.get("components", [])
    if not components:
        issues.append(ValidationIssue(
            severity="error", code="NO_COMPONENTS",
            message="system-implementation must have at least one component.",
            path="system-security-plan.system-implementation.components",
        ))

    users = si.get("users", [])
    if not users:
        issues.append(ValidationIssue(
            severity="warning", code="NO_USERS",
            message="FedRAMP recommends at least one user defined in system-implementation.",
            path="system-security-plan.system-implementation.users",
        ))

    # Check each component has required fields
    for i, comp in enumerate(components):
        for f in ["uuid", "type", "title", "description", "status"]:
            if f not in comp:
                issues.append(ValidationIssue(
                    severity="error", code="MISSING_COMPONENT_FIELD",
                    message=f"Component[{i}] missing required field: '{f}'.",
                    path=f"system-security-plan.system-implementation.components[{i}].{f}",
                ))

    return issues


def _check_control_implementation(ci: dict) -> list[ValidationIssue]:
    issues = []
    reqs = ci.get("implemented-requirements", [])
    if not reqs:
        issues.append(ValidationIssue(
            severity="error", code="NO_IMPLEMENTED_REQUIREMENTS",
            message="control-implementation must have at least one implemented-requirement.",
            path="system-security-plan.control-implementation.implemented-requirements",
        ))

    not_implemented = 0
    missing_by_comp = 0
    for req in reqs:
        by_comps = req.get("by-components", [])
        if not by_comps:
            missing_by_comp += 1

        # Check for not-implemented status
        for bc in by_comps:
            impl_status = bc.get("implementation-status", {})
            if impl_status.get("state") == "not-implemented":
                not_implemented += 1

    if not_implemented > 0:
        issues.append(ValidationIssue(
            severity="warning", code="CONTROLS_NOT_IMPLEMENTED",
            message=(
                f"{not_implemented} by-component(s) have state 'not-implemented'. "
                "These must be addressed before FedRAMP submission."
            ),
            path="system-security-plan.control-implementation.implemented-requirements",
        ))

    if missing_by_comp > 0:
        issues.append(ValidationIssue(
            severity="warning", code="MISSING_BY_COMPONENTS",
            message=(
                f"{missing_by_comp} implemented-requirement(s) have no by-components. "
                "FedRAMP requires evidence for each control."
            ),
        ))

    return issues


def _check_trestle_roundtrip(ssp_dict: dict) -> list[ValidationIssue]:
    """Attempt to parse the SSP through trestle's model for type validation."""
    issues = []
    try:
        ssp_model.SystemSecurityPlan(**ssp_dict)
    except Exception as exc:  # noqa: BLE001
        issues.append(ValidationIssue(
            severity="error", code="TRESTLE_PARSE_ERROR",
            message=f"OSCAL model validation failed: {exc}",
        ))
    return issues


# ── Public API ────────────────────────────────────────────────────────────────

def validate_ssp_file(path: str | Path) -> ValidationReport:
    """
    Validate an OSCAL SSP JSON file.

    Runs all checks in order, accumulating issues. Returns a ValidationReport
    with passed=True only if there are zero errors (warnings are allowed).

    Parameters
    ----------
    path:
        Path to the SSP JSON file.

    Returns
    -------
    ValidationReport with full list of issues.

    Example
    -------
    >>> report = validate_ssp_file("./output/ssp.json")
    >>> print(report.summary())
    >>> for issue in report.errors:
    ...     print(issue.code, issue.message)
    """
    path = Path(path)
    issues: list[ValidationIssue] = []

    # 1. Load JSON
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        return ValidationReport(
            passed=False,
            issues=[ValidationIssue(
                severity="error", code="JSON_PARSE_ERROR",
                message=f"Could not parse file as JSON: {exc}",
            )],
        )

    # 2. Envelope check
    issues.extend(_check_envelope(data))
    if any(i.severity == "error" for i in issues):
        return ValidationReport(passed=False, issues=issues)

    ssp = data["system-security-plan"]

    # 3. Required top-level fields
    issues.extend(_check_required_fields(ssp))

    # 4. Metadata
    if "metadata" in ssp:
        issues.extend(_check_metadata(ssp["metadata"]))

    # 5. FedRAMP properties
    issues.extend(_check_fedramp_props(ssp))

    # 6. System characteristics
    if "system-characteristics" in ssp:
        issues.extend(_check_system_characteristics(ssp["system-characteristics"]))

    # 7. System implementation
    if "system-implementation" in ssp:
        issues.extend(_check_system_implementation(ssp["system-implementation"]))

    # 8. Control implementation
    if "control-implementation" in ssp:
        issues.extend(_check_control_implementation(ssp["control-implementation"]))

    # 9. Trestle round-trip (type validation)
    issues.extend(_check_trestle_roundtrip(ssp))

    passed = not any(i.severity == "error" for i in issues)
    return ValidationReport(passed=passed, issues=issues)


def validate_ssp_dict(ssp_dict: dict) -> ValidationReport:
    """Validate an already-parsed SSP dict (without a file)."""
    import tempfile, json
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"system-security-plan": ssp_dict}, f)
        tmp = f.name
    return validate_ssp_file(tmp)
