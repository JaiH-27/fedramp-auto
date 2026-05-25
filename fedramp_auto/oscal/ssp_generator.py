"""
fedramp_auto.oscal.ssp_generator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Generates a FedRAMP 20x / RFC-0024 compliant OSCAL System Security Plan
(SSP) in JSON format from a completed gap analysis.

Uses the compliance-trestle SDK for correct OSCAL data model construction
so the output is guaranteed to be schema-valid OSCAL 1.x.

Produces:
  - system-security-plan JSON (OSCAL 1.1.x)
  - Pre-populated with FedRAMP Low baseline metadata
  - One ImplementedRequirement per satisfied control
  - Remarks populated with the rationale from the control mapper
  - Gap controls included as "not-satisfied" for full SSP coverage
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from trestle.oscal import ssp as ssp_model
from trestle.oscal import common

from fedramp_auto.gaps.detector import GapReport
from fedramp_auto.mapper.control_mapper import ResourceMapping


# ── FedRAMP baseline profile URIs ────────────────────────────────────────────
_FEDRAMP_PROFILE_URIS = {
    "low": (
        "https://raw.githubusercontent.com/GSA/fedramp-automation/master/"
        "dist/content/rev5/baselines/json/FedRAMP_rev5_LOW-baseline_profile.json"
    ),
    "moderate": (
        "https://raw.githubusercontent.com/GSA/fedramp-automation/master/"
        "dist/content/rev5/baselines/json/FedRAMP_rev5_MODERATE-baseline_profile.json"
    ),
}

_OSCAL_VERSION = "1.1.2"
_FEDRAMP_NS = "https://fedramp.gov/ns/oscal"


# ── Helper factories ──────────────────────────────────────────────────────────

def _uuid() -> str:
    return str(uuid.uuid4())


def _prop(name: str, value: str, ns: str | None = None) -> common.Property:
    kwargs: dict[str, Any] = {"name": name, "value": value}
    if ns:
        kwargs["ns"] = ns  # type: ignore[assignment]
    return common.Property(**kwargs)


def _fedramp_prop(name: str, value: str) -> common.Property:
    return _prop(name, value, ns=_FEDRAMP_NS)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── Control ID normalisation ──────────────────────────────────────────────────
# OSCAL control IDs use lowercase kebab-case: "ac-2", "sc-28", "au-9(1)"

def _oscal_control_id(control_id: str) -> str:
    """Convert 'AC-2' → 'ac-2', 'SC-28(1)' → 'sc-28.1' per OSCAL convention."""
    cid = control_id.lower().strip()
    # OSCAL uses dot notation for enhancements: ac-2(1) → ac-2.1
    cid = cid.replace("(", ".").replace(")", "")
    return cid


# ── SSP builder ───────────────────────────────────────────────────────────────

@dataclass
class SystemInfo:
    """Minimal system metadata required for a valid SSP."""
    system_name: str = "Unnamed System"
    system_name_short: str = "SYS"
    description: str = "System description pending completion."
    version: str = "0.1"
    org_name: str = "Your Organization"
    org_email: str = "security@example.com"


def build_ssp(
    gap_report: GapReport,
    resource_mappings: list[ResourceMapping],
    system_info: SystemInfo | None = None,
    baseline: str = "low",
) -> ssp_model.SystemSecurityPlan:
    """
    Build a trestle SystemSecurityPlan object from a gap report and mappings.

    Parameters
    ----------
    gap_report:
        Output of fedramp_auto.gaps.detector.detect_gaps().
    resource_mappings:
        Output of fedramp_auto.mapper.control_mapper.ControlMapper.map_resources().
    system_info:
        Optional system metadata. Defaults to placeholder values.
    baseline:
        "low" or "moderate" — selects the FedRAMP profile URI.

    Returns
    -------
    A trestle SystemSecurityPlan ready for .json() serialisation.
    """
    si = system_info or SystemInfo()
    baseline = baseline.lower()
    profile_href = _FEDRAMP_PROFILE_URIS.get(baseline, _FEDRAMP_PROFILE_URIS["low"])

    # ── UUIDs (stable per run for now; make deterministic via system name hash later)
    ssp_uuid = _uuid()
    org_party_uuid = _uuid()
    owner_role_uuid = "system-owner"
    aws_component_uuid = _uuid()
    this_system_uuid = _uuid()

    # ── Metadata ──────────────────────────────────────────────────────────────
    metadata = common.Metadata(
        title=f"{si.system_name} — System Security Plan",
        last_modified=_now(),
        version=si.version,
        oscal_version=_OSCAL_VERSION,  # type: ignore[arg-type]
        roles=[
            common.Role(id="system-owner", title="System Owner"),
            common.Role(id="information-system-security-officer", title="ISSO"),
            common.Role(id="authorizing-official", title="Authorizing Official"),
        ],
        parties=[
            common.Parties(
                uuid=org_party_uuid,
                type="organization",
                name=si.org_name,
                email_addresses=[si.org_email],  # type: ignore[list-item]
            )
        ],
        responsible_parties=[
            common.ResponsibleParty(
                role_id=owner_role_uuid,
                party_uuids=[org_party_uuid],
            )
        ],
        props=[
            _fedramp_prop("marking", "CUI"),
        ],
    )

    # ── Import profile (FedRAMP baseline) ────────────────────────────────────
    import_profile = ssp_model.ImportProfile(href=profile_href)

    # ── System characteristics ────────────────────────────────────────────────
    # Map baseline to FIPS-199 impact levels
    impact_level = "fips-199-low" if baseline == "low" else "fips-199-moderate"

    system_characteristics = ssp_model.SystemCharacteristics(
        system_ids=[
            common.SystemId(id=f"fedramp-auto-{ssp_uuid[:8]}")
        ],
        system_name=si.system_name,  # type: ignore[arg-type]
        system_name_short=si.system_name_short,  # type: ignore[arg-type]
        description=si.description,
        security_sensitivity_level=impact_level,  # type: ignore[arg-type]
        security_impact_level=ssp_model.SecurityImpactLevel(
            security_objective_confidentiality=impact_level,  # type: ignore[arg-type]
            security_objective_integrity=impact_level,  # type: ignore[arg-type]
            security_objective_availability=impact_level,  # type: ignore[arg-type]
        ),
        system_information=ssp_model.SystemInformation(
            information_types=[
                ssp_model.InformationType(
                    uuid=_uuid(),
                    title="General Support System Information",
                    description=(
                        "Information processed, stored, and transmitted by this system. "
                        "Classification pending data categorisation review."
                    ),
                    confidentiality_impact=ssp_model.Impact(base=impact_level),  # type: ignore[arg-type]
                    integrity_impact=ssp_model.Impact(base=impact_level),  # type: ignore[arg-type]
                    availability_impact=ssp_model.Impact(base=impact_level),  # type: ignore[arg-type]
                )
            ]
        ),
        status=ssp_model.Status1(
            state="under-development",
            remarks="SSP generated by FedRAMP-Auto. Review and update prior to submission.",
        ),
        authorization_boundary=ssp_model.AuthorizationBoundary(
            description=(
                "The authorization boundary encompasses all AWS infrastructure "
                "resources defined in the Terraform configuration analysed by "
                "FedRAMP-Auto. See attached architecture diagram for details."
            )
        ),
        props=[
            _fedramp_prop("authorization-type", "fedramp-agency"),
            _fedramp_prop("identity-assurance-level", "2"),
            _fedramp_prop("authenticator-assurance-level", "2"),
            _fedramp_prop("federation-assurance-level", "2"),
        ],
    )

    # ── System implementation ─────────────────────────────────────────────────
    # One component per distinct resource type found in the scan
    resource_types = sorted({rm.resource.resource_type for rm in resource_mappings})

    components: list[common.SystemComponent] = [
        # "This System" component — required by FedRAMP
        common.SystemComponent(
            uuid=this_system_uuid,
            type="this-system",
            title="This System",
            description="The overall system boundary as defined in the authorization boundary.",
            status=common.Status(state="operational"),
        ),
        # AWS cloud component
        common.SystemComponent(
            uuid=aws_component_uuid,
            type="service",
            title="Amazon Web Services (AWS)",
            description=(
                "AWS cloud infrastructure providing compute, storage, networking, "
                "and security services within the FedRAMP authorization boundary."
            ),
            status=common.Status(state="operational"),
            props=[
                _fedramp_prop("implementation-point", "external"),
                _fedramp_prop("leveraged-authorization-uuid", _uuid()),
                _prop("inherited-uuid", _uuid()),
            ],
        ),
    ]

    # Add one component per resource type found
    resource_type_uuids: dict[str, str] = {}
    for rt in resource_types:
        comp_uuid = _uuid()
        resource_type_uuids[rt] = comp_uuid
        # Human-friendly title: aws_s3_bucket → "AWS S3 Bucket"
        title = rt.replace("aws_", "AWS ").replace("_", " ").title()
        components.append(
            common.SystemComponent(
                uuid=comp_uuid,
                type="software",
                title=title,
                description=f"Terraform-managed {title} resource(s) within the system boundary.",
                status=common.Status(state="operational"),
                props=[
                    _prop("resource-type", rt),
                    _fedramp_prop("implementation-point", "internal"),
                ],
            )
        )

    users = [
        common.SystemUser(
            uuid=_uuid(),
            title="System Administrator",
            description="Personnel with privileged access to manage infrastructure resources.",
            role_ids=["system-owner"],
        ),
        common.SystemUser(
            uuid=_uuid(),
            title="End User",
            description="General users of the system with standard access privileges.",
        ),
    ]

    system_implementation = ssp_model.SystemImplementation(
        users=users,
        components=components,
    )

    # ── Control implementation ────────────────────────────────────────────────
    # Build a lookup: control_id → list of (rationale, resource_identifier)
    control_evidence: dict[str, list[dict[str, str]]] = {}
    for rm in resource_mappings:
        for ctrl in rm.controls:
            cid = _oscal_control_id(ctrl.control_id)
            if cid not in control_evidence:
                control_evidence[cid] = []
            control_evidence[cid].append({
                "rationale": ctrl.rationale,
                "resource": rm.resource.identifier,
                "resource_type": rm.resource.resource_type,
                "source": ctrl.source,
            })

    # Satisfied controls → implemented requirements
    implemented_requirements: list[ssp_model.ImplementedRequirement] = []

    satisfied_ids = {_oscal_control_id(c) for c in gap_report.satisfied_control_ids}
    # All controls to document = satisfied + gaps (with not-satisfied status)
    all_control_ids = set(satisfied_ids)
    for gap in gap_report.gaps:
        for cid in gap.missing_controls:
            all_control_ids.add(_oscal_control_id(cid))

    for control_id in sorted(all_control_ids):
        is_satisfied = control_id in satisfied_ids
        evidence_list = control_evidence.get(control_id, [])

        # Build remarks from evidence
        if evidence_list:
            remarks_lines = ["Infrastructure evidence:"]
            for ev in evidence_list[:5]:  # cap at 5 to keep SSP readable
                remarks_lines.append(f"  • {ev['resource']}: {ev['rationale']}")
            remarks = "\n".join(remarks_lines)
        else:
            remarks = (
                "No direct infrastructure evidence found for this control. "
                "Manual implementation statement required."
            )

        # Build by_components referencing the relevant AWS components
        by_components: list[ssp_model.ByComponent] = []
        seen_types: set[str] = set()
        for ev in evidence_list:
            rt = ev["resource_type"]
            if rt in seen_types:
                continue
            seen_types.add(rt)
            comp_uuid = resource_type_uuids.get(rt, aws_component_uuid)
            impl_status = (
                common.ImplementationStatus(state="implemented")
                if is_satisfied
                else common.ImplementationStatus(
                    state="planned",
                    remarks="Gap identified by FedRAMP-Auto. Remediation required.",
                )
            )
            by_components.append(
                ssp_model.ByComponent(
                    component_uuid=comp_uuid,
                    uuid=_uuid(),
                    description=ev["rationale"],
                    implementation_status=impl_status,
                )
            )

        # If no by_components, add a this-system placeholder
        if not by_components:
            by_components.append(
                ssp_model.ByComponent(
                    component_uuid=this_system_uuid,
                    uuid=_uuid(),
                    description=(
                        "Implementation statement pending. "
                        "This control must be addressed before FedRAMP authorization."
                    ),
                    implementation_status=common.ImplementationStatus(
                        state="not-implemented",
                        remarks="No automated evidence found. Manual review required.",
                    ),
                )
            )

        props = [
            _fedramp_prop(
                "implementation-status",
                "implemented" if is_satisfied else "planned",
            )
        ]

        implemented_requirements.append(
            ssp_model.ImplementedRequirement(
                uuid=_uuid(),
                control_id=control_id,  # type: ignore[arg-type]
                props=props,
                by_components=by_components,
                remarks=remarks,
            )
        )

    control_implementation = ssp_model.ControlImplementation(
        description=(
            f"This section documents the implementation of {len(implemented_requirements)} "
            f"NIST 800-53 Rev5 controls for the FedRAMP {baseline.upper()} baseline. "
            f"Evidence was auto-generated by FedRAMP-Auto from Terraform infrastructure code."
        ),
        implemented_requirements=implemented_requirements,
    )

    # ── Assemble SSP ──────────────────────────────────────────────────────────
    return ssp_model.SystemSecurityPlan(
        uuid=ssp_uuid,
        metadata=metadata,
        import_profile=import_profile,
        system_characteristics=system_characteristics,
        system_implementation=system_implementation,
        control_implementation=control_implementation,
    )


# ── Serialisation ─────────────────────────────────────────────────────────────

def write_ssp(
    ssp: ssp_model.SystemSecurityPlan,
    output_path: str | Path,
) -> Path:
    """
    Serialise the SSP to a JSON file wrapped in the OSCAL top-level envelope.

    The envelope format is:
      {"system-security-plan": { ...ssp fields... }}

    This matches what FedRAMP's validator and the official OSCAL schema expect.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # trestle models serialise via .dict() + manual JSON dump
    ssp_dict = json.loads(ssp.json(exclude_none=True, by_alias=True))
    envelope = {"system-security-plan": ssp_dict}

    output_path.write_text(json.dumps(envelope, indent=2))
    return output_path


# ── Public convenience function ───────────────────────────────────────────────

def generate_ssp(
    gap_report: GapReport,
    resource_mappings: list[ResourceMapping],
    output_path: str | Path,
    system_info: SystemInfo | None = None,
) -> Path:
    """
    End-to-end: build and write an OSCAL SSP JSON file.

    Parameters
    ----------
    gap_report:
        From fedramp_auto.gaps.detector.detect_gaps().
    resource_mappings:
        From fedramp_auto.mapper.control_mapper.ControlMapper.map_resources().
    output_path:
        Where to write the SSP JSON file (e.g. "./output/ssp.json").
    system_info:
        Optional system metadata.

    Returns
    -------
    Path to the written file.

    Example
    -------
    >>> path = generate_ssp(gap_report, mappings, "./output/ssp.json")
    >>> print(f"SSP written to {path}")
    """
    plan = build_ssp(
        gap_report=gap_report,
        resource_mappings=resource_mappings,
        system_info=system_info,
        baseline=gap_report.baseline,
    )
    return write_ssp(plan, output_path)
