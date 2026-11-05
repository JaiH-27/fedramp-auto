"""
fedramp_auto.dashboard.view_model
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Turns scan results into the data the dashboard page renders.

``scan_result.json`` lists gaps but not the KSIs that passed, so the full KSI
list comes from the catalogue for the scan's baseline.  A scan's own gaps stay
authoritative: a gap whose KSI has since left the catalogue is still shown.

Source paths are cut down to the part that differs between files.  The exported
page is meant to be shared, and absolute paths would reveal local usernames.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from fedramp_auto.dashboard.loader import ScanGroup
from fedramp_auto.gaps.detector import ksis_for_baseline

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low")
_PATH_SEPARATOR = re.compile(r"[\\/]+")


def _shorten_paths(paths: set[str]) -> dict[str, str]:
    """Map each path to itself minus the leading folders all paths share."""
    split = {p: _PATH_SEPARATOR.split(p) for p in paths}
    if not split:
        return {}
    shared = 0
    for column in zip(*(parts[:-1] for parts in split.values()), strict=False):
        if len(set(column)) > 1:
            break
        shared += 1
    return {path: "/".join(parts[shared:]) for path, parts in split.items()}


def _resources_by_control(scan: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    resources = scan.get("resources", [])
    short = _shorten_paths({str(r.get("source_file", "")) for r in resources})
    by_control: dict[str, list[dict[str, str]]] = {}
    for resource in resources:
        for control in resource.get("controls", []):
            by_control.setdefault(control["control_id"].upper(), []).append({
                "identifier": resource.get("identifier", ""),
                "file": short[str(resource.get("source_file", ""))],
                "rationale": control.get("rationale", ""),
                "source": control.get("source", ""),
            })
    return by_control


def _ksi_rows(scan: dict[str, Any]) -> list[dict[str, Any]]:
    gaps = {g["ksi_id"]: g for g in scan.get("gaps", [])}
    by_control = _resources_by_control(scan)

    def controls(control_ids: Iterable[str]) -> list[dict[str, Any]]:
        return [{"id": c, "resources": by_control.get(c.upper(), [])} for c in control_ids]

    rows = [
        {
            "ksi_id": ksi.ksi_id,
            "title": ksi.title,
            "description": ksi.description,
            "severity": ksi.severity.value,
            "satisfied": ksi.ksi_id not in gaps,
            "controls": controls(ksi.control_ids),
        }
        for ksi in ksis_for_baseline(scan["baseline"])
    ]
    known = {row["ksi_id"] for row in rows}
    rows.extend(
        {
            "ksi_id": ksi_id,
            "title": gap.get("title", ""),
            "description": "",
            "severity": gap.get("severity", "low"),
            "satisfied": False,
            "controls": controls(gap.get("missing_controls", [])),
        }
        for ksi_id, gap in gaps.items()
        if ksi_id not in known
    )
    return rows


def _remediations(scan: dict[str, Any]) -> list[dict[str, Any]]:
    gaps = {g["ksi_id"]: g for g in scan.get("gaps", [])}
    rows = []
    for rem in scan.get("remediations", []):
        gap = gaps.get(rem.get("ksi_id"), {})
        rows.append({
            "ksi_id": rem.get("ksi_id", ""),
            "title": gap.get("title", ""),
            "severity": gap.get("severity", "low"),
            "risk": rem.get("risk_explanation", ""),
            "action": rem.get("remediation_action", ""),
            "snippet": rem.get("terraform_snippet", ""),
            # Results saved before these keys existed are always Terraform for AWS
            "language": rem.get("snippet_language", "hcl"),
            "cloud": rem.get("cloud", "aws"),
        })
    order = {severity: rank for rank, severity in enumerate(SEVERITIES)}
    return sorted(rows, key=lambda r: (order.get(r["severity"], 9), r["ksi_id"]))


def build_scan(scan: dict[str, Any]) -> dict[str, Any]:
    """The dashboard's view of one scan."""
    gaps = scan.get("gaps", [])
    return {
        "generated_at": scan["generated_at"],
        "target": scan["target"],
        "baseline": scan["baseline"],
        "cloud": scan.get("cloud", "aws"),
        "coverage_pct": scan["coverage_pct"],
        "satisfied_ksi_count": scan.get("satisfied_ksi_count", 0),
        "total_ksi_count": scan.get("total_ksi_count", 0),
        "resource_count": len(scan.get("resources", [])),
        "gap_count": len(gaps),
        "gaps_by_severity": {
            severity: sum(1 for g in gaps if g.get("severity") == severity)
            for severity in SEVERITIES
        },
        "ksis": _ksi_rows(scan),
        "remediations": _remediations(scan),
    }


def build_view_model(groups: list[ScanGroup]) -> dict[str, Any]:
    """Everything the page needs, as JSON-serialisable data."""
    return {
        "groups": [
            {"key": g.key, "target": g.target, "baseline": g.baseline,
             "scans": [build_scan(scan) for scan in g.scans]}
            for g in groups
        ],
    }
