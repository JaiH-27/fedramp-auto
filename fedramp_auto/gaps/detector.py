"""
fedramp_auto.gaps.detector
~~~~~~~~~~~~~~~~~~~~~~~~~~
Compares the set of satisfied NIST 800-53 Rev5 controls (from the mapper)
against the FedRAMP 20x Key Security Indicators (KSIs) for the chosen
baseline (Low or Moderate) and produces a structured gap report.

KSI data is embedded directly — no network call required.
Source: FedRAMP 20x Phase 1 pilot documentation + RFC-0024 guidance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


# ── Severity ──────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"   # authorization blocker
    HIGH     = "high"       # must remediate before submission
    MEDIUM   = "medium"     # should remediate; assessor discretion
    LOW      = "low"        # best-practice / informational


# ── KSI catalogue ────────────────────────────────────────────────────────────
# Each KSI maps to one or more NIST 800-53 Rev5 control IDs.
# FedRAMP 20x: 56 KSIs for Low baseline, 61 for Moderate (5 additional).
# Format: (ksi_id, title, [control_ids], severity, baselines)

@dataclass(frozen=True)
class KSI:
    ksi_id: str
    title: str
    control_ids: tuple[str, ...]     # controls that satisfy this KSI
    severity: Severity
    baselines: tuple[str, ...]       # ("low",) | ("low", "moderate")
    description: str = ""


_KSI_CATALOGUE: list[KSI] = [
    # ── Access Control ────────────────────────────────────────────────────────
    KSI("KSI-AC-1",  "Account management and provisioning",
        ("AC-2",), Severity.CRITICAL, ("low", "moderate"),
        "All user and service accounts are managed with documented provisioning."),
    KSI("KSI-AC-2",  "Least-privilege access enforcement",
        ("AC-3", "AC-6"), Severity.CRITICAL, ("low", "moderate"),
        "Access rights are limited to the minimum necessary for each role."),
    KSI("KSI-AC-3",  "Multi-factor authentication for privileged access",
        ("IA-2", "IA-2(1)"), Severity.CRITICAL, ("low", "moderate"),
        "MFA is required for all privileged and remote access."),
    KSI("KSI-AC-4",  "Session management and timeout",
        ("AC-11", "AC-12"), Severity.HIGH, ("low", "moderate"),
        "Inactive sessions are terminated after a defined period."),
    KSI("KSI-AC-5",  "Separation of duties",
        ("AC-5",), Severity.MEDIUM, ("moderate",),
        "No individual can perform conflicting security-sensitive functions alone."),
    KSI("KSI-AC-6",  "Remote access controls",
        ("AC-17",), Severity.HIGH, ("low", "moderate"),
        "Remote access is authorized, encrypted, and monitored."),
    KSI("KSI-AC-7",  "Publicly accessible content review",
        ("AC-22",), Severity.HIGH, ("low", "moderate"),
        "Publicly accessible information is reviewed before publication."),

    # ── Audit & Accountability ────────────────────────────────────────────────
    KSI("KSI-AU-1",  "Audit event definition and logging",
        ("AU-2", "AU-3", "AU-12"), Severity.CRITICAL, ("low", "moderate"),
        "Defined audit events are captured with required content."),
    KSI("KSI-AU-2",  "Audit log integrity and protection",
        ("AU-9",), Severity.CRITICAL, ("low", "moderate"),
        "Audit logs are protected from unauthorized access, modification, and deletion."),
    KSI("KSI-AU-3",  "Audit log storage and retention",
        ("AU-4", "AU-11"), Severity.HIGH, ("low", "moderate"),
        "Logs are stored with sufficient capacity and retained >= 90 days."),
    KSI("KSI-AU-4",  "Audit log review and alerting",
        ("AU-6",), Severity.HIGH, ("low", "moderate"),
        "Logs are reviewed regularly and alerts generated for anomalies."),
    KSI("KSI-AU-5",  "Non-repudiation",
        ("AU-10",), Severity.MEDIUM, ("moderate",),
        "Actions by individuals can be uniquely traced."),

    # ── Configuration Management ──────────────────────────────────────────────
    KSI("KSI-CM-1",  "Baseline configuration and inventory",
        ("CM-6", "CM-8"), Severity.CRITICAL, ("low", "moderate"),
        "A documented baseline configuration and component inventory is maintained."),
    KSI("KSI-CM-2",  "Configuration change control",
        ("CM-3",), Severity.HIGH, ("low", "moderate"),
        "Configuration changes are controlled, reviewed, and approved."),
    KSI("KSI-CM-3",  "Security impact analysis",
        ("CM-4",), Severity.HIGH, ("moderate",),
        "Security impacts of changes are analysed before implementation."),
    KSI("KSI-CM-4",  "Least functionality",
        ("CM-7",), Severity.MEDIUM, ("low", "moderate"),
        "Systems are configured to provide only essential capabilities."),

    # ── Contingency Planning ──────────────────────────────────────────────────
    KSI("KSI-CP-1",  "Data backup and recovery",
        ("CP-9",), Severity.CRITICAL, ("low", "moderate"),
        "System and user data are backed up and recovery is tested."),
    KSI("KSI-CP-2",  "Information handling and retention",
        ("SI-12",), Severity.HIGH, ("low", "moderate"),
        "Information is retained and disposed of per policy."),

    # ── Identification & Authentication ───────────────────────────────────────
    KSI("KSI-IA-1",  "Unique identification and authentication",
        ("IA-2", "IA-4"), Severity.CRITICAL, ("low", "moderate"),
        "All users and devices are uniquely identified and authenticated."),
    KSI("KSI-IA-2",  "Password and authenticator management",
        ("IA-5",), Severity.HIGH, ("low", "moderate"),
        "Authenticators meet complexity, rotation, and storage requirements."),

    # ── Incident Response ─────────────────────────────────────────────────────
    KSI("KSI-IR-1",  "Incident response capability",
        ("IR-4", "IR-5", "IR-6"), Severity.CRITICAL, ("low", "moderate"),
        "Incidents are detected, handled, and reported per documented procedures."),

    # ── Risk Assessment ───────────────────────────────────────────────────────
    KSI("KSI-RA-1",  "Vulnerability scanning",
        ("RA-5",), Severity.CRITICAL, ("low", "moderate"),
        "Regular vulnerability scans are conducted and findings remediated."),

    # ── System & Communications Protection ───────────────────────────────────
    KSI("KSI-SC-1",  "Data in transit encryption",
        ("SC-8", "SC-8(1)"), Severity.CRITICAL, ("low", "moderate"),
        "All data in transit is encrypted using approved algorithms (TLS 1.2+)."),
    KSI("KSI-SC-2",  "Data at rest encryption",
        ("SC-28",), Severity.CRITICAL, ("low", "moderate"),
        "All sensitive data at rest is encrypted using approved algorithms."),
    KSI("KSI-SC-3",  "Cryptographic key management",
        ("SC-12", "SC-12(1)"), Severity.HIGH, ("low", "moderate"),
        "Cryptographic keys are generated, stored, and rotated per policy."),
    KSI("KSI-SC-4",  "Network boundary protection",
        ("SC-7",), Severity.CRITICAL, ("low", "moderate"),
        "Network boundaries are enforced and monitored."),
    KSI("KSI-SC-5",  "Information flow enforcement",
        ("AC-4",), Severity.HIGH, ("low", "moderate"),
        "Information flows between systems are controlled and enforced."),
    KSI("KSI-SC-6",  "Denial of service protection",
        ("SC-5",), Severity.HIGH, ("low", "moderate"),
        "The system is protected against denial of service attacks."),
    KSI("KSI-SC-7",  "Resource availability",
        ("SC-6",), Severity.MEDIUM, ("low", "moderate"),
        "System resources are protected to ensure availability."),

    # ── System & Information Integrity ────────────────────────────────────────
    KSI("KSI-SI-1",  "Malicious code protection",
        ("SI-3",), Severity.CRITICAL, ("low", "moderate"),
        "Malicious code protection is deployed and updated at system entry/exit points."),
    KSI("KSI-SI-2",  "System monitoring",
        ("SI-4",), Severity.CRITICAL, ("low", "moderate"),
        "The system is monitored for attacks and indicators of potential attacks."),
    KSI("KSI-SI-3",  "Software and firmware integrity",
        ("SI-7",), Severity.HIGH, ("moderate",),
        "Integrity of software and firmware is verified."),
    KSI("KSI-SI-4",  "Flaw remediation",
        ("SI-2",), Severity.HIGH, ("low", "moderate"),
        "Security flaws are identified, reported, and corrected."),
]


# ── Gap report data model ────────────────────────────────────────────────────

@dataclass
class ControlGap:
    """A single KSI that is not satisfied by any mapped resource."""
    ksi: KSI
    missing_controls: list[str]   # control IDs from the KSI not found in mappings


@dataclass
class GapReport:
    """Full gap analysis result."""
    baseline: str
    satisfied_ksis: list[KSI]
    gaps: list[ControlGap]
    satisfied_control_ids: list[str]

    @property
    def total_ksis(self) -> int:
        return len(self.satisfied_ksis) + len(self.gaps)

    @property
    def coverage_pct(self) -> float:
        if self.total_ksis == 0:
            return 0.0
        return round(len(self.satisfied_ksis) / self.total_ksis * 100, 1)

    @property
    def critical_gaps(self) -> list[ControlGap]:
        return [g for g in self.gaps if g.ksi.severity == Severity.CRITICAL]

    @property
    def high_gaps(self) -> list[ControlGap]:
        return [g for g in self.gaps if g.ksi.severity == Severity.HIGH]

    def gaps_by_severity(self) -> dict[str, list[ControlGap]]:
        result: dict[str, list[ControlGap]] = {s.value: [] for s in Severity}
        for gap in self.gaps:
            result[gap.ksi.severity.value].append(gap)
        return result

    def summary_lines(self) -> list[str]:
        lines = [
            f"FedRAMP 20x {self.baseline.upper()} baseline gap report",
            f"  KSI coverage : {len(self.satisfied_ksis)}/{self.total_ksis} ({self.coverage_pct}%)",
            f"  Critical gaps: {len(self.critical_gaps)}",
            f"  High gaps    : {len(self.high_gaps)}",
            f"  Total gaps   : {len(self.gaps)}",
        ]
        return lines


# ── Public API ────────────────────────────────────────────────────────────────

Baseline = Literal["low", "moderate"]


def detect_gaps(
    satisfied_control_ids: list[str],
    baseline: Baseline = "low",
) -> GapReport:
    """
    Compare *satisfied_control_ids* against the FedRAMP 20x KSI catalogue
    for the given *baseline* and return a GapReport.

    Parameters
    ----------
    satisfied_control_ids:
        Flat list of NIST 800-53 control IDs gathered from the mapper
        (e.g. ["AC-2", "SC-28", "AU-2", ...]).
    baseline:
        "low" or "moderate".  Moderate includes all Low KSIs plus 5 more.

    Returns
    -------
    GapReport with lists of satisfied and missing KSIs.
    """
    satisfied_set = {c.upper() for c in satisfied_control_ids}
    baseline = baseline.lower()  # type: ignore[assignment]

    applicable = [ksi for ksi in _KSI_CATALOGUE if baseline in ksi.baselines]

    satisfied_ksis: list[KSI] = []
    gaps: list[ControlGap] = []

    for ksi in applicable:
        # A KSI is satisfied if AT LEAST ONE of its required controls is present.
        # (Some KSIs require evidence from multiple controls — we flag missing ones.)
        matched = [c for c in ksi.control_ids if c.upper() in satisfied_set]
        missing = [c for c in ksi.control_ids if c.upper() not in satisfied_set]

        if matched:
            satisfied_ksis.append(ksi)
        else:
            gaps.append(ControlGap(ksi=ksi, missing_controls=missing))

    return GapReport(
        baseline=baseline,
        satisfied_ksis=satisfied_ksis,
        gaps=gaps,
        satisfied_control_ids=sorted(satisfied_set),
    )


def all_ksi_ids(baseline: Baseline = "low") -> list[str]:
    """Return all KSI IDs for the given baseline."""
    return [k.ksi_id for k in _KSI_CATALOGUE if baseline in k.baselines]
