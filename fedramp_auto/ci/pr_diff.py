"""
fedramp_auto.ci.pr_diff
~~~~~~~~~~~~~~~~~~~~~~~
Compares two ``scan_result.json`` files — the pull request head against its
base branch — so CI can report what a change did to FedRAMP compliance
rather than restating every pre-existing gap.

Gaps are keyed by KSI ID:
  - new       : open on head, not open on base (the PR introduced or exposed it)
  - resolved  : open on base, closed on head
  - unchanged : open on both

Without a base result (first adoption, push builds) every open gap counts as
new, so the "new-critical" policy degrades to "any-critical".
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

FailPolicy = Literal["new-critical", "any-critical", "never"]
FAIL_POLICIES: tuple[str, ...] = ("new-critical", "any-critical", "never")

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class ScanDiff:
    """What a pull request changed, KSI by KSI."""

    head: dict[str, Any]
    base: dict[str, Any] | None
    new_gaps: list[dict[str, Any]] = field(default_factory=list)
    resolved_gaps: list[dict[str, Any]] = field(default_factory=list)
    unchanged_gaps: list[dict[str, Any]] = field(default_factory=list)

    @property
    def has_base(self) -> bool:
        return self.base is not None

    @property
    def coverage_head(self) -> float:
        return float(self.head.get("coverage_pct", 0.0))

    @property
    def coverage_base(self) -> float | None:
        return None if self.base is None else float(self.base.get("coverage_pct", 0.0))

    @property
    def coverage_delta(self) -> float | None:
        base = self.coverage_base
        return None if base is None else round(self.coverage_head - base, 1)

    @property
    def open_gaps(self) -> list[dict[str, Any]]:
        return _sorted(self.new_gaps + self.unchanged_gaps)

    @property
    def new_critical_gaps(self) -> list[dict[str, Any]]:
        return [g for g in self.new_gaps if g.get("severity") == "critical"]

    @property
    def critical_gaps(self) -> list[dict[str, Any]]:
        return [g for g in self.open_gaps if g.get("severity") == "critical"]

    def summary(self, policy: FailPolicy) -> dict[str, Any]:
        """Machine-readable summary (written for the GitHub Action's outputs)."""
        return {
            "coverage_pct": self.coverage_head,
            "coverage_delta": self.coverage_delta,
            "open_gaps": len(self.open_gaps),
            "critical_gaps": len(self.critical_gaps),
            "new_gaps": len(self.new_gaps),
            "new_critical_gaps": len(self.new_critical_gaps),
            "resolved_gaps": len(self.resolved_gaps),
            "has_base": self.has_base,
            "fail_on": policy,
            "failed": should_fail(self, policy),
        }


def _sorted(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(gaps, key=lambda g: (_SEVERITY_ORDER.get(g.get("severity", ""), 9),
                                       g.get("ksi_id", "")))


def load_result(path: str | Path | None) -> dict[str, Any] | None:
    """Load a scan_result.json; None (or a missing file) means "no base"."""
    if path is None:
        return None
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def compare(head: dict[str, Any], base: dict[str, Any] | None) -> ScanDiff:
    """Diff the head scan against the base scan (or against nothing)."""
    head_gaps = {g["ksi_id"]: g for g in head.get("gaps", [])}
    if base is None:
        return ScanDiff(head=head, base=None, new_gaps=_sorted(list(head_gaps.values())))

    base_gaps = {g["ksi_id"]: g for g in base.get("gaps", [])}
    return ScanDiff(
        head=head,
        base=base,
        new_gaps=_sorted([g for k, g in head_gaps.items() if k not in base_gaps]),
        resolved_gaps=_sorted([g for k, g in base_gaps.items() if k not in head_gaps]),
        unchanged_gaps=_sorted([g for k, g in head_gaps.items() if k in base_gaps]),
    )


def should_fail(diff: ScanDiff, policy: FailPolicy) -> bool:
    """Apply the CI failure policy."""
    if policy == "never":
        return False
    if policy == "any-critical":
        return bool(diff.critical_gaps)
    if policy == "new-critical":
        return bool(diff.new_critical_gaps)
    raise ValueError(f"fail policy must be one of {FAIL_POLICIES}, got {policy!r}")
