"""
fedramp_auto.dashboard.loader
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Finds the ``scan_result*.json`` files under a directory and groups them into
projects, oldest scan first.

``scan`` writes each result twice (``scan_result.json`` and a copy in
``history/``), so results are de-duplicated.  Results saved before
``generated_at`` and ``target`` existed fall back to the file's modification
time and its directory name.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass
class ScanGroup:
    """Every scan of one target at one baseline, oldest first."""

    target: str
    baseline: str
    scans: list[dict[str, Any]] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.target} · {self.baseline}"


@dataclass
class LoadResult:
    groups: list[ScanGroup] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _result_files(root: Path) -> list[Path]:
    return [root] if root.is_file() else sorted(root.rglob("scan_result*.json"))


def _read_result(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "gaps" not in data or "coverage_pct" not in data:
        raise ValueError("not a FedRAMP-Auto scan result")
    return data


def _default_target(path: Path) -> str:
    folder = path.parent.parent if path.parent.name == "history" else path.parent
    return folder.resolve().name


def _modified_at(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, UTC).isoformat()


def _timestamp(scan: dict[str, Any]) -> datetime:
    when = datetime.fromisoformat(scan["generated_at"])
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def load_scans(root: str | Path) -> LoadResult:
    """Load every scan result under *root* (a directory or a single file)."""
    loaded = LoadResult()
    groups: dict[tuple[str, str], ScanGroup] = {}
    seen: set[tuple[str, str, str]] = set()

    for path in _result_files(Path(root)):
        try:
            data = _read_result(path)
            target = str(data.get("target") or _default_target(path))
            baseline = str(data.get("baseline", "low"))
            generated_at = str(data.get("generated_at") or _modified_at(path))
            datetime.fromisoformat(generated_at)
        except (OSError, ValueError) as exc:  # JSONDecodeError is a ValueError
            loaded.warnings.append(f"Skipped {path}: {exc}")
            continue

        if (target, baseline, generated_at) in seen:
            continue
        seen.add((target, baseline, generated_at))

        group = groups.setdefault((target, baseline), ScanGroup(target, baseline))
        group.scans.append({**data, "target": target, "baseline": baseline,
                            "generated_at": generated_at})

    for group in groups.values():
        group.scans.sort(key=_timestamp)
    loaded.groups = sorted(groups.values(), key=lambda g: g.key)
    return loaded
