"""Finding and grouping scan results for the dashboard"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fedramp_auto.dashboard.loader import load_scans


def _result(**extra) -> dict:
    return {"baseline": "low", "coverage_pct": 50.0, "gaps": [], **extra}


def _write(path: Path, data: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_latest_result_and_its_history_copy_count_once(tmp_path):
    scan = _result(target="infra", generated_at="2026-11-05T10:00:00+00:00")
    _write(tmp_path / "scan_result.json", scan)
    _write(tmp_path / "history" / "scan_result-1.json", scan)
    (group,) = load_scans(tmp_path).groups
    assert len(group.scans) == 1


def test_scans_are_ordered_oldest_first(tmp_path):
    for name, when in (("a", "2026-11-05T10:00:00+00:00"), ("b", "2026-11-01T10:00:00+00:00")):
        _write(tmp_path / f"scan_result-{name}.json", _result(target="infra", generated_at=when))
    (group,) = load_scans(tmp_path).groups
    assert [s["generated_at"][:10] for s in group.scans] == ["2026-11-01", "2026-11-05"]


def test_targets_and_baselines_get_separate_groups(tmp_path):
    when = "2026-11-05T10:00:00+00:00"
    _write(tmp_path / "a" / "scan_result.json", _result(target="a", generated_at=when))
    _write(tmp_path / "b" / "scan_result.json", _result(target="b", generated_at=when))
    _write(tmp_path / "c" / "scan_result.json",
           _result(target="b", baseline="moderate", generated_at=when))
    assert [g.key for g in load_scans(tmp_path).groups] == ["a · low", "b · low", "b · moderate"]


def test_legacy_results_fall_back_to_folder_name_and_file_time(tmp_path):
    path = _write(tmp_path / "prod" / "history" / "scan_result-old.json", _result())
    os.utime(path, (1_700_000_000, 1_700_000_000))
    (group,) = load_scans(tmp_path).groups
    assert group.target == "prod"
    assert group.scans[0]["generated_at"].startswith("2023-11-14")


def test_a_single_file_can_be_loaded(tmp_path):
    path = _write(tmp_path / "anything.json", _result(target="infra"))
    assert len(load_scans(path).groups) == 1


def test_unreadable_results_are_skipped_with_a_warning(tmp_path):
    (tmp_path / "scan_result.json").write_text("{broken", encoding="utf-8")
    _write(tmp_path / "scan_result-other.json", {"unrelated": True})
    _write(tmp_path / "scan_result-date.json", _result(generated_at="yesterday"))
    loaded = load_scans(tmp_path)
    assert loaded.groups == []
    assert len(loaded.warnings) == 3


def test_empty_directory_has_no_groups(tmp_path):
    assert load_scans(tmp_path).groups == []
