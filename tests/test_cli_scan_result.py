"""Metadata `fedramp-auto scan` records in scan_result.json"""

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from typer.testing import CliRunner

from fedramp_auto.cli.main import app

FIXTURES = Path(__file__).parent / "fixtures"


def _scan(out: Path) -> dict:
    result = CliRunner().invoke(app, ["scan", str(FIXTURES / "terraform"), "--no-llm",
                                      "-o", str(out)])
    assert result.exit_code in (0, 2), result.output
    return json.loads((out / "scan_result.json").read_text())


def test_scan_result_records_when_it_was_generated(tmp_path):
    generated = datetime.fromisoformat(_scan(tmp_path)["generated_at"])
    assert generated.tzinfo is not None
    assert datetime.now(UTC) - generated < timedelta(minutes=1)


def test_scan_result_names_the_scanned_directory_without_its_full_path(tmp_path):
    assert _scan(tmp_path)["target"] == "terraform"


def test_report_still_reads_results_saved_without_the_new_fields(tmp_path):
    data = _scan(tmp_path)
    del data["generated_at"], data["target"]
    legacy = tmp_path / "legacy.json"
    legacy.write_text(json.dumps(data))
    assert CliRunner().invoke(app, ["report", str(legacy)]).exit_code == 0


def test_each_scan_keeps_a_copy_in_history(tmp_path):
    first = _scan(tmp_path)
    second = _scan(tmp_path)
    archived = [json.loads(p.read_text()) for p in sorted((tmp_path / "history").glob("*.json"))]
    assert [a["generated_at"] for a in archived] == [first["generated_at"],
                                                     second["generated_at"]]
