"""`fedramp-auto dashboard` and the loopback server behind it"""

import http.client
import shutil
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from typer.testing import CliRunner

from fedramp_auto.cli.main import app
from fedramp_auto.dashboard.server import HOST, make_server

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


@pytest.fixture(scope="module")
def output(tmp_path_factory):
    """One output folder holding real scans of all three fixture formats."""
    root = tmp_path_factory.mktemp("dashboard")
    for name in ("terraform", "arm", "cdk"):
        result = runner.invoke(app, ["scan", str(FIXTURES / name), "--no-llm",
                                     "-o", str(root / name)])
        assert result.exit_code in (0, 2), result.output
    return root


@pytest.fixture
def server():
    calls = []

    def build_page() -> str:
        calls.append(1)
        return f"page {len(calls)}"

    httpd = make_server(build_page)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()


def _get(httpd, path="/", host=None):
    conn = http.client.HTTPConnection(HOST, httpd.server_address[1], timeout=5)
    conn.putrequest("GET", path, skip_host=True)
    conn.putheader("Host", host or f"{HOST}:{httpd.server_address[1]}")
    conn.endheaders()
    response = conn.getresponse()
    body = response.read().decode("utf-8")
    conn.close()
    return response.status, body


def test_export_writes_a_page_covering_all_three_fixtures(output, tmp_path):
    page = tmp_path / "dashboard.html"
    result = runner.invoke(app, ["dashboard", str(output), "--export", str(page)])
    assert result.exit_code == 0, result.output
    html = page.read_text(encoding="utf-8")
    for target in ("terraform · low", "arm · low", "cdk · low"):
        assert target in html


def test_export_creates_missing_folders(output, tmp_path):
    page = tmp_path / "reports" / "q4" / "dashboard.html"
    assert runner.invoke(app, ["dashboard", str(output), "--export", str(page)]).exit_code == 0
    assert page.exists()


def test_missing_path_is_an_error(tmp_path):
    result = runner.invoke(app, ["dashboard", str(tmp_path / "nope")])
    assert result.exit_code == 1


def test_folder_without_scans_is_an_error(tmp_path):
    result = runner.invoke(app, ["dashboard", str(tmp_path)])
    assert result.exit_code == 1
    assert "No scan results" in result.output


def test_broken_results_are_reported_but_do_not_stop_the_dashboard(output, tmp_path):
    shutil.copytree(output / "arm", tmp_path / "arm")
    (tmp_path / "scan_result-broken.json").write_text("{", encoding="utf-8")
    page = tmp_path / "dashboard.html"
    result = runner.invoke(app, ["dashboard", str(tmp_path), "--export", str(page)])
    assert result.exit_code == 0
    assert "scan_result-broken.json" in result.output.replace("\n", "")


def test_server_only_listens_on_loopback(server):
    assert server.server_address[0] == "127.0.0.1"


def test_server_rebuilds_the_page_on_each_request(server):
    assert _get(server) == (200, "page 1")
    assert _get(server) == (200, "page 2")


def test_server_accepts_localhost_with_or_without_a_port(server):
    assert _get(server, host="localhost")[0] == 200
    assert _get(server, host="localhost:8765")[0] == 200


def test_server_refuses_foreign_hosts(server):
    assert _get(server, host="evil.example:8765")[0] == 403


def test_server_serves_nothing_but_the_page(server):
    assert _get(server, "/scan_result.json")[0] == 404
    assert _get(server, "/../../etc/passwd")[0] == 404
