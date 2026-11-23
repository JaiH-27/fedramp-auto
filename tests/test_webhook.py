"""Tests for fedramp_auto.integrations.webhook and the --webhook / notify CLI"""

import json
import sys
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from typer.testing import CliRunner

from fedramp_auto.cli.main import app
from fedramp_auto.integrations import webhook as wh

FIXTURES = Path(__file__).parent / "fixtures"
SECRET = "s3cret"


def _result(gaps, at="2026-11-20T10:00:00+00:00", target="infra", baseline="low",
            coverage=50.0):
    return {
        "generated_at": at, "target": target, "baseline": baseline, "cloud": "aws",
        "coverage_pct": coverage, "satisfied_ksi_count": 10, "total_ksi_count": 29,
        "resources": [{"identifier": "aws_s3_bucket.secret_name",
                       "source_file": "/home/me/infra/main.tf", "controls": []}],
        "gaps": [{"ksi_id": k, "title": f"title {k}", "severity": s,
                  "missing_controls": ["SC-28"]} for k, s in gaps],
        "remediations": [{"ksi_id": k, "risk_explanation": "risk", "remediation_action": "fix",
                          "terraform_snippet": "resource {}", "snippet_language": "hcl",
                          "source": "static", "cloud": "aws"} for k, _ in gaps],
    }


# ── Payload ───────────────────────────────────────────────────────────────────

def test_payload_diffs_against_previous_scan():
    prev = _result([("KSI-A", "high"), ("KSI-B", "critical")], coverage=40.0)
    cur = _result([("KSI-B", "critical"), ("KSI-C", "critical")], coverage=45.5)
    p = wh.build_payload(cur, prev, env={})
    assert [g["ksi_id"] for g in p["new_gaps"]] == ["KSI-C"]
    assert [g["ksi_id"] for g in p["resolved_gaps"]] == ["KSI-A"]
    assert [g["ksi_id"] for g in p["open_gaps"]] == ["KSI-B", "KSI-C"]
    assert p["summary"] == {"open_gaps": 2, "critical_gaps": 2, "new_gaps": 1,
                            "new_critical_gaps": 1, "resolved_gaps": 1, "has_previous": True}
    assert p["coverage"]["delta"] == 5.5
    assert p["new_gaps"][0]["remediation"]["remediation_action"] == "fix"
    assert "remediation" not in p["resolved_gaps"][0]
    assert p["event"] == wh.EVENT and "ci" not in p


def test_first_scan_treats_every_gap_as_new():
    p = wh.build_payload(_result([("KSI-A", "low")]), None, env={})
    assert p["summary"]["has_previous"] is False
    assert p["summary"]["new_gaps"] == 1 and p["coverage"]["delta"] is None


def test_payload_never_contains_resource_names_or_paths():
    body = wh.encode(wh.build_payload(_result([("KSI-A", "high")]), None, env={}))
    assert b"secret_name" not in body and b"/home/me" not in body
    assert b'"resources"' not in body


def test_github_actions_context_is_included():
    env = {"GITHUB_REPOSITORY": "o/r", "GITHUB_RUN_ID": "42", "GITHUB_SHA": "abc",
           "GITHUB_REF": "refs/heads/main"}
    ci = wh.build_payload(_result([]), None, env=env)["ci"]
    assert ci == {"repository": "o/r", "ref": "refs/heads/main", "sha": "abc",
                  "url": "https://github.com/o/r/actions/runs/42"}


def test_find_previous_picks_newest_earlier_scan_of_same_target_and_baseline(tmp_path):
    hist = tmp_path / "history"
    hist.mkdir()
    scans = {
        "a": _result([], at="2026-11-01T00:00:00+00:00"),
        "b": _result([], at="2026-11-02T00:00:00+00:00"),
        "other-target": _result([], at="2026-11-03T00:00:00+00:00", target="x"),
        "other-baseline": _result([], at="2026-11-03T00:00:00+00:00", baseline="moderate"),
        "current": _result([], at="2026-11-04T00:00:00+00:00"),
        "later": _result([], at="2026-11-05T00:00:00+00:00"),
    }
    for name, data in scans.items():
        (hist / f"scan_result-{name}.json").write_text(json.dumps(data))
    (hist / "scan_result-broken.json").write_text("{not json")
    found = wh.find_previous(scans["current"], hist)
    assert found["generated_at"] == "2026-11-02T00:00:00+00:00"
    assert wh.find_previous(scans["current"], tmp_path / "missing") is None


# ── Signing and delivery ──────────────────────────────────────────────────────

def test_sign_and_verify():
    body = b'{"a":1}'
    sig = wh.sign(body, SECRET)
    assert sig.startswith("sha256=") and len(sig) == 7 + 64
    assert wh.verify(body, SECRET, sig)
    assert not wh.verify(body + b" ", SECRET, sig)
    assert not wh.verify(body, "wrong", sig)


@pytest.mark.parametrize("url", ["ftp://x/y", "localhost:5678/webhook", "", "https://"])
def test_rejects_non_http_urls(url):
    with pytest.raises(wh.WebhookError):
        wh.validate_url(url)


def test_redact_url_drops_tokens():
    red = wh.redact_url("https://hooks.example.com/webhook/0f3e9a1b-token-abc?key=zzz")
    assert "token" not in red and "zzz" not in red and red.startswith("https://hooks.example.com")


def test_redact_url_keeps_the_port():
    assert wh.redact_url("http://localhost:5678/x") == "http://localhost:5678/x"


def test_notify_reports_an_unreadable_previous_scan(tmp_path):
    cur = tmp_path / "cur.json"
    cur.write_text(json.dumps(_result([])))
    bad = tmp_path / "bad.json"
    bad.write_text("")
    result = CliRunner().invoke(app, ["notify", str(cur), "--previous", str(bad),
                                      "--webhook", "http://127.0.0.1:9/x"])
    assert result.exit_code == 1
    assert "cannot read scan result" in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)


class _Receiver(BaseHTTPRequestHandler):
    received: list = []
    status = 200

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"]))
        # Keep the Message object: header lookups are case-insensitive, as in HTTP
        type(self).received.append((self.headers, body))
        self.send_response(type(self).status)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def receiver():
    _Receiver.received = []
    _Receiver.status = 200
    server = HTTPServer(("127.0.0.1", 0), _Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/webhook/fedramp", _Receiver
    server.shutdown()
    server.server_close()


def test_send_posts_signed_json(receiver):
    url, rx = receiver
    payload = wh.build_payload(_result([("KSI-A", "critical")]), None, env={})
    result = wh.send(url, payload, SECRET)
    assert result.status == 200 and result.attempts == 1
    headers, body = rx.received[0]
    assert headers["Content-Type"] == "application/json"
    assert headers[wh.EVENT_HEADER] == wh.EVENT
    assert wh.verify(body, SECRET, headers[wh.SIGNATURE_HEADER])
    assert json.loads(body) == payload


def test_send_without_secret_is_unsigned(receiver):
    url, rx = receiver
    wh.send(url, {"event": wh.EVENT}, None)
    assert wh.SIGNATURE_HEADER not in rx.received[0][0]


def test_4xx_is_not_retried(receiver):
    url, rx = receiver
    rx.status = 404
    with pytest.raises(wh.WebhookError, match="HTTP 404"):
        wh.send(url, {"event": wh.EVENT}, sleep=lambda s: None)
    assert len(rx.received) == 1


def test_5xx_and_network_errors_are_retried(monkeypatch):
    outcomes = [urllib.error.URLError("refused"),
                urllib.error.HTTPError("u", 503, "busy", {}, None), 200]
    delays = []

    def fake_post(url, body, headers, timeout):
        o = outcomes.pop(0)
        if isinstance(o, Exception):
            raise o
        return o

    monkeypatch.setattr(wh, "_post", fake_post)
    result = wh.send("https://example.com/hook", {"event": wh.EVENT}, sleep=delays.append)
    assert result.attempts == 3 and delays == [1.0, 2.0]


def test_gives_up_after_retries(monkeypatch):
    def fail(*a):
        raise urllib.error.URLError("refused")

    monkeypatch.setattr(wh, "_post", fail)
    with pytest.raises(wh.WebhookError, match="refused"):
        wh.send("https://example.com/hook", {}, retries=1, sleep=lambda s: None)


# ── CLI ───────────────────────────────────────────────────────────────────────

def test_scan_with_webhook_sends_diff_against_the_previous_scan(tmp_path, receiver):
    url, rx = receiver
    args = ["scan", str(FIXTURES / "terraform"), "--no-llm", "-o", str(tmp_path),
            "--webhook", url]
    first = CliRunner().invoke(app, args, env={"FEDRAMP_WEBHOOK_SECRET": SECRET})
    assert first.exit_code in (0, 2), first.output
    second = CliRunner().invoke(app, args, env={"FEDRAMP_WEBHOOK_SECRET": SECRET})
    assert second.exit_code == first.exit_code, second.output
    assert "Webhook sent" in second.output

    (h1, b1), (h2, b2) = rx.received
    p1, p2 = json.loads(b1), json.loads(b2)
    assert wh.verify(b2, SECRET, h2[wh.SIGNATURE_HEADER])
    assert p1["summary"]["has_previous"] is False
    assert p2["summary"]["has_previous"] is True
    assert p2["summary"]["new_gaps"] == 0 and p2["summary"]["resolved_gaps"] == 0
    assert p2["target"] == "terraform"


def test_scan_exit_code_unchanged_when_webhook_fails(tmp_path, monkeypatch):
    def fail(*a):
        raise urllib.error.URLError("refused")

    monkeypatch.setattr(wh, "_post", fail)
    monkeypatch.setattr(wh.time, "sleep", lambda s: None)
    plain = CliRunner().invoke(app, ["scan", str(FIXTURES / "terraform"), "--no-llm",
                                     "-o", str(tmp_path / "a")])
    hooked = CliRunner().invoke(app, ["scan", str(FIXTURES / "terraform"), "--no-llm",
                                      "-o", str(tmp_path / "b"),
                                      "--webhook", "http://127.0.0.1:9/x"])
    assert hooked.exit_code == plain.exit_code
    assert "Webhook not delivered" in hooked.output


def test_scan_rejects_bad_webhook_url_before_scanning(tmp_path):
    result = CliRunner().invoke(app, ["scan", str(FIXTURES / "terraform"), "--no-llm",
                                      "-o", str(tmp_path), "--webhook", "ftp://x"])
    assert result.exit_code == 1
    assert not (tmp_path / "scan_result.json").exists()


def test_notify_command(tmp_path, receiver):
    url, rx = receiver
    prev = tmp_path / "prev.json"
    cur = tmp_path / "cur.json"
    prev.write_text(json.dumps(_result([("KSI-A", "high")], at="2026-11-01T00:00:00+00:00")))
    cur.write_text(json.dumps(_result([("KSI-B", "critical")])))
    result = CliRunner().invoke(app, ["notify", str(cur), "--previous", str(prev),
                                      "--webhook", url])
    assert result.exit_code == 0, result.output
    payload = json.loads(rx.received[0][1])
    assert [g["ksi_id"] for g in payload["new_gaps"]] == ["KSI-B"]
    assert [g["ksi_id"] for g in payload["resolved_gaps"]] == ["KSI-A"]


def test_notify_fails_when_delivery_fails(tmp_path, receiver):
    url, rx = receiver
    rx.status = 400
    cur = tmp_path / "cur.json"
    cur.write_text(json.dumps(_result([])))
    assert CliRunner().invoke(app, ["notify", str(cur), "--webhook", url]).exit_code == 1


def test_notify_requires_a_webhook(tmp_path):
    cur = tmp_path / "cur.json"
    cur.write_text(json.dumps(_result([])))
    result = CliRunner().invoke(app, ["notify", str(cur)], env={"FEDRAMP_WEBHOOK_URL": ""})
    assert result.exit_code != 0
