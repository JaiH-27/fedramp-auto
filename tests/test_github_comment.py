"""Tests for fedramp_auto.ci.github_comment (GitHub API calls are faked)"""

import io
import sys
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from fedramp_auto.ci import github_comment as gc

MARKER = "<!-- fedramp-auto:pr-comment:default -->"
BODY = f"{MARKER}\n### FedRAMP-Auto · LOW baseline\n"
API = "https://api.github.com"


class FakeGitHub:
    """Records calls; serves PR comments across pages."""

    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def __call__(self, method, url, token, payload=None):
        self.calls.append((method, url, payload))
        if method == "GET":
            page = int(url.split("page=")[-1]) if "&page=" in url else 1
            nxt = page + 1
            link = (f'<{API}/repos/o/r/issues/7/comments?per_page=100&page={nxt}>; rel="next"'
                    if nxt <= len(self.pages) else "")
            return self.pages[page - 1], {"Link": link}
        if method == "POST":
            return {"id": 999}, {}
        return {}, {}


def test_next_page_parsing():
    link = ('<https://api.github.com/x?page=2>; rel="next", '
            '<https://api.github.com/x?page=5>; rel="last"')
    assert gc.next_page(link) == "https://api.github.com/x?page=2"
    assert gc.next_page('<https://api.github.com/x?page=1>; rel="prev"') is None
    assert gc.next_page(None) is None


def test_creates_comment_when_none_exists(monkeypatch):
    fake = FakeGitHub([[{"id": 1, "body": "LGTM"}]])
    monkeypatch.setattr(gc, "_request", fake)
    assert gc.upsert_comment("o/r", 7, BODY, "t") == ("created", 999)
    method, url, payload = fake.calls[-1]
    assert method == "POST" and url.endswith("/repos/o/r/issues/7/comments")
    assert payload == {"body": BODY}


def test_updates_existing_comment_on_a_later_page(monkeypatch):
    fake = FakeGitHub([
        [{"id": 1, "body": "first"}],
        [{"id": 2, "body": "<!-- fedramp-auto:pr-comment:other -->\nx"},
         {"id": 3, "body": f"{MARKER}\nold result"}],
    ])
    monkeypatch.setattr(gc, "_request", fake)
    assert gc.upsert_comment("o/r", 7, BODY, "t") == ("updated", 3)
    assert [c[0] for c in fake.calls] == ["GET", "GET", "PATCH"]
    assert fake.calls[-1][1].endswith("/repos/o/r/issues/comments/3")


def test_body_must_carry_marker():
    with pytest.raises(ValueError):
        gc.upsert_comment("o/r", 7, "no marker here", "t")


def _env(monkeypatch, **overrides):
    values = {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "o/r", "PR_NUMBER": "7", **overrides}
    for key, value in values.items():
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)


def test_main_posts(monkeypatch, tmp_path, capsys):
    _env(monkeypatch)
    monkeypatch.setattr(gc, "_request", FakeGitHub([[]]))
    path = tmp_path / "c.md"
    path.write_text(BODY, encoding="utf-8")
    assert gc.main([str(path)]) == 0
    assert "PR comment created: 999" in capsys.readouterr().out


def test_main_skips_without_pr_number(monkeypatch, tmp_path, capsys):
    _env(monkeypatch, PR_NUMBER=None)
    path = tmp_path / "c.md"
    path.write_text(BODY, encoding="utf-8")
    assert gc.main([str(path)]) == 0
    assert "::warning::Not posting PR comment: PR_NUMBER not set" in capsys.readouterr().out


@pytest.mark.parametrize(("code", "exit_code"), [(403, 0), (404, 0), (500, 1)])
def test_main_http_errors(monkeypatch, tmp_path, code, exit_code):
    _env(monkeypatch)

    def boom(*_args, **_kwargs):
        raise urllib.error.HTTPError("u", code, "err", {}, io.BytesIO())

    monkeypatch.setattr(gc, "_request", boom)
    path = tmp_path / "c.md"
    path.write_text(BODY, encoding="utf-8")
    assert gc.main([str(path)]) == exit_code
