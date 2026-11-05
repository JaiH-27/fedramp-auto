"""
fedramp_auto.ci.github_comment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Creates or updates FedRAMP-Auto's comment on a GitHub pull request.

The comment body's first line is its hidden marker
(``<!-- fedramp-auto:pr-comment:<id> -->``).  If a comment starting with
that marker already exists it is edited in place; otherwise a new one is
posted.  One comment per PR (per id), updated on every push.

Run from CI::

    GITHUB_TOKEN=... GITHUB_REPOSITORY=owner/repo PR_NUMBER=12 \\
        python -m fedramp_auto.ci.github_comment comment.md

A 403/404 (e.g. the read-only token GitHub gives pull requests from forks)
is reported as a warning, not a failure — the scan result still stands.
Uses only the standard library.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_API_URL = "https://api.github.com"
_NEXT_LINK = re.compile(r'<([^>]+)>;\s*rel="next"')


def _request(method: str, url: str, token: str, payload: dict | None = None
             ) -> tuple[Any, dict[str, str]]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "fedramp-auto",
        **({"Content-Type": "application/json"} if data else {}),
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8")
        return (json.loads(body) if body else None), dict(resp.headers)


def next_page(link_header: str | None) -> str | None:
    """URL of the next page from a GitHub ``Link`` header, if any."""
    if not link_header:
        return None
    match = _NEXT_LINK.search(link_header)
    return match.group(1) if match else None


def find_comment(repo: str, pr_number: int, marker: str, token: str,
                 api_url: str = DEFAULT_API_URL) -> int | None:
    """ID of the first PR comment whose body starts with *marker*."""
    url: str | None = f"{api_url}/repos/{repo}/issues/{pr_number}/comments?per_page=100"
    while url:
        comments, headers = _request("GET", url, token)
        for comment in comments or []:
            if str(comment.get("body", "")).startswith(marker):
                return int(comment["id"])
        url = next_page(headers.get("Link") or headers.get("link"))
    return None


def upsert_comment(repo: str, pr_number: int, body: str, token: str,
                   api_url: str = DEFAULT_API_URL) -> tuple[str, int]:
    """Update the existing FedRAMP-Auto comment or create one.

    Returns ("updated" | "created", comment_id).
    """
    marker = body.splitlines()[0] if body else ""
    if not marker.startswith("<!-- fedramp-auto:"):
        raise ValueError("comment body must start with its fedramp-auto marker")

    existing = find_comment(repo, pr_number, marker, token, api_url)
    if existing is not None:
        _request("PATCH", f"{api_url}/repos/{repo}/issues/comments/{existing}", token,
                 {"body": body})
        return "updated", existing
    created, _ = _request("POST", f"{api_url}/repos/{repo}/issues/{pr_number}/comments",
                          token, {"body": body})
    return "created", int(created["id"])


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m fedramp_auto.ci.github_comment COMMENT_FILE", file=sys.stderr)
        return 1

    env = os.environ
    missing = [k for k in ("GITHUB_TOKEN", "GITHUB_REPOSITORY", "PR_NUMBER") if not env.get(k)]
    if missing:
        print(f"::warning::Not posting PR comment: {', '.join(missing)} not set")
        return 0

    body = Path(args[0]).read_text(encoding="utf-8")
    try:
        action, comment_id = upsert_comment(
            env["GITHUB_REPOSITORY"], int(env["PR_NUMBER"]), body, env["GITHUB_TOKEN"],
            env.get("GITHUB_API_URL", DEFAULT_API_URL),
        )
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 404):
            print(f"::warning::Could not post PR comment (HTTP {exc.code}). Pull requests "
                  "from forks get a read-only token; the job summary has the full report.")
            return 0
        print(f"::error::GitHub API error posting PR comment: HTTP {exc.code}", file=sys.stderr)
        return 1
    print(f"PR comment {action}: {comment_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
