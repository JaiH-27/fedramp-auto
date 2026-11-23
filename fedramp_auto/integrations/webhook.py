"""
fedramp_auto.integrations.webhook
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
POSTs a summary of a scan to a URL you choose, so a workflow tool such as
n8n (see ``examples/n8n``) can open tickets, send alerts or file evidence.

The payload says what changed since the previous scan of the same target and
baseline (taken from ``output/history/``):

  - ``new_gaps``      : open now, not open last time
  - ``resolved_gaps`` : open last time, closed now
  - ``open_gaps``     : everything open now

Each open or new gap carries its remediation advice.

What is sent
------------
KSI IDs, titles, severities, missing NIST controls, coverage numbers, the
remediation text and snippets, and the scanned directory's *name*.  Resource
identifiers, source file paths and your infrastructure code are never sent.
If ``GITHUB_REPOSITORY`` etc. are set (GitHub Actions), the run's repository,
ref, commit and URL are included so tickets can link back to it.

Signing
-------
With a secret, the raw request body is signed with HMAC-SHA256 and sent as
``X-FedRAMP-Auto-Signature: sha256=<hex>`` (the same scheme GitHub uses), so
the receiver can reject requests that did not come from your scanner.

Uses only the standard library.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fedramp_auto.ci.pr_diff import compare

EVENT = "fedramp_auto.scan.completed"
SCHEMA_VERSION = 1
SIGNATURE_HEADER = "X-FedRAMP-Auto-Signature"
EVENT_HEADER = "X-FedRAMP-Auto-Event"
DEFAULT_TIMEOUT = 15.0
DEFAULT_RETRIES = 2  # extra attempts after the first, for 5xx / network errors

_GAP_FIELDS = ("ksi_id", "title", "severity", "missing_controls")
_REMEDIATION_FIELDS = ("risk_explanation", "remediation_action", "terraform_snippet",
                       "snippet_language", "cloud", "source")


class WebhookError(RuntimeError):
    """The webhook could not be delivered."""


@dataclass
class WebhookResult:
    status: int
    attempts: int


# ── Payload ───────────────────────────────────────────────────────────────────

def find_previous(result: dict[str, Any], history_dir: Path) -> dict[str, Any] | None:
    """The newest archived scan of the same target and baseline before *result*."""
    if not history_dir.is_dir():
        return None
    current_at = result.get("generated_at", "")
    best: dict[str, Any] | None = None
    for path in history_dir.glob("scan_result-*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        at = data.get("generated_at", "")
        if (not at or at >= current_at
                or data.get("target") != result.get("target")
                or data.get("baseline") != result.get("baseline")):
            continue
        if best is None or at > best.get("generated_at", ""):
            best = data
    return best


def _gap(gap: dict[str, Any], remediations: dict[str, dict[str, Any]],
         with_remediation: bool) -> dict[str, Any]:
    out = {k: gap.get(k) for k in _GAP_FIELDS}
    if with_remediation:
        rem = remediations.get(gap.get("ksi_id", ""))
        out["remediation"] = ({k: rem.get(k) for k in _REMEDIATION_FIELDS}
                              if rem else None)
    return out


def _ci_context(env: dict[str, str]) -> dict[str, str] | None:
    repo = env.get("GITHUB_REPOSITORY")
    if not repo:
        return None
    server = env.get("GITHUB_SERVER_URL", "https://github.com")
    run_id = env.get("GITHUB_RUN_ID")
    return {
        "repository": repo,
        "ref": env.get("GITHUB_REF", ""),
        "sha": env.get("GITHUB_SHA", ""),
        "url": f"{server}/{repo}/actions/runs/{run_id}" if run_id else f"{server}/{repo}",
    }


def build_payload(result: dict[str, Any], previous: dict[str, Any] | None = None,
                  env: dict[str, str] | None = None) -> dict[str, Any]:
    """Webhook body for *result*, compared with *previous* (None = first scan)."""
    diff = compare(result, previous)
    remediations = {r["ksi_id"]: r for r in result.get("remediations", []) if "ksi_id" in r}
    summary = diff.summary("never")
    payload: dict[str, Any] = {
        "event": EVENT,
        "schema_version": SCHEMA_VERSION,
        "generated_at": result.get("generated_at"),
        "target": result.get("target"),
        "baseline": result.get("baseline"),
        "cloud": result.get("cloud"),
        "coverage": {
            "pct": diff.coverage_head,
            "previous_pct": diff.coverage_base,
            "delta": diff.coverage_delta,
            "satisfied_ksis": result.get("satisfied_ksi_count"),
            "total_ksis": result.get("total_ksi_count"),
        },
        "summary": {
            "open_gaps": summary["open_gaps"],
            "critical_gaps": summary["critical_gaps"],
            "new_gaps": summary["new_gaps"],
            "new_critical_gaps": summary["new_critical_gaps"],
            "resolved_gaps": summary["resolved_gaps"],
            "has_previous": summary["has_base"],
        },
        "new_gaps": [_gap(g, remediations, True) for g in diff.new_gaps],
        "resolved_gaps": [_gap(g, remediations, False) for g in diff.resolved_gaps],
        "open_gaps": [_gap(g, remediations, True) for g in diff.open_gaps],
    }
    ci = _ci_context(dict(os.environ) if env is None else env)
    if ci:
        payload["ci"] = ci
    return payload


# ── Delivery ──────────────────────────────────────────────────────────────────

def encode(payload: dict[str, Any]) -> bytes:
    """The exact bytes that are sent (and signed)."""
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign(body: bytes, secret: str) -> str:
    """``sha256=<hex>`` HMAC of *body*."""
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify(body: bytes, secret: str, signature: str) -> bool:
    """Receiver-side check (handy for tests and Python receivers)."""
    return hmac.compare_digest(sign(body, secret), signature or "")


def validate_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise WebhookError(f"webhook URL must be http(s)://host/...: {url!r}")


def redact_url(url: str) -> str:
    """Scheme, host and path only; n8n and Slack URLs carry tokens in the path or query."""
    parts = urlsplit(url)
    path = parts.path
    if len(path) > 12:
        path = path[:12] + "..."
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{parts.hostname or ''}{port}{path}"


def _post(url: str, body: bytes, headers: dict[str, str], timeout: float) -> int:
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return int(resp.status)


def send(url: str, payload: dict[str, Any], secret: str | None = None, *,
         timeout: float = DEFAULT_TIMEOUT, retries: int = DEFAULT_RETRIES,
         sleep: Callable[[float], None] = time.sleep) -> WebhookResult:
    """POST *payload* to *url*. Retries 5xx and network errors, not 4xx."""
    validate_url(url)
    body = encode(payload)
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "fedramp-auto",
        EVENT_HEADER: str(payload.get("event", EVENT)),
    }
    if secret:
        headers[SIGNATURE_HEADER] = sign(body, secret)

    last_error = ""
    for attempt in range(1, retries + 2):
        try:
            return WebhookResult(status=_post(url, body, headers, timeout), attempts=attempt)
        except urllib.error.HTTPError as exc:
            last_error = f"HTTP {exc.code}"
            if exc.code < 500:
                break
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            last_error = f"{type(exc).__name__}: {reason}"
        if attempt <= retries:
            sleep(float(2 ** (attempt - 1)))
    raise WebhookError(f"webhook to {redact_url(url)} failed: {last_error}")


def _load(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise WebhookError(f"cannot read scan result {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise WebhookError(f"{path} is not a scan result")
    return data


def notify(result_path: Path, url: str, secret: str | None = None,
           previous_path: Path | None = None, **send_kwargs: Any
           ) -> tuple[dict[str, Any], WebhookResult]:
    """Load a scan result (and its previous scan), build the payload and send it."""
    result = _load(result_path)
    if previous_path is not None:
        previous = _load(previous_path)
    else:
        previous = find_previous(result, result_path.parent / "history")
    payload = build_payload(result, previous)
    return payload, send(url, payload, secret, **send_kwargs)
