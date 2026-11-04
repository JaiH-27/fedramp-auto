"""
fedramp_auto.ci.pr_comment
~~~~~~~~~~~~~~~~~~~~~~~~~~
Renders a :class:`~fedramp_auto.ci.pr_diff.ScanDiff` as a GitHub pull request
comment (GitHub-flavoured Markdown).

The first line is a hidden marker, ``<!-- fedramp-auto:pr-comment:<id> -->``,
so CI can find and update its own comment on each push instead of posting a
new one.  The comment stays under GitHub's 65,536-character limit by
dropping remediation snippets that do not fit.
"""

from __future__ import annotations

from typing import Any

from fedramp_auto.ci.pr_diff import FailPolicy, ScanDiff, should_fail

MAX_COMMENT_CHARS = 60_000   # GitHub's hard limit is 65,536

_CLOUD_LABELS = {
    "aws": "Terraform · aws",
    "azure": "Terraform · azurerm",
    "cdk": "AWS CDK · TypeScript",
}
_SEVERITY_LABELS = {"critical": "🔴 critical", "high": "🟠 high", "medium": "🟡 medium",
                    "low": "🔵 low"}


def marker(comment_id: str = "default") -> str:
    """Hidden HTML comment identifying this tool's comment on a PR."""
    return f"<!-- fedramp-auto:pr-comment:{comment_id} -->"


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _gap_table(gaps: list[dict[str, Any]]) -> list[str]:
    rows = ["| KSI | Title | Severity | Missing controls |", "|---|---|---|---|"]
    for g in gaps:
        sev = g.get("severity", "")
        rows.append(
            f"| `{_cell(g['ksi_id'])}` | {_cell(g.get('title', ''))} "
            f"| {_SEVERITY_LABELS.get(sev, _cell(sev))} "
            f"| {_cell(', '.join(g.get('missing_controls', [])))} |"
        )
    return rows


def _delta_text(diff: ScanDiff) -> str:
    delta = diff.coverage_delta
    if delta is None:
        return "no base branch scan to compare against"
    if delta == 0:
        return f"no change vs base ({diff.coverage_base}%)"
    return f"**{delta:+.1f} pts** vs base ({diff.coverage_base}%)"


def _status_line(diff: ScanDiff, policy: FailPolicy) -> str:
    if should_fail(diff, policy):
        if policy == "any-critical":
            n = len(diff.critical_gaps)
            return f"> ❌ **Failing:** {n} critical gap(s) open (policy `{policy}`)."
        n = len(diff.new_critical_gaps)
        return f"> ❌ **Failing:** this change opens {n} critical gap(s) (policy `{policy}`)."
    if diff.new_gaps:
        return f"> ⚠️ This change opens {len(diff.new_gaps)} gap(s); none block the merge."
    if diff.resolved_gaps:
        return f"> ✅ This change closes {len(diff.resolved_gaps)} gap(s) and opens none."
    return "> ✅ No new compliance gaps."


def _fence(code: str) -> str:
    """A code fence longer than any backtick run inside the snippet."""
    longest = max((len(run) for run in code.split("\n") if set(run) == {"`"}), default=0)
    return "`" * max(3, longest + 1)


def _fixes_section(diff: ScanDiff, budget: int) -> list[str]:
    remediations = {r["ksi_id"]: r for r in diff.head.get("remediations", [])}
    targets = [g for g in diff.new_gaps if g["ksi_id"] in remediations]
    if not targets:
        return []

    label = "new gaps" if diff.has_base else "open gaps"
    out = ["", "<details>", f"<summary>Suggested fixes for {label} ({len(targets)})</summary>", ""]
    used = sum(len(line) + 1 for line in out)
    skipped = 0
    for g in targets:
        rem = remediations[g["ksi_id"]]
        code = rem.get("terraform_snippet", "")
        lang = rem.get("snippet_language", "hcl")
        fence = _fence(code)
        block = [
            f"**`{g['ksi_id']}` — {g.get('title', '')}**",
            "",
            rem.get("remediation_action", ""),
            "",
            f"{fence}{lang}",
            code,
            fence,
            "",
        ]
        size = sum(len(line) + 1 for line in block)
        if used + size > budget:
            skipped += 1
            continue
        out.extend(block)
        used += size
    if skipped:
        out.append(f"_{skipped} more fix(es) omitted to fit GitHub's comment size limit — "
                   "see `report.md` in the workflow artifacts._")
        out.append("")
    out.append("</details>")
    return out


def render_comment(
    diff: ScanDiff,
    policy: FailPolicy = "new-critical",
    comment_id: str = "default",
    max_chars: int = MAX_COMMENT_CHARS,
) -> str:
    """Render the PR comment for *diff*."""
    head = diff.head
    baseline = str(head.get("baseline", "?")).upper()
    satisfied = head.get("satisfied_ksi_count", "?")
    total = head.get("total_ksi_count", "?")
    open_gaps = diff.open_gaps
    cloud = _CLOUD_LABELS.get(str(head.get("cloud", "")), str(head.get("cloud", "")))

    lines = [
        marker(comment_id),
        f"### FedRAMP-Auto · {baseline} baseline",
        "",
        f"**KSI coverage:** {diff.coverage_head}% ({satisfied}/{total}) · {_delta_text(diff)}  ",
        f"**Open gaps:** {len(open_gaps)} ({len(diff.critical_gaps)} critical)"
        + (f" · **New:** {len(diff.new_gaps)} · **Resolved:** {len(diff.resolved_gaps)}"
           if diff.has_base else ""),
        "",
        _status_line(diff, policy),
    ]

    if diff.has_base and diff.new_gaps:
        lines += ["", f"#### New gaps ({len(diff.new_gaps)})", "", *_gap_table(diff.new_gaps)]
    if diff.resolved_gaps:
        lines += ["", f"#### Resolved gaps ({len(diff.resolved_gaps)})", "",
                  *_gap_table(diff.resolved_gaps)]
    if open_gaps:
        lines += ["", "<details>", f"<summary>All open gaps ({len(open_gaps)})</summary>", "",
                  *_gap_table(open_gaps), "", "</details>"]

    footer = [
        "",
        "---",
        f"<sub>Generated by FedRAMP-Auto · fixes target {cloud} · static rules only; "
        "infrastructure code never left the CI runner.</sub>",
        "",
    ]
    body_so_far = "\n".join(lines + footer)
    lines += _fixes_section(diff, budget=max_chars - len(body_so_far))
    return "\n".join(lines + footer)
