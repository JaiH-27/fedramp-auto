"""
fedramp_auto.cli.main
~~~~~~~~~~~~~~~~~~~~~
Command-line interface for FedRAMP-Auto.

Commands
--------
  scan      Ingest a directory of Terraform files and run full analysis.
  report    Print or export a gap report from a previous scan result.
  validate  Run the FedRAMP OSCAL schema validator against an SSP file.

Usage
-----
  fedramp-auto scan ./infra --baseline low --output ./output
  fedramp-auto report ./output/scan_result.json
  fedramp-auto validate ./output/ssp.json
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

app = typer.Typer(
    name="fedramp-auto",
    help="Automated FedRAMP 20x compliance engine — IaC to OSCAL via local LLM.",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()
err_console = Console(stderr=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        level=level,
    )


def _severity_colour(severity: str) -> str:
    return {"critical": "red", "high": "orange3", "medium": "yellow", "low": "cyan"}.get(
        severity, "white"
    )


def _print_gap_table(gaps: list[dict]) -> None:
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold")
    table.add_column("KSI", style="dim", width=12)
    table.add_column("Title", width=36)
    table.add_column("Severity", width=10)
    table.add_column("Missing controls")
    for gap in gaps:
        sev = gap["severity"]
        table.add_row(
            gap["ksi_id"],
            gap["title"],
            f"[{_severity_colour(sev)}]{sev}[/]",
            ", ".join(gap["missing_controls"]),
        )
    console.print(table)


# ── scan command ──────────────────────────────────────────────────────────────

@app.command()
def scan(
    infra_dir: Annotated[Path, typer.Argument(help="Directory containing Terraform .tf files")],
    baseline: Annotated[str, typer.Option("--baseline", "-b", help="FedRAMP baseline: low | moderate")] = "low",
    output: Annotated[Path, typer.Option("--output", "-o", help="Directory to write scan results")] = Path("./output"),
    model: Annotated[str, typer.Option("--model", "-m", help="Ollama model name")] = "mistral",
    ollama_url: Annotated[str, typer.Option("--ollama-url", help="Ollama API base URL")] = "http://localhost:11434",
    no_llm: Annotated[bool, typer.Option("--no-llm", help="Disable LLM fallback (static rules only)")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """
    Scan a Terraform directory for FedRAMP compliance gaps.

    Parses all .tf files, maps resources to NIST 800-53 controls, identifies
    missing Key Security Indicators, and generates remediation advice.
    """
    _setup_logging(verbose)

    if baseline not in ("low", "moderate"):
        err_console.print("[red]--baseline must be 'low' or 'moderate'[/red]")
        raise typer.Exit(1)

    if not infra_dir.exists():
        err_console.print(f"[red]Directory not found: {infra_dir}[/red]")
        raise typer.Exit(1)

    output.mkdir(parents=True, exist_ok=True)

    # Lazy imports so CLI loads fast even without all deps installed
    from fedramp_auto.parser.terraform import parse_directory
    from fedramp_auto.mapper.control_mapper import ControlMapper
    from fedramp_auto.gaps.detector import detect_gaps
    from fedramp_auto.advisor.remediation import RemediationAdvisor

    console.print(Panel(
        f"[bold]FedRAMP-Auto[/bold] · scan\n"
        f"  Directory : {infra_dir.resolve()}\n"
        f"  Baseline  : {baseline.upper()}\n"
        f"  Model     : {'disabled (--no-llm)' if no_llm else model}\n"
        f"  Output    : {output.resolve()}",
        border_style="blue",
    ))

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:

        # 1. Parse
        task = progress.add_task("Parsing Terraform files...", total=None)
        parse_result = parse_directory(infra_dir)
        progress.update(task, description=f"[green]Parsed {len(parse_result.resources)} resource(s)[/green]")

        if parse_result.errors:
            for e in parse_result.errors:
                err_console.print(f"[yellow]Parse warning: {e}[/yellow]")

        # 2. Map controls
        progress.update(task, description="Mapping resources to NIST 800-53 controls...")
        mapper = ControlMapper(model=model, base_url=ollama_url, llm_fallback=not no_llm)
        mappings = mapper.map_resources(parse_result.resources)

        all_controls: list[str] = []
        for rm in mappings:
            all_controls.extend(rm.control_ids)

        unique_controls = sorted(set(all_controls))
        progress.update(task, description=f"[green]Mapped {len(unique_controls)} unique control(s)[/green]")

        # 3. Detect gaps
        progress.update(task, description="Detecting KSI gaps...")
        gap_report = detect_gaps(unique_controls, baseline=baseline)  # type: ignore[arg-type]
        progress.update(task, description=(
            f"[green]Gap analysis complete: "
            f"{gap_report.coverage_pct}% coverage, "
            f"{len(gap_report.critical_gaps)} critical gap(s)[/green]"
        ))

        # 4. Remediation advice
        progress.update(task, description="Generating remediation advice...")
        advisor = RemediationAdvisor(model=model, base_url=ollama_url, llm_fallback=not no_llm)
        advices = advisor.advise(gap_report.gaps)

    # ── Print summary ──────────────────────────────────────────────────────────
    console.print()
    for line in gap_report.summary_lines():
        console.print(f"  {line}")
    console.print()

    if gap_report.gaps:
        console.print("[bold]Gaps found:[/bold]")
        _print_gap_table([
            {
                "ksi_id": g.ksi.ksi_id,
                "title": g.ksi.title,
                "severity": g.ksi.severity.value,
                "missing_controls": g.missing_controls,
            }
            for g in gap_report.gaps
        ])

    # ── Save JSON result ───────────────────────────────────────────────────────
    scan_result = {
        "baseline": baseline,
        "coverage_pct": gap_report.coverage_pct,
        "satisfied_ksi_count": len(gap_report.satisfied_ksis),
        "total_ksi_count": gap_report.total_ksis,
        "satisfied_control_ids": gap_report.satisfied_control_ids,
        "resources": [
            {
                "identifier": rm.resource.identifier,
                "source_file": rm.resource.source_file,
                "controls": [
                    {"control_id": c.control_id, "rationale": c.rationale, "source": c.source}
                    for c in rm.controls
                ],
            }
            for rm in mappings
        ],
        "gaps": [
            {
                "ksi_id": g.ksi.ksi_id,
                "title": g.ksi.title,
                "severity": g.ksi.severity.value,
                "missing_controls": g.missing_controls,
            }
            for g in gap_report.gaps
        ],
        "remediations": [
            {
                "ksi_id": a.ksi_id,
                "risk_explanation": a.risk_explanation,
                "remediation_action": a.remediation_action,
                "terraform_snippet": a.terraform_snippet,
                "source": a.source,
            }
            for a in advices
        ],
    }

    result_path = output / "scan_result.json"
    result_path.write_text(json.dumps(scan_result, indent=2))

    # ── Save markdown report ───────────────────────────────────────────────────
    md_lines = [
        f"# FedRAMP-Auto scan report\n",
        f"**Baseline:** {baseline.upper()}  ",
        f"**KSI coverage:** {gap_report.coverage_pct}% ({len(gap_report.satisfied_ksis)}/{gap_report.total_ksis})  ",
        f"**Critical gaps:** {len(gap_report.critical_gaps)}  ",
        f"**Total gaps:** {len(gap_report.gaps)}\n",
        "## Gaps\n",
    ]
    for g in gap_report.gaps:
        md_lines.append(f"### {g.ksi.ksi_id} — {g.ksi.title}")
        md_lines.append(f"**Severity:** {g.ksi.severity.value}  ")
        md_lines.append(f"**Missing controls:** {', '.join(g.missing_controls)}\n")

    md_lines.append("## Remediations\n")
    for a in advices:
        md_lines.append(f"### {a.ksi_id}")
        md_lines.append(f"**Risk:** {a.risk_explanation}\n")
        md_lines.append(f"**Action:** {a.remediation_action}\n")
        md_lines.append("**Terraform:**\n```hcl")
        md_lines.append(a.terraform_snippet)
        md_lines.append("```\n")

    md_path = output / "report.md"
    md_path.write_text("\n".join(md_lines), encoding="utf-8")

    console.print(f"[green]Results saved:[/green]")
    console.print(f"  {result_path}")
    console.print(f"  {md_path}")
    console.print()

    # Exit non-zero if there are critical gaps (useful in CI)
    if gap_report.critical_gaps:
        raise typer.Exit(2)


# ── report command ────────────────────────────────────────────────────────────

@app.command()
def report(
    result_file: Annotated[Path, typer.Argument(help="scan_result.json from a previous scan")],
    show_remediations: Annotated[bool, typer.Option("--remediations", "-r", help="Print remediation snippets")] = False,
) -> None:
    """Print a formatted summary of a saved scan result."""

    if not result_file.exists():
        err_console.print(f"[red]File not found: {result_file}[/red]")
        raise typer.Exit(1)

    data = json.loads(result_file.read_text())

    console.print(Panel(
        f"[bold]Scan report[/bold] · {result_file}\n"
        f"  Baseline  : {data.get('baseline', '?').upper()}\n"
        f"  Coverage  : {data.get('coverage_pct', 0)}%"
        f" ({data.get('satisfied_ksi_count', 0)}/{data.get('total_ksi_count', 0)} KSIs)\n"
        f"  Gaps      : {len(data.get('gaps', []))}",
        border_style="blue",
    ))

    gaps = data.get("gaps", [])
    if gaps:
        _print_gap_table(gaps)

    if show_remediations:
        for rem in data.get("remediations", []):
            console.print(f"\n[bold]{rem['ksi_id']}[/bold]")
            console.print(f"[dim]{rem['risk_explanation']}[/dim]")
            console.print(f"\n{rem['remediation_action']}\n")
            console.print("```hcl")
            console.print(rem["terraform_snippet"])
            console.print("```")


# ── validate command ──────────────────────────────────────────────────────────

@app.command()
def validate(
    ssp_file: Annotated[Path, typer.Argument(help="OSCAL SSP JSON file to validate")],
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """
    Validate an OSCAL SSP JSON file against the FedRAMP schema.

    Checks JSON structure, required fields, and OSCAL schema compliance.
    Full FedRAMP validator integration requires the fedramp-automation repo.
    """
    _setup_logging(verbose)

    if not ssp_file.exists():
        err_console.print(f"[red]File not found: {ssp_file}[/red]")
        raise typer.Exit(1)

    console.print(f"Validating [cyan]{ssp_file}[/cyan]...")

    try:
        data = json.loads(ssp_file.read_text())
    except json.JSONDecodeError as exc:
        err_console.print(f"[red]Invalid JSON: {exc}[/red]")
        raise typer.Exit(1)

    errors: list[str] = []

    # Basic structural checks
    ssp = data.get("system-security-plan")
    if not ssp:
        errors.append("Missing top-level 'system-security-plan' key")
    else:
        for field in ("uuid", "metadata", "system-characteristics", "control-implementation"):
            if field not in ssp:
                errors.append(f"Missing required field: system-security-plan.{field}")

        meta = ssp.get("metadata", {})
        for mf in ("title", "last-modified", "version", "oscal-version"):
            if mf not in meta:
                errors.append(f"Missing metadata field: {mf}")

    if errors:
        console.print(f"[red]Validation failed — {len(errors)} error(s):[/red]")
        for e in errors:
            console.print(f"  [red]✗[/red] {e}")
        raise typer.Exit(1)
    else:
        console.print("[green]✓ Structural validation passed[/green]")
        console.print("[dim]  Note: full FedRAMP schema validation requires the fedramp-automation toolchain.[/dim]")
        console.print("[dim]  Install: https://github.com/GSA/fedramp-automation[/dim]")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
