"""
fedramp_auto.cli.main
~~~~~~~~~~~~~~~~~~~~~
Command-line interface for FedRAMP-Auto.

Commands
--------
  scan      Ingest a directory of Terraform / Azure ARM / AWS CDK files and run full analysis.
  report    Print or export a gap report from a previous scan result.
  validate  Run the FedRAMP OSCAL schema validator against an SSP file.
  dashboard Browse scan results in a local web page.

Usage
-----
  fedramp-auto scan ./infra --baseline low --output ./output
  fedramp-auto scan ./azure-infra --cloud azure
  fedramp-auto scan ./my-cdk-app --format cdk          # after `cdk synth`
  fedramp-auto report ./output/scan_result.json
  fedramp-auto validate ./output/ssp.json
  fedramp-auto dashboard ./output
"""

from __future__ import annotations

import json
import logging
import sys
import webbrowser
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, TextIO

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

app = typer.Typer(
    name="fedramp-auto",
    help="Automated FedRAMP 20x compliance engine — IaC to OSCAL via local LLM.",
    add_completion=False,
    rich_markup_mode="rich",
)



# ── Console encoding ──────────────────────────────────────────────────────────
# Windows consoles and redirected output often use a legacy code page (cp1252)
# that cannot encode the spinner glyphs, ✓, box-drawing or em dashes rich
# prints.  Without this, any such character raises UnicodeEncodeError and the
# scan dies mid-run.

def _is_utf8(stream: TextIO) -> bool:
    encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
    return encoding in ("utf8", "utf8sig")


def _harden_stream(stream: TextIO) -> None:
    """Replace unencodable characters with '?' instead of crashing."""
    if _is_utf8(stream) or not hasattr(stream, "reconfigure"):
        return
    try:
        stream.reconfigure(errors="replace")
    except (ValueError, OSError):  # detached or closed stream
        pass


def _spinner_name(stream: TextIO) -> str:
    """The braille "dots" spinner needs Unicode; fall back to rich's ASCII "line" spinner."""
    return "dots" if _is_utf8(stream) else "line"


_harden_stream(sys.stdout)
_harden_stream(sys.stderr)

console = Console()
err_console = Console(stderr=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        level=level,
    )


_CLOUD_LABELS = {
    "aws": "AWS · aws provider",
    "azure": "Azure · azurerm provider",
    "cdk": "AWS · CDK v2 (TypeScript)",
}

# Heading for a remediation snippet in reports, by snippet language
_SNIPPET_HEADINGS = {"hcl": "Terraform", "typescript": "AWS CDK"}


def _severity_colour(severity: str) -> str:
    return {"critical": "red", "high": "orange3", "medium": "yellow", "low": "cyan"}.get(
        severity, "white"
    )


def _archive_result(result_path: Path, generated_at: str) -> Path:
    """Keep a timestamped copy, because each scan overwrites scan_result.json."""
    stamp = datetime.fromisoformat(generated_at).strftime("%Y%m%dT%H%M%S%fZ")
    history = result_path.parent / "history"
    history.mkdir(exist_ok=True)
    archived = history / f"scan_result-{stamp}.json"
    archived.write_bytes(result_path.read_bytes())
    return archived


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
    infra_dir: Annotated[
        Path,
        typer.Argument(
            help="Directory containing Terraform .tf files, ARM templates, and/or CDK cdk.out"
        ),
    ],
    iac_format: Annotated[
        str, typer.Option("--format", "-f", help="IaC format: auto | terraform | arm | cdk")
    ] = "auto",
    baseline: Annotated[
        str, typer.Option("--baseline", "-b", help="FedRAMP baseline: low | moderate")
    ] = "low",
    cloud: Annotated[
        str,
        typer.Option("--cloud", "-c", help="Remediation snippet target: auto | aws | azure | cdk"),
    ] = "auto",
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Directory to write scan results")
    ] = Path("./output"),
    model: Annotated[str, typer.Option("--model", "-m", help="Ollama model name")] = "mistral",
    ollama_url: Annotated[
        str, typer.Option("--ollama-url", help="Ollama API base URL")
    ] = "http://localhost:11434",
    no_llm: Annotated[
        bool, typer.Option("--no-llm", help="Disable LLM fallback (static rules only)")
    ] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """
    Scan an infrastructure-as-code directory for FedRAMP compliance gaps.

    Parses all .tf files, Azure ARM templates and AWS CloudFormation / CDK
    synthesized templates (*.json), maps resources to
    NIST 800-53 controls, identifies missing Key Security Indicators, and
    generates remediation advice.
    """
    _setup_logging(verbose)

    if baseline not in ("low", "moderate"):
        err_console.print("[red]--baseline must be 'low' or 'moderate'[/red]")
        raise typer.Exit(1)

    if iac_format not in ("auto", "terraform", "arm", "cdk"):
        err_console.print("[red]--format must be 'auto', 'terraform', 'arm', or 'cdk'[/red]")
        raise typer.Exit(1)

    if cloud not in ("auto", "aws", "azure", "cdk"):
        err_console.print("[red]--cloud must be 'auto', 'aws', 'azure', or 'cdk'[/red]")
        raise typer.Exit(1)

    if not infra_dir.exists():
        err_console.print(f"[red]Directory not found: {infra_dir}[/red]")
        raise typer.Exit(1)

    output.mkdir(parents=True, exist_ok=True)

    # Lazy imports so CLI loads fast even without all deps installed
    from fedramp_auto.advisor.remediation import RemediationAdvisor, detect_cloud
    from fedramp_auto.gaps.detector import detect_gaps
    from fedramp_auto.mapper.control_mapper import ControlMapper
    from fedramp_auto.oscal.ssp_generator import generate_ssp
    from fedramp_auto.parser import arm, cloudformation, terraform
    from fedramp_auto.parser.terraform import ParseResult

    console.print(Panel(
        f"[bold]FedRAMP-Auto[/bold] · scan\n"
        f"  Directory : {infra_dir.resolve()}\n"
        f"  Format    : {iac_format}\n"
        f"  Cloud     : {cloud}\n"
        f"  Baseline  : {baseline.upper()}\n"
        f"  Model     : {'disabled (--no-llm)' if no_llm else model}\n"
        f"  Output    : {output.resolve()}",
        border_style="blue",
    ))

    spinner = SpinnerColumn(_spinner_name(console.file))
    with Progress(spinner, TextColumn("{task.description}"), console=console) as progress:

        # 1. Parse
        task = progress.add_task("Parsing infrastructure files...", total=None)
        parse_result = ParseResult()
        parsers = {
            "terraform": [terraform], "arm": [arm], "cdk": [cloudformation],
        }.get(iac_format, [terraform, arm, cloudformation])
        for parser in parsers:
            partial = parser.parse_directory(infra_dir)
            parse_result.resources.extend(partial.resources)
            parse_result.errors.extend(partial.errors)
        progress.update(
            task, description=f"[green]Parsed {len(parse_result.resources)} resource(s)[/green]"
        )

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
        progress.update(
            task, description=f"[green]Mapped {len(unique_controls)} unique control(s)[/green]"
        )

        # 3. Detect gaps
        progress.update(task, description="Detecting KSI gaps...")
        gap_report = detect_gaps(unique_controls, baseline=baseline)  # type: ignore[arg-type]
        progress.update(task, description=(
            f"[green]Gap analysis complete: "
            f"{gap_report.coverage_pct}% coverage, "
            f"{len(gap_report.critical_gaps)} critical gap(s)[/green]"
        ))

        # 4. Remediation advice
        snippet_cloud = detect_cloud(parse_result.resources) if cloud == "auto" else cloud
        progress.update(task, description=f"Generating remediation advice ({snippet_cloud})...")
        advisor = RemediationAdvisor(
            model=model, base_url=ollama_url, llm_fallback=not no_llm, cloud=snippet_cloud
        )
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
        "generated_at": datetime.now(UTC).isoformat(),
        "target": infra_dir.resolve().name,
        "baseline": baseline,
        "cloud": snippet_cloud,
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
                "snippet_language": a.snippet_language,
                "source": a.source,
                "cloud": a.cloud,
            }
            for a in advices
        ],
    }

    result_path = output / "scan_result.json"
    result_path.write_text(json.dumps(scan_result, indent=2))
    _archive_result(result_path, scan_result["generated_at"])

    # ── Generate OSCAL SSP ────────────────────────────────────────────────────
    ssp_path = output / "ssp.json"
    generate_ssp(gap_report, mappings, ssp_path)

    # ── Save markdown report ───────────────────────────────────────────────────
    md_lines = [
        "# FedRAMP-Auto scan report\n",
        f"**Baseline:** {baseline.upper()}  ",
        f"**Remediation target:** {_CLOUD_LABELS[snippet_cloud]}  ",
        f"**KSI coverage:** {gap_report.coverage_pct}% "
        f"({len(gap_report.satisfied_ksis)}/{gap_report.total_ksis})  ",
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
        heading = _SNIPPET_HEADINGS[a.snippet_language]
        md_lines.append(f"**{heading} ({_CLOUD_LABELS[a.cloud]}):**\n```{a.snippet_language}")
        md_lines.append(a.terraform_snippet)
        md_lines.append("```\n")

    md_path = output / "report.md"
    md_path.write_text("\n".join(md_lines), encoding="utf-8")

    console.print("[green]Results saved:[/green]")
    console.print(f"  {result_path}")
    console.print(f"  {md_path}")
    console.print(f"  {ssp_path}")
    console.print()

    # Exit non-zero if there are critical gaps (useful in CI)
    if gap_report.critical_gaps:
        raise typer.Exit(2)


# ── report command ────────────────────────────────────────────────────────────

@app.command()
def report(
    result_file: Annotated[Path, typer.Argument(help="scan_result.json from a previous scan")],
    show_remediations: Annotated[
        bool, typer.Option("--remediations", "-r", help="Print remediation snippets")
    ] = False,
) -> None:
    """Print a formatted summary of a saved scan result."""

    if not result_file.exists():
        err_console.print(f"[red]File not found: {result_file}[/red]")
        raise typer.Exit(1)

    data = json.loads(result_file.read_text())

    console.print(Panel(
        f"[bold]Scan report[/bold] · {result_file}\n"
        f"  Baseline  : {data.get('baseline', '?').upper()}\n"
        f"  Cloud     : {data.get('cloud', 'aws')}\n"
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
            console.print(f"\n[bold]{rem['ksi_id']}[/bold] [dim]({rem.get('cloud', 'aws')})[/dim]")
            console.print(f"[dim]{rem['risk_explanation']}[/dim]")
            console.print(f"\n{rem['remediation_action']}\n")
            # Results saved before snippet_language existed are always HCL
            console.print(f"```{rem.get('snippet_language', 'hcl')}")
            console.print(rem["terraform_snippet"])
            console.print("```")


# ── dashboard command ─────────────────────────────────────────────────────────

@app.command()
def dashboard(
    results: Annotated[
        Path, typer.Argument(help="Folder of scan results, or one scan_result.json")
    ] = Path("./output"),
    port: Annotated[
        int, typer.Option("--port", "-p", help="Local port to serve on (0 picks a free one)")
    ] = 8765,
    export: Annotated[
        Path | None,
        typer.Option("--export", "-e", help="Write a standalone HTML file instead of serving"),
    ] = None,
    no_open: Annotated[
        bool, typer.Option("--no-open", help="Do not open a browser")
    ] = False,
) -> None:
    """
    Browse scan results in a local web page.

    Shows KSI coverage, gaps with the resources behind each control, remediation
    snippets, and coverage history. Everything stays on this machine: the server
    only listens on 127.0.0.1 and the page loads nothing from the network.
    """
    from fedramp_auto.dashboard.loader import load_scans
    from fedramp_auto.dashboard.render import render_page
    from fedramp_auto.dashboard.server import HOST, make_server
    from fedramp_auto.dashboard.view_model import build_view_model

    if not results.exists():
        err_console.print(f"[red]Path not found: {results}[/red]")
        raise typer.Exit(1)

    def build_page() -> str:
        return render_page(build_view_model(load_scans(results).groups))

    loaded = load_scans(results)
    for warning in loaded.warnings:
        err_console.print(f"[yellow]{warning}[/yellow]", soft_wrap=True)
    if not loaded.groups:
        err_console.print(f"[red]No scan results found in {results}. Run a scan first.[/red]")
        raise typer.Exit(1)

    if export is not None:
        export.parent.mkdir(parents=True, exist_ok=True)
        export.write_text(build_page(), encoding="utf-8")
        console.print(f"[green]Dashboard saved:[/green] {export}")
        return

    try:
        server = make_server(build_page, port)
    except OSError as exc:
        err_console.print(f"[red]Could not use port {port}: {exc}. Try --port 0.[/red]")
        raise typer.Exit(1) from exc

    url = f"http://{HOST}:{server.server_address[1]}/"
    console.print(f"[green]Dashboard running at[/green] {url}  [dim](Ctrl+C to stop)[/dim]")
    if not no_open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("Stopped.")
    finally:
        server.server_close()


# ── validate command ──────────────────────────────────────────────────────────

@app.command()
def validate(
    ssp_file: Annotated[Path, typer.Argument(help="OSCAL SSP JSON file to validate")],
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """
    Validate an OSCAL SSP JSON file against the FedRAMP schema.

    Checks JSON structure, FedRAMP-specific fields, and OSCAL model compliance.
    """
    _setup_logging(verbose)

    if not ssp_file.exists():
        err_console.print(f"[red]File not found: {ssp_file}[/red]")
        raise typer.Exit(1)

    from fedramp_auto.oscal.validator import validate_ssp_file

    console.print(f"Validating [cyan]{ssp_file}[/cyan]...")
    report = validate_ssp_file(ssp_file)
    for issue in report.issues:
        colour = {"error": "red", "warning": "yellow", "info": "dim"}.get(
            issue.severity, "white"
        )
        location = f" [dim]({issue.path})[/dim]" if issue.path else ""
        console.print(
            f"[{colour}]{issue.severity.upper()} {issue.code}[/] {issue.message}{location}"
        )

    if report.passed:
        console.print(f"[green]✓ {report.summary()}[/green]")
    else:
        console.print(f"[red]✗ {report.summary()}[/red]")
        raise typer.Exit(1)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()



