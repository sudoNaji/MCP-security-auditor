#!/usr/bin/env python3
"""
MCP Security Auditor CLI.

Commands:
  scan-schema    Scan tool definitions (JSON/YAML)
  scan-source    Scan server source code (Python/JS)
  scan-live      Introspect a running MCP server
  scan-package   Check npm/PyPI supply chain
  report         Re-render saved JSON report
  info           Show loaded threat rules
"""

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

sys.path.insert(0, str(Path(__file__).parent))

from threats import Severity, ThreatClass, DETECTION_RULES
from scanner import ScanResult, ToolDefinitionScanner, SourceCodeScanner
from report import write_json_report, write_sarif_report, build_metrics
from live_server import LiveServerScanner, MCPServerConnection
from package_scanner import PackageSupplyChainScanner, PackageMetadata

console = Console(stderr=False)
err_console = Console(stderr=True)

VERSION = "1.0.0"

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
}


@click.group(invoke_without_command=True)
@click.version_option(VERSION, prog_name="mcp-audit")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """
    \b
    ███╗   ███╗ ██████╗██████╗    █████╗ ██╗   ██╗██████╗ ██╗████████╗
    ████╗ ████║██╔════╝██╔══██╗  ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
    ██╔████╔██║██║     ██████╔╝  ███████║██║   ██║██║  ██║██║   ██║
    ██║╚██╔╝██║██║     ██╔═══╝   ██╔══██║██║   ██║██║  ██║██║   ██║
    ██║ ╚═╝ ██║╚██████╗██║       ██║  ██║╚██████╔╝██████╔╝██║   ██║
    ╚═╝     ╚═╝ ╚═════╝╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝

    Security auditor for MCP servers — detects poisoning, injection, 
    supply-chain risks, secrets exposure.
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ─────────────────────────────────────────────────────────────
# Shared options
# ─────────────────────────────────────────────────────────────

_format_opt = click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "sarif"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format.",
)

_output_opt = click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Write report to file.",
)

_severity_opt = click.option(
    "--min-severity",
    "min_severity",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"], case_sensitive=False),
    default="LOW",
    show_default=True,
    help="Ignore findings below this severity.",
)


# ─────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────

def _render_findings_table(results: list[ScanResult]) -> tuple[Table, int]:
    """Render findings as a rich table."""
    table = Table(
        title="[bold]MCP Security Audit Findings[/bold]",
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
        expand=True,
    )
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Rule", style="cyan", width=14)
    table.add_column("Threat Class", width=18)
    table.add_column("Title", width=30)
    table.add_column("Target", overflow="fold")
    
    row_count = 0
    for r in results:
        for f in r.sorted_findings():
            sev_style = SEVERITY_STYLE.get(f.severity.value, "white")
            table.add_row(
                Text(f.severity.value, style=f"bold {sev_style}"),
                f.rule_id,
                f.threat_class.value.replace("_", " ").title(),
                f.title,
                r.target,
            )
            row_count += 1
    
    return table, row_count


def _render_summary(results: list[ScanResult]) -> Panel:
    """Render findings summary."""
    total = sum(len(r.findings) for r in results)
    by_sev: dict[str, int] = {}
    for r in results:
        for f in r.findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1

    targets = len(results)
    clean = sum(1 for r in results if r.clean)

    lines = []
    lines.append(f"[bold]Targets scanned:[/bold] {targets}   [bold]Clean:[/bold] {clean}")
    lines.append("")
    if total == 0:
        lines.append("[bold green]✓ No security issues detected[/bold green]")
    else:
        lines.append(f"[bold red]✗ {total} finding(s) detected[/bold red]")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = by_sev.get(sev, 0)
            if count:
                style = SEVERITY_STYLE.get(sev, "white")
                lines.append(f"  [{style}]{sev}[/{style}]: {count}")

    return Panel("\n".join(lines), title="[bold]MCP Audit[/bold] — Summary", border_style="blue")


def _print_results(results: list[ScanResult], output_format: str, output_path: str | None):
    """Print results in requested format."""
    out = Path(output_path) if output_path else None

    if output_format == "json":
        payload = write_json_report(results, output_path=out)
        if not out:
            console.print_json(payload)
    elif output_format == "sarif":
        payload = write_sarif_report(results, output_path=out)
        if not out:
            console.print(payload)
    else:  # text
        table, row_count = _render_findings_table(results)
        summary = _render_summary(results)
        if row_count > 0:
            console.print(table)
            console.print()
        console.print(summary)
        if out:
            write_json_report(results, output_path=out)
            console.print(f"\n[dim]Report written to {out}[/dim]")


# ─────────────────────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────────────────────

@cli.command("info")
def cmd_info() -> None:
    """Show loaded threat rules."""
    table = Table(
        title="[bold]MCP Security Auditor — Threat Rules[/bold]",
        box=box.SIMPLE_HEAD,
        highlight=True,
    )
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("Rule ID", style="cyan", no_wrap=True)
    table.add_column("Severity", width=10)
    table.add_column("Title", width=40)

    for idx, (rule_id, rule) in enumerate(sorted(DETECTION_RULES.items()), start=1):
        severity = rule.get("severity", "MEDIUM")
        sev_str = severity.value if hasattr(severity, 'value') else str(severity)
        sev_style = SEVERITY_STYLE.get(sev_str, "white")
        table.add_row(
            str(idx),
            rule_id,
            Text(sev_str, style=f"bold {sev_style}"),
            rule.get("title", ""),
        )

    console.print(table)
    console.print(f"\n[dim]Total rules: {len(DETECTION_RULES)}[/dim]")


@cli.command("scan-schema")
@click.argument("schema_file", type=click.Path(exists=True))
@_format_opt
@_output_opt
@_severity_opt
def cmd_scan_schema(schema_file: str, output_format: str, output_path: str, min_severity: str):
    """Scan MCP tool schema file (JSON/YAML)."""
    import json
    
    path = Path(schema_file)
    try:
        schema = json.loads(path.read_text())
    except Exception as e:
        err_console.print(f"[red]Error reading {schema_file}: {e}[/red]")
        sys.exit(2)
    
    scanner = ToolDefinitionScanner()
    tool_name = schema.get("name", "unknown")
    findings = scanner.scan(schema, tool_name=tool_name)
    
    result = ScanResult(
        target=schema_file,
        target_type="tool_schema",
        findings=findings,
    )
    
    _print_results([result], output_format, output_path)
    sys.exit(1 if findings else 0)


@cli.command("scan-source")
@click.argument("source_file", type=click.Path(exists=True))
@_format_opt
@_output_opt
@_severity_opt
def cmd_scan_source(source_file: str, output_format: str, output_path: str, min_severity: str):
    """Scan MCP server source code (Python/JS)."""
    path = Path(source_file)
    
    scanner = SourceCodeScanner()
    findings = scanner.scan(path)
    
    result = ScanResult(
        target=source_file,
        target_type="source_code",
        findings=findings,
    )
    
    _print_results([result], output_format, output_path)
    sys.exit(1 if findings else 0)


@cli.command("scan-live")
@click.option("--command", required=True, help="Command to launch MCP server")
@click.option("--sandbox", is_flag=True, default=True, help="Run tools in sandbox (test mode)")
@_format_opt
@_output_opt
def cmd_scan_live(command: str, sandbox: bool, output_format: str, output_path: str):
    """Introspect a running MCP server."""
    conn = MCPServerConnection(command=command)
    scanner = LiveServerScanner(conn, sandbox_mode=sandbox)
    
    if not scanner.connect():
        _print_results([], output_format, output_path)
        sys.exit(1)
    
    findings = scanner.inspect_tools()
    result = ScanResult(
        target=f"live:{command}",
        target_type="live_server",
        findings=findings,
    )
    
    scanner.close()
    _print_results([result], output_format, output_path)
    sys.exit(1 if findings else 0)


@cli.command("scan-package")
@click.argument("package_name")
@click.option("--registry", type=click.Choice(["npm", "pypi"], case_sensitive=False), default="npm")
@click.option("--version", default="latest")
@_format_opt
@_output_opt
def cmd_scan_package(package_name: str, registry: str, version: str, output_format: str, output_path: str):
    """Scan npm/PyPI MCP package for supply-chain risks."""
    scanner = PackageSupplyChainScanner()
    
    if registry.lower() == "npm":
        metadata = scanner.check_npm_package(package_name, version)
    else:
        metadata = scanner.check_pypi_package(package_name, version)
    
    findings = scanner.scan(metadata)
    result = ScanResult(
        target=f"{registry}:{package_name}@{version}",
        target_type="package",
        findings=findings,
    )
    
    _print_results([result], output_format, output_path)
    sys.exit(1 if findings else 0)


@cli.command("report")
@click.argument("json_report", type=click.Path(exists=True))
@click.option("--format", type=click.Choice(["text", "sarif", "metrics"]), default="text")
@_output_opt
def cmd_report(json_report: str, format: str, output_path: str):
    """Re-render a saved JSON report."""
    import json as _json
    raw = _json.loads(Path(json_report).read_text())
    
    results = []
    for item in raw.get("results", []):
        r = ScanResult(target=item["target"], target_type=item["target_type"])
        for fd in item.get("findings", []):
            # Reconstruct Finding from dict
            from threats import Finding
            r.findings.append(Finding(
                threat_class=ThreatClass(fd["threat_class"]),
                severity=Severity(fd["severity"]),
                rule_id=fd["rule_id"],
                title=fd["title"],
                description=fd["description"],
                evidence=fd["evidence"],
                location=fd["location"],
                recommendation=fd["recommendation"],
                cwe=fd.get("cwe", ""),
            ))
        results.append(r)
    
    _print_results(results, format, output_path)


if __name__ == "__main__":
    cli()
