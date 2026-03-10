"""
Trend Vision One — Data Collection & Reporting CLI

Usage examples:
  python main.py report
  python main.py report --days 7 --severity critical --severity high
  python main.py report --output /tmp/my_report.pdf
  python main.py report --skip-endpoints --skip-iocs
"""

import sys
from datetime import datetime, timedelta, timezone

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from client import TrendVisionOneClient
from collectors import (
    collect_alerts,
    collect_endpoints,
    collect_suspicious_objects,
    collect_vulnerabilities,
)
from reports import generate_report

console = Console()


def _make_client() -> TrendVisionOneClient:
    try:
        return TrendVisionOneClient()
    except ValueError as exc:
        console.print(f"[bold red]Configuration error:[/] {exc}")
        sys.exit(1)


@click.group()
def cli():
    """Trend Vision One data collector and report generator."""


@cli.command()
@click.option(
    "--days",
    default=30,
    show_default=True,
    type=int,
    help="Number of days back to collect alert/vuln data.",
)
@click.option(
    "--severity",
    multiple=True,
    type=click.Choice(
        ["critical", "high", "medium", "low", "info"], case_sensitive=False
    ),
    help="Filter alerts/vulns by severity (repeatable). Defaults to all.",
)
@click.option(
    "--output",
    default=None,
    help="Output PDF file path. Auto-generated if not provided.",
)
@click.option("--skip-alerts", is_flag=True, help="Skip Workbench alerts collection.")
@click.option("--skip-endpoints", is_flag=True, help="Skip endpoint sensor collection.")
@click.option("--skip-iocs", is_flag=True, help="Skip threat intel / IoC collection.")
@click.option("--skip-vulns", is_flag=True, help="Skip vulnerability assessment.")
def report(days, severity, output, skip_alerts, skip_endpoints, skip_iocs, skip_vulns):
    """Collect data from Trend Vision One and generate a PDF report."""

    end_time = datetime.now(tz=timezone.utc)
    start_time = end_time - timedelta(days=days)
    sev_filter = list(severity) if severity else None

    console.print(
        f"\n[bold]Trend Vision One Reporter[/]\n"
        f"Period : [cyan]{start_time.date()}[/] → [cyan]{end_time.date()}[/]\n"
        f"Filters: severity={sev_filter or 'all'}\n"
    )

    alerts: list = []
    endpoints: list = []
    iocs: list = []
    vulns: list = []

    with _make_client() as client:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:

            if not skip_alerts:
                task = progress.add_task("Fetching Workbench alerts…", total=None)
                try:
                    alerts = collect_alerts(
                        client,
                        start_time=start_time,
                        end_time=end_time,
                        severity=sev_filter,
                    )
                    progress.update(task, description=f"[green]✓[/] Alerts: {len(alerts)} retrieved")
                except Exception as exc:
                    progress.update(task, description=f"[red]✗[/] Alerts failed: {exc}")

            if not skip_endpoints:
                task = progress.add_task("Fetching endpoint sensors…", total=None)
                try:
                    endpoints = collect_endpoints(client)
                    progress.update(task, description=f"[green]✓[/] Endpoints: {len(endpoints)} retrieved")
                except Exception as exc:
                    progress.update(task, description=f"[red]✗[/] Endpoints failed: {exc}")

            if not skip_iocs:
                task = progress.add_task("Fetching threat intel / IoCs…", total=None)
                try:
                    iocs = collect_suspicious_objects(client)
                    progress.update(task, description=f"[green]✓[/] IoCs: {len(iocs)} retrieved")
                except Exception as exc:
                    progress.update(task, description=f"[red]✗[/] IoCs failed: {exc}")

            if not skip_vulns:
                task = progress.add_task("Fetching vulnerabilities…", total=None)
                try:
                    vulns = collect_vulnerabilities(client, severity=sev_filter)
                    progress.update(task, description=f"[green]✓[/] Vulns: {len(vulns)} retrieved")
                except Exception as exc:
                    progress.update(task, description=f"[red]✗[/] Vulns failed: {exc}")

    # Print summary table
    summary = Table(title="Collection Summary", show_header=True, header_style="bold magenta")
    summary.add_column("Dataset", style="cyan")
    summary.add_column("Records", justify="right")
    summary.add_row("Workbench Alerts", str(len(alerts)))
    summary.add_row("Endpoints", str(len(endpoints)))
    summary.add_row("Threat IoCs", str(len(iocs)))
    summary.add_row("Vulnerabilities", str(len(vulns)))
    console.print(summary)

    if not any([alerts, endpoints, iocs, vulns]):
        console.print("[yellow]No data collected — report not generated.[/]")
        sys.exit(0)

    console.print("\nGenerating PDF report…")
    pdf_path = generate_report(
        alerts=alerts,
        endpoints=endpoints,
        iocs=iocs,
        vulns=vulns,
        output_path=output,
    )
    console.print(f"[bold green]Report saved:[/] {pdf_path}")


if __name__ == "__main__":
    cli()
