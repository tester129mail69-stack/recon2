"""GODRECON CLI — Beautiful terminal interface built with Typer + Rich."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from godrecon import __version__
from godrecon.core.config import load_config
from godrecon.utils.logger import configure_logging, get_logger

app = typer.Typer(
    name="godrecon",
    help="[bold red]GODRECON[/] — The Ultimate Cybersecurity Reconnaissance Tool",
    rich_markup_mode="rich",
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)
logger = get_logger(__name__)

_BANNER = r"""
 ██████╗  ██████╗ ██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔════╝ ██╔═══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║  ███╗██║   ██║██║  ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║   ██║██║   ██║██║  ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚██████╔╝╚██████╔╝██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
"""


def _print_banner() -> None:
    """Print the GODRECON ASCII art banner."""
    console.print(
        Panel(
            Text(_BANNER, style="bold red", justify="center"),
            subtitle=f"[dim]v{__version__} — The Ultimate Reconnaissance Tool[/]",
            border_style="red",
            expand=False,
        )
    )


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------


@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="Target domain, IP, or CIDR"),
    full: bool = typer.Option(False, "--full", help="Run all modules"),
    subs_only: bool = typer.Option(False, "--subs-only", help="Subdomain enumeration only"),
    ports: bool = typer.Option(False, "--ports", help="Enable port scanning"),
    screenshots: bool = typer.Option(False, "--screenshots", help="Enable screenshots"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    fmt: str = typer.Option("json", "--format", "-f", help="Output format: json/csv/html/pdf/md"),
    threads: int = typer.Option(50, "--threads", help="Concurrency level"),
    timeout: int = typer.Option(10, "--timeout", help="Request timeout in seconds"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Proxy URL (http/socks5)"),
    silent: bool = typer.Option(False, "--silent", help="Minimal output"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    config_file: Optional[str] = typer.Option(None, "--config", help="Custom config file"),
) -> None:
    """[bold]Run a reconnaissance scan against a target.[/]

    Examples:

        godrecon scan --target example.com

        godrecon scan --target example.com --full --format html -o report.html

        godrecon scan --target 192.168.1.0/24 --ports --threads 100
    """
    if not silent:
        _print_banner()

    configure_logging(verbose=verbose)

    # Load and patch config
    cfg = load_config(config_file)
    cfg.general.threads = threads
    cfg.general.timeout = timeout
    if proxy:
        cfg.general.proxy = proxy
    if output:
        cfg.general.output_dir = str(Path(output).parent)

    if subs_only:
        # Disable everything except subdomains
        for field_name in cfg.modules.model_fields:
            setattr(cfg.modules, field_name, field_name == "subdomains")

    if full:
        for field_name in cfg.modules.model_fields:
            setattr(cfg.modules, field_name, True)

    if ports:
        cfg.modules.ports = True
    if screenshots:
        cfg.modules.screenshots = True

    if not silent:
        console.print(
            f"[bold green]►[/] Scanning [bold]{target}[/] "
            f"(threads={threads}, timeout={timeout}s)"
        )

    # Run the async scan
    asyncio.run(_run_scan(target, cfg, output, fmt, silent))


async def _run_scan(
    target: str,
    cfg: object,
    output: Optional[str],
    fmt: str,
    silent: bool,
) -> None:
    """Internal async wrapper for the scan engine."""
    from godrecon.core.engine import ScanEngine

    engine = ScanEngine(target=target, config=cfg)  # type: ignore[arg-type]

    events_log: list = []

    def on_event(event: dict) -> None:  # type: ignore[type-arg]
        events_log.append(event)
        if not silent and event.get("event") == "module_finished":
            findings = event.get("findings", 0)
            console.print(
                f"  [green]✓[/] [dim]{event['module']}[/] — "
                f"[bold]{findings}[/] finding(s)"
            )
        elif not silent and event.get("event") == "module_error":
            console.print(
                f"  [red]✗[/] [dim]{event['module']}[/] — "
                f"[red]{event.get('error', 'unknown error')}[/]"
            )

    engine.on_event(on_event)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
        disable=silent,
    ) as progress:
        task_id = progress.add_task(f"Scanning {target}…", total=None)
        result = await engine.run()
        progress.update(task_id, completed=True)

    if not silent:
        _display_results(result)

    # Write output file
    if output:
        _write_output(result, output, fmt)
        if not silent:
            console.print(f"\n[bold green]✓[/] Report saved to [bold]{output}[/]")


def _display_results(result: object) -> None:  # type: ignore[type-arg]
    """Render a Rich summary table of scan results."""
    from godrecon.core.engine import ScanResult

    assert isinstance(result, ScanResult)

    console.print()
    table = Table(
        title=f"Scan Results — {result.target}",
        show_header=True,
        header_style="bold magenta",
        border_style="dim",
    )
    table.add_column("Module", style="cyan", no_wrap=True)
    table.add_column("Findings", justify="right", style="bold")
    table.add_column("Status", justify="center")

    for module_name, module_result in result.module_results.items():
        count = len(module_result.findings) if module_result else 0
        status = "[red]ERROR[/]" if (module_result and module_result.error) else "[green]OK[/]"
        table.add_row(module_name, str(count), status)

    console.print(table)

    stats = result.stats
    console.print(
        f"\n[bold]Duration:[/] {stats.get('duration_seconds', 0):.1f}s  "
        f"[bold]Modules:[/] {stats.get('modules_run', 0)}  "
        f"[bold]Errors:[/] {stats.get('modules_with_errors', 0)}"
    )


def _write_output(result: object, output: str, fmt: str) -> None:  # type: ignore[type-arg]
    """Serialise *result* to *output* using the requested *fmt*."""
    from godrecon.core.engine import ScanResult

    assert isinstance(result, ScanResult)

    data = {
        "target": result.target,
        "stats": result.stats,
        "module_results": result.module_results,
        "errors": result.errors,
    }

    fmt = fmt.lower()
    if fmt == "json":
        from godrecon.reporting.json_report import JSONReporter
        JSONReporter().generate(data, output)
    elif fmt in ("html", "htm"):
        from godrecon.reporting.html import HTMLReporter
        HTMLReporter().generate(data, output)
    elif fmt == "csv":
        from godrecon.reporting.csv_report import CSVReporter
        CSVReporter().generate(data, output)
    elif fmt in ("md", "markdown"):
        from godrecon.reporting.markdown_report import MarkdownReporter
        MarkdownReporter().generate(data, output)
    elif fmt == "pdf":
        from godrecon.reporting.pdf import PDFReporter
        PDFReporter().generate(data, output)
    else:
        err_console.print(f"[red]Unknown output format: {fmt}[/]")


# ---------------------------------------------------------------------------
# config command
# ---------------------------------------------------------------------------


@app.command()
def config(
    show: bool = typer.Option(True, "--show", help="Print current configuration"),
    config_file: Optional[str] = typer.Option(None, "--config", help="Config file path"),
) -> None:
    """[bold]Show or validate the current configuration.[/]"""
    _print_banner()
    cfg = load_config(config_file)
    console.print_json(cfg.model_dump_json(indent=2))


# ---------------------------------------------------------------------------
# version command
# ---------------------------------------------------------------------------


@app.command()
def version() -> None:
    """[bold]Show GODRECON version information.[/]"""
    console.print(f"[bold red]GODRECON[/] version [bold]{__version__}[/]")


def main() -> None:
    """Entry point registered in setup.py / pyproject.toml."""
    app()


if __name__ == "__main__":
    main()
