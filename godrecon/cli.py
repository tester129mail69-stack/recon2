"""GODRECON CLI — Beautiful terminal interface built with Typer + Rich."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import List, Optional

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


# ---------------------------------------------------------------------------
# api command
# ---------------------------------------------------------------------------


@app.command()
def api(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address for the API server"),
    port: int = typer.Option(8000, "--port", "-p", help="TCP port for the API server"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="API key for authentication (overrides config)"),
    config_file: Optional[str] = typer.Option(None, "--config", help="Custom config file"),
) -> None:
    """[bold]Start the GODRECON REST API server.[/]

    Examples:

        godrecon api

        godrecon api --host 0.0.0.0 --port 8080

        godrecon api --api-key mysecretkey
    """
    _print_banner()
    cfg = load_config(config_file)

    effective_key = api_key if api_key is not None else cfg.api.api_key
    effective_host = host if host != "127.0.0.1" else cfg.api.host
    effective_port = port if port != 8000 else cfg.api.port

    console.print(
        f"[bold green]►[/] Starting GODRECON API server at "
        f"[bold]http://{effective_host}:{effective_port}[/]"
    )
    if effective_key:
        console.print("[dim]  API key authentication enabled.[/]")
    else:
        console.print("[yellow]  ⚠ No API key configured — server is open to all.[/]")

    from godrecon.api.server import run_server
    run_server(
        host=effective_host,
        port=effective_port,
        api_key=effective_key,
        cors_origins=cfg.api.cors_origins,
        max_concurrent_scans=cfg.api.max_concurrent_scans,
    )


def main() -> None:
    """Entry point registered in setup.py / pyproject.toml."""
    app()


# ---------------------------------------------------------------------------
# monitor command
# ---------------------------------------------------------------------------


@app.command()
def monitor(
    target: str = typer.Argument(..., help="Target domain or IP to monitor"),
    interval: str = typer.Option("daily", "--interval", "-i", help="Scan interval: hourly, daily, weekly, or seconds"),
    notify: Optional[List[str]] = typer.Option(None, "--notify", "-n", help="Notification backends: slack, discord, telegram, email, webhook"),
    config_file: Optional[str] = typer.Option(None, "--config", help="Custom config file"),
) -> None:
    """[bold]Start continuous monitoring for a target.[/]

    Schedules recurring scans and sends alerts when new findings are detected.

    Examples:

        godrecon monitor example.com

        godrecon monitor example.com --interval daily --notify slack

        godrecon monitor example.com --interval 3600
    """
    _print_banner()
    cfg = load_config(config_file)

    from godrecon.monitoring.monitor import ContinuousMonitor

    cm = ContinuousMonitor(cfg)
    entry = cm.add_target(target, interval=interval, notify=notify or [])
    console.print(
        f"[bold green]►[/] Monitoring [bold]{target}[/] "
        f"(interval=[bold]{interval}[/], id=[dim]{entry.schedule_id}[/])"
    )
    console.print("[dim]  Press Ctrl+C to stop.[/]")

    async def _run() -> None:
        await cm.start()
        try:
            while True:
                await asyncio.sleep(60)
        except asyncio.CancelledError:
            pass
        finally:
            await cm.stop()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring stopped.[/]")


# ---------------------------------------------------------------------------
# schedules command
# ---------------------------------------------------------------------------


@app.command()
def schedules(
    action: str = typer.Argument("list", help="Action: list, add, remove"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Target (for add)"),
    interval: str = typer.Option("daily", "--interval", "-i", help="Interval (for add)"),
    schedule_id: Optional[str] = typer.Option(None, "--id", help="Schedule ID (for remove)"),
    config_file: Optional[str] = typer.Option(None, "--config", help="Custom config file"),
) -> None:
    """[bold]Manage scan schedules.[/]

    Actions: list, add, remove

    Examples:

        godrecon schedules list

        godrecon schedules add --target example.com --interval daily

        godrecon schedules remove --id <schedule_id>
    """
    from godrecon.monitoring.scheduler import ScanScheduler

    scheduler = ScanScheduler()
    action = action.lower()

    if action == "list":
        entries = scheduler.list_schedules()
        if not entries:
            console.print("[dim]No schedules configured.[/]")
            return
        import time as _time
        table = Table(title="Scan Schedules", border_style="dim")
        table.add_column("ID", style="dim", no_wrap=True)
        table.add_column("Target", style="bold")
        table.add_column("Interval")
        table.add_column("Next Run")
        table.add_column("Enabled")
        for e in entries:
            next_ts = e.next_run
            secs = round(next_ts - _time.time()) if next_ts else 0
            next_str = "overdue" if secs <= 0 else f"in {secs}s"
            table.add_row(
                e.schedule_id[:8] + "…",
                e.target,
                e.interval,
                next_str,
                "[green]Yes[/]" if e.enabled else "[red]No[/]",
            )
        console.print(table)

    elif action == "add":
        if not target:
            err_console.print("[red]--target is required for 'add'[/]")
            raise typer.Exit(1)
        entry = scheduler.add(target, interval=interval)
        console.print(
            f"[bold green]✓[/] Schedule added: [bold]{target}[/] every [bold]{interval}[/] "
            f"(id=[dim]{entry.schedule_id}[/])"
        )

    elif action == "remove":
        if not schedule_id:
            err_console.print("[red]--id is required for 'remove'[/]")
            raise typer.Exit(1)
        if scheduler.remove(schedule_id):
            console.print(f"[bold green]✓[/] Schedule [dim]{schedule_id}[/] removed.")
        else:
            err_console.print(f"[red]Schedule {schedule_id!r} not found.[/]")
            raise typer.Exit(1)

    else:
        err_console.print(f"[red]Unknown action: {action!r}. Use list, add, or remove.[/]")
        raise typer.Exit(1)


if __name__ == "__main__":
    main()
