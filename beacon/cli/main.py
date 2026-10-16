"""Professional CLI interface for Beacon network analysis."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Optional

# Ensure UTF-8 console output across Windows and other environments
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


import click
import typer
from click.core import UNSET
from rich import box

# Click 8.5+ compatibility patch for Typer:
# In Click 8.5+, click.Option treats flag_value != UNSET as an explicit flag indicator.
# Some Typer versions pass flag_value=None to click.Option.__init__, causing non-boolean
# options to be mis-inferred as flags. We patch click.Option.__init__ directly so that
# TyperOption.__init__ signatures across different Typer versions (e.g. 0.12 vs 0.27)
# are never corrupted with unexpected arguments.
if hasattr(click.core, "UNSET"):
    _orig_click_opt_init = click.Option.__init__

    def _safe_click_opt_init(self, *args, **kwargs):
        if kwargs.get("flag_value") is None:
            kwargs["flag_value"] = click.core.UNSET
        return _orig_click_opt_init(self, *args, **kwargs)

    click.Option.__init__ = _safe_click_opt_init

_orig_gm = click.ParamType.get_metavar
click.ParamType.get_metavar = lambda self, param, ctx=None: (
    _orig_gm(self, param, ctx) if ctx is not None else (param.name.upper() if param and param.name else "")
)

_orig_make_metavar = click.Parameter.make_metavar


def _safe_make_metavar(self: click.Parameter, ctx: Optional[click.Context] = None) -> str:
    if ctx is not None:
        return _orig_make_metavar(self, ctx)
    return self.name.upper() if self.name else ""


click.Parameter.make_metavar = _safe_make_metavar  # type: ignore[assignment]

typer.core.TyperArgument.make_metavar = lambda self, *args, **kwargs: (
    str(self.metavar)
    if self.metavar is not None
    else (
        str(self.type.get_metavar(self, args[0]))
        if (args and hasattr(self.type, "get_metavar") and self.type.get_metavar(self, args[0]))
        else str(self.name.upper() if self.name else "ARG")
    )
)

import enum as _enum
_orig_norm_choice = click.Choice.normalize_choice


def _safe_normalize_choice(self: click.Choice, choice: object, ctx: Optional[click.Context] = None) -> str:
    if isinstance(choice, _enum.Enum):
        val = str(choice.value)
        if any(c == val or (not self.case_sensitive and c.casefold() == val.casefold()) for c in self.choices):
            return val if self.case_sensitive else val.casefold()
    return _orig_norm_choice(self, choice, ctx)


click.Choice.normalize_choice = _safe_normalize_choice  # type: ignore[assignment]

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text
from rich.markup import escape

from beacon import __version__
from beacon.core import AnalysisEngine, AnalysisMode
from beacon.core.engine import AnalysisEngine
from beacon.core.modes import get_mode_config
from beacon.core.packet_parser import PacketParser
from beacon.models import Severity, HostStats, ConversationStats, TimelineEvent, IOC
from beacon.analysis.hosts import HostAnalyzer
from beacon.analysis.conversations import ConversationAnalyzer
from beacon.analysis.timeline import TimelineBuilder
from beacon.analysis.ioc_extractor import IOCExtractor
from beacon.analysis.packet_inspector import PacketInspector
from beacon.utils.formatters import (
    format_bytes,
    format_duration,
    format_int,
    format_timestamp,
    redact_text,
    write_json,
)

logger = logging.getLogger(__name__)
console = Console()

app = typer.Typer(
    name="beacon",
    help="Beacon - Cybersecurity Network Traffic Analysis Platform",
    add_completion=False,
    pretty_exceptions_show_locals=False,
)

MODE_COLORS = {"blue": "bright_blue", "red": "bright_red", "white": "bright_white"}


def version_callback(show_version: bool) -> None:
    if show_version:
        console.print(f"[bold bright_blue]Beacon[/] version [white]{__version__}[/]")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", callback=version_callback, is_eager=True, help="Show version and exit"
    ),
    gui: bool = typer.Option(False, "--gui", help="Launch Beacon web dashboard in default browser"),
) -> None:
    """Beacon - Transform raw network traffic into actionable security intelligence."""
    if ctx.invoked_subcommand is None:
        from beacon.launcher import launch_beacon
        sys.exit(launch_beacon())


@app.command("launch")
def launch_cmd(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host address to bind the server to"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to listen on"),
    pin: Optional[str] = typer.Option(None, "--pin", help="Optional access PIN to require from remote clients"),
    low_resource: bool = typer.Option(False, "--low-resource", help="Enable low-resource mode for older hardware"),
    no_browser: bool = typer.Option(False, "--no-browser", help="Do not open default browser automatically"),
) -> None:
    """Start Beacon production server and automatically launch the dashboard in your default browser."""
    from beacon.launcher import launch_beacon
    sys.exit(launch_beacon(host=host, port=port, pin=pin, low_resource=low_resource, open_browser=not no_browser))


@app.command("analyze")
def analyze(
    pcap_path: Path = typer.Argument(..., help="Path to PCAP/PCAPNG file", exists=True, dir_okay=False),
    mode: AnalysisMode = typer.Option(AnalysisMode.WHITE, "--mode", "-m", help="Analysis mode"),
    limit: Optional[int] = typer.Option(None, "--limit", "-l", help="Limit packet count"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file (JSON)"),
    with_memory: bool = typer.Option(False, "--memory", "-M", help="Index capture into Beacon Memory and display change briefing"),
    verbose: bool = typer.Option(False, "--verbose", "-V", help="Enable verbose output"),
) -> None:
    """Run a full analysis on a network capture."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    mode_config = get_mode_config(mode)
    color = MODE_COLORS.get(mode.value, "white")
    console.print(Panel.fit(f"[bold {color}]{mode_config.name}[/] - {mode_config.focus}", subtitle=f"📄 {pcap_path.name}"))
    try:
        with AnalysisEngine(pcap_path, mode=mode) as engine:
            results = engine.analyze(packet_limit=limit)
            if with_memory:
                engine.record_to_memory()
                briefing = engine.get_memory_briefing()
            else:
                briefing = None
        console.print("\n[bold]Summary[/]")
        summary = Table(box=box.SIMPLE, padding=(0, 1))
        summary.add_column("Property", style="cyan", no_wrap=True)
        summary.add_column("Value", style="white")
        summary.add_row("Total Packets", format_int(results["total_packets"]))
        summary.add_row("Total Bytes", format_bytes(results["total_bytes"]))
        summary.add_row("Unique Hosts", format_int(results["unique_hosts"]))
        summary.add_row("Duration", format_duration(results["duration_seconds"]))
        console.print(summary)
        if results.get("protocols"):
            console.print("\n[bold]Protocols[/]")
            proto_table = Table(box=box.SIMPLE, padding=(0, 1))
            proto_table.add_column("Protocol", style="bright_blue")
            proto_table.add_column("Count", justify="right")
            for protocol, count in sorted(results["protocols"].items(), key=lambda x: x[1], reverse=True):
                proto_table.add_row(protocol, format_int(count))
            console.print(proto_table)

        # Display findings if any
        if results.get("findings"):
            findings_count = results.get("findings_count", len(results["findings"]))
            by_severity = results.get("findings_by_severity", {})
            console.print(f"\n[bold {MODE_COLORS.get(mode.value, 'white')}]Findings[/] ({findings_count} total)")

            if by_severity:
                severity_summary = ", ".join(f"{sev}: {count}" for sev, count in sorted(by_severity.items(), reverse=True))
                console.print(f"  {severity_summary}")

            # Display top findings
            findings_table = Table(box=box.HEAVY_HEAD, show_lines=False)
            findings_table.add_column("Sev", style="yellow", width=4)
            findings_table.add_column("Conf", style="cyan", width=4)
            findings_table.add_column("Category", style="bright_blue", width=18)
            findings_table.add_column("Title", style="white")

            severity_colors = {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "cyan",
                "info": "bright_black",
            }

            for finding in results["findings"][:10]:  # Show top 10
                sev = finding.get("severity", "info")
                conf = finding.get("confidence", "low")
                category = finding.get("category", "unknown")
                title = finding.get("title", "Unknown Finding")

                sev_style = severity_colors.get(sev, "white")
                findings_table.add_row(
                    f"[{sev_style}]{sev[:4].upper()}[/]",
                    conf[:4].upper(),
                    category.replace("_", " ").title()[:18],
                    title[:80],
                )

            console.print(findings_table)

            if findings_count > 10:
                console.print(f"  [dim]... and {findings_count - 10} more findings[/]")

            console.print(f"\n  [dim]Use --output to export all findings to JSON[/]")

        if briefing:
            _render_memory_briefing_cli(briefing)

        if output:
            write_json(str(output), results)
            console.print(f"\n[green]✓[/] Results saved to [white]{output}[/]")
    except Exception as exc:
        console.print(f"\n[red bold]✗[/] [red]{exc}[/]")
        if verbose:
            logger.exception("Analysis failed")
        raise typer.Exit(1) from exc


@app.command("hosts")
def hosts(
    pcap_path: Path = typer.Argument(..., help="Path to PCAP/PCAPNG file", exists=True, dir_okay=False),
    mode: AnalysisMode = typer.Option(AnalysisMode.WHITE, "--mode", "-m", help="Analysis mode"),
    top: int = typer.Option(20, "--top", help="Limit to top N hosts"),
    direction: str = typer.Option("", "--direction", help="Filter: inbound, outbound, lateral, external"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Export JSON"),
) -> None:
    """Show per-host traffic analysis."""
    try:
        with AnalysisEngine(pcap_path, mode=mode) as engine:
            engine.analyze()
            stats = HostAnalyzer.query(engine)
        table = Table(title="Host Analysis", box=box.HEAVY_HEAD)
        table.add_column("#", justify="right", style="dim")
        table.add_column("Host", style="bright_white")
        table.add_column("Internal", justify="center")
        table.add_column("Packets", justify="right")
        table.add_column("Bytes", justify="right")
        table.add_column("Ratio", justify="right")
        table.add_column("Protocols", style="bright_blue")
        total_packets = sum(host.total_packets for host in stats)
        total_bytes = sum(host.total_bytes for host in stats)
        for index, host in enumerate(stats[:top], 1):
            ratio = (host.total_bytes / total_bytes * 100) if total_bytes else 0
            table.add_row(
                str(index),
                host.ip,
                "✓" if host.is_internal else "✗",
                format_int(host.total_packets),
                format_bytes(host.total_bytes),
                f"{ratio:.1f}%",
                ", ".join(sorted(host.protocols)[:4]),
            )
        console.print(table)
        if output:
            write_json(str(output), [host.to_dict() for host in stats[:top]])
            console.print(f"\n[green]✓[/] Exported to [white]{output}[/]")
    except Exception as exc:
        console.print(f"\n[red bold]✗[/] [red]{exc}[/]")
        raise typer.Exit(1) from exc


@app.command("conversations")
def conversations(
    pcap_path: Path = typer.Argument(..., help="Path to PCAP/PCAPNG file", exists=True, dir_okay=False),
    mode: AnalysisMode = typer.Option(AnalysisMode.WHITE, "--mode", "-m", help="Analysis mode"),
    top: int = typer.Option(20, "--top", help="Limit to top N conversations"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Export JSON"),
) -> None:
    """Show bidirectional conversation analysis."""
    try:
        with AnalysisEngine(pcap_path, mode=mode) as engine:
            engine.analyze()
            stats = ConversationAnalyzer.analyze(engine._load_packets_from_cache())
        if stats:
            table = Table(title="Top Conversations", box=box.HEAVY_HEAD)
            table.add_column("#", justify="right", style="dim")
            table.add_column("Host 1", style="bright_white")
            table.add_column("Host 2", style="bright_white")
            table.add_column("Proto", style="bright_blue")
            table.add_column("Packets", justify="right")
            table.add_column("Bytes", justify="right")
            table.add_column("Duration", justify="right")
            for index, conv in enumerate(stats[:top], 1):
                table.add_row(
                    str(index), conv.host1, conv.host2, conv.protocol,
                    format_int(conv.packet_count), format_bytes(conv.byte_count),
                    format_duration(conv.duration_seconds),
                )
            console.print(table)
        else:
            console.print("[yellow]No conversations found.[/]")
        if output:
            write_json(str(output), [conv.to_dict() for conv in stats[:top]])
            console.print(f"\n[green]✓[/] Exported to [white]{output}[/]")
    except Exception as exc:
        console.print(f"\n[red bold]✗[/] [red]{exc}[/]")
        raise typer.Exit(1) from exc


@app.command("findings")
def findings_command(
    pcap_path: Path = typer.Argument(..., help="Path to PCAP/PCAPNG file", exists=True, dir_okay=False),
    mode: AnalysisMode = typer.Option(AnalysisMode.BLUE, "--mode", "-m", help="Analysis mode"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Filter by severity: critical, high, medium, low, info"),
    category: Optional[str] = typer.Option(None, "--category", help="Filter by category"),
    limit: Optional[int] = typer.Option(None, "--limit", "-l", help="Limit packet count for analysis"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Export JSON"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show full details"),
) -> None:
    """Show security findings from Blue/Red mode analysis."""
    try:
        mode_config = get_mode_config(mode)
        color = MODE_COLORS.get(mode.value, "white")

        console.print(Panel.fit(
            f"[bold {color}]{mode_config.name} Findings[/]",
            subtitle=f"📄 {pcap_path.name}"
        ))

        with AnalysisEngine(pcap_path, mode=mode) as engine:
            results = engine.analyze(packet_limit=limit)

        findings_list = results.get("findings", [])

        # Apply filters
        if severity:
            findings_list = [f for f in findings_list if f.get("severity", "").lower() == severity.lower()]

        if category:
            findings_list = [f for f in findings_list if category.lower() in f.get("category", "").lower()]

        if not findings_list:
            console.print("[yellow]No findings detected.[/]")
            return

        console.print(f"\n[bold]Found {len(findings_list)} findings[/]\n")

        severity_colors = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "bright_black",
        }

        for idx, finding in enumerate(findings_list, 1):
            sev = finding.get("severity", "info")
            conf = finding.get("confidence", "low")
            cat = finding.get("category", "unknown").replace("_", " ").title()
            title = finding.get("title", "Unknown Finding")
            desc = finding.get("description", "")
            evidence = finding.get("evidence", [])
            recommendation = finding.get("recommendation", "")

            sev_style = severity_colors.get(sev, "white")

            # Create panel for each finding
            content = []
            content.append(f"[bold]Category:[/] {cat}")
            content.append(f"[bold]Severity:[/] [{sev_style}]{sev.upper()}[/]  [bold]Confidence:[/] {conf.upper()}")

            if finding.get("source_ip"):
                content.append(f"[bold]Source:[/] {finding['source_ip']}")
            if finding.get("destination_ip"):
                content.append(f"[bold]Destination:[/] {finding['destination_ip']}")

            content.append(f"\n{desc}")

            if verbose and evidence:
                content.append(f"\n[bold]Evidence:[/]")
                for ev in evidence[:5]:
                    content.append(f"  • {ev}")
                if len(evidence) > 5:
                    content.append(f"  ... and {len(evidence) - 5} more")

            if verbose and recommendation:
                content.append(f"\n[bold]Recommendation:[/]")
                content.append(f"  {recommendation}")

            panel = Panel(
                "\n".join(content),
                title=f"[{sev_style}]#{idx}[/] {title}",
                border_style=sev_style,
                expand=False,
            )
            console.print(panel)

        if output:
            write_json(str(output), findings_list)
            console.print(f"\n[green]✓[/] Findings exported to [white]{output}[/]")

    except Exception as exc:
        console.print(f"\n[red bold]✗[/] [red]{exc}[/]")
        raise typer.Exit(1) from exc


@app.command("protocols")
def protocols(
    pcap_path: Path = typer.Argument(..., help="Path to PCAP/PCAPNG file", exists=True, dir_okay=False),
    mode: AnalysisMode = typer.Option(AnalysisMode.WHITE, "--mode", "-m", help="Analysis mode"),
    dns: bool = typer.Option(False, "--dns", help="Show DNS details"),
    http: bool = typer.Option(False, "--http", help="Show HTTP details"),
    tls: bool = typer.Option(False, "--tls", help="Show TLS details"),
) -> None:
    """Show protocol distribution and extraction details."""
    try:
        with AnalysisEngine(pcap_path, mode=mode) as engine:
            engine.analyze()
        cursor = engine.db_conn.cursor()
        rows = cursor.execute(
            """SELECT app_proto, transport_proto, COUNT(*) AS count, SUM(length) AS bytes
               FROM packets WHERE app_proto IS NOT NULL OR transport_proto IS NOT NULL
               GROUP BY app_proto, transport_proto ORDER BY count DESC"""
        ).fetchall()
        if dns:
            _print_dns_details(cursor)
        if http:
            _print_http_details(cursor)
        if tls:
            _print_tls_details(cursor)
        if not dns and not http and not tls:
            table = Table(title="Protocol Distribution", box=box.HEAVY_HEAD)
            table.add_column("Protocol", style="bright_blue")
            table.add_column("Packets", justify="right")
            table.add_column("Bytes", justify="right")
            for row in rows:
                proto = row["app_proto"] or row["transport_proto"] or "unknown"
                table.add_row(proto, format_int(row["count"]), format_bytes(row["bytes"] or 0))
            console.print(table)
    except Exception as exc:
        console.print(f"\n[red bold]✗[/] [red]{exc}[/]")
        raise typer.Exit(1) from exc


def _print_dns_details(cursor) -> None:
    rows = cursor.execute("SELECT dns_query_name, COUNT(*) AS count FROM packets WHERE dns_query_name IS NOT NULL GROUP BY dns_query_name ORDER BY count DESC LIMIT 20").fetchall()
    table = Table(title="Top DNS Queries", box=box.HEAVY_HEAD)
    table.add_column("Query", style="bright_magenta")
    table.add_column("Count", justify="right")
    for row in rows:
        table.add_row(row["dns_query_name"], format_int(row["count"]))
    console.print(table)


def _print_http_details(cursor) -> None:
    rows = cursor.execute("SELECT http_host, http_method, http_uri, COUNT(*) AS count FROM packets WHERE http_host IS NOT NULL OR http_uri IS NOT NULL GROUP BY http_host, http_method, http_uri ORDER BY count DESC LIMIT 20").fetchall()
    table = Table(title="Top HTTP Requests", box=box.HEAVY_HEAD)
    table.add_column("Host", style="bright_blue")
    table.add_column("Method", style="bright_green")
    table.add_column("URI", style="white")
    for row in rows:
        table.add_row(row["http_host"] or "-", row["http_method"] or "-", row["http_uri"] or "-")
    console.print(table)


def _print_tls_details(cursor) -> None:
    rows = cursor.execute("SELECT tls_server_name, tls_version, COUNT(*) AS count FROM packets WHERE tls_server_name IS NOT NULL GROUP BY tls_server_name, tls_version ORDER BY count DESC LIMIT 20").fetchall()
    table = Table(title="TLS Connections", box=box.HEAVY_HEAD)
    table.add_column("Server", style="bright_white")
    table.add_column("Version", style="bright_yellow")
    table.add_column("Count", justify="right")
    for row in rows:
        table.add_row(row["tls_server_name"] or "-", row["tls_version"] or "-", format_int(row["count"]))
    console.print(table)


@app.command("timeline")
def timeline(
    pcap_path: Path = typer.Argument(..., help="Path to PCAP/PCAPNG file", exists=True, dir_okay=False),
    mode: AnalysisMode = typer.Option(AnalysisMode.WHITE, "--mode", "-m", help="Analysis mode"),
    limit: int = typer.Option(500, "--limit", help="Max timeline events to display"),
) -> None:
    """Show chronological event timeline."""
    try:
        with AnalysisEngine(pcap_path, mode=mode) as engine:
            packets = list(engine.tshark.read_packets_json(pcap_path, packet_limit=limit))
            parsed = [PacketParser.parse_json_packet(packet) for packet in packets]
            parsed = [p for p in parsed if p is not None]
            events = TimelineBuilder.build(parsed)
        display = events[:limit]
        if display:
            table = Table(title="Timeline", box=box.HEAVY_HEAD)
            table.add_column("Time", style="bright_black", width=24)
            table.add_column("Type", style="bright_blue", width=8)
            table.add_column("Source", style="bright_white", width=18)
            table.add_column("Dest", style="bright_white", width=18)
            table.add_column("Message", style="white")
            for event in display:
                table.add_row(
                    format_timestamp(event.timestamp), event.event_type, event.source, event.destination, event.message,
                )
            console.print(table)
        else:
            console.print("[yellow]No timeline events found.[/]")
    except Exception as exc:
        console.print(f"\n[red bold]✗[/] [red]{exc}[/]")
        raise typer.Exit(1) from exc


@app.command("ioc")
def ioc(
    pcap_path: Path = typer.Argument(..., help="Path to PCAP/PCAPNG file", exists=True, dir_okay=False),
    mode: AnalysisMode = typer.Option(AnalysisMode.WHITE, "--mode", "-m", help="Analysis mode"),
    export: Optional[Path] = typer.Option(None, "--export", "-o", help="Export JSON"),
) -> None:
    """Extract indicators of interest."""
    try:
        with AnalysisEngine(pcap_path, mode=mode) as engine:
            packets = list(engine.tshark.read_packets_json(pcap_path))
            parsed = [PacketParser.parse_json_packet(packet) for packet in packets]
            parsed = [p for p in parsed if p is not None]
        iocs = IOCExtractor.extract(parsed)
        table = Table(title="Indicators of Interest", box=box.HEAVY_HEAD)
        table.add_column("#", justify="right", style="dim")
        table.add_column("Type", style="bright_yellow")
        table.add_column("Value", style="bright_white")
        table.add_column("Count", justify="right")
        for index, item in enumerate(iocs[:50], 1):
            table.add_row(str(index), item.type.upper(), item.value, format_int(item.count))
        console.print(table)
        if export:
            write_json(str(export), [item.to_dict() for item in iocs])
            console.print(f"\n[green]✓[/] Exported to [white]{export}[/]")
    except Exception as exc:
        console.print(f"\n[red bold]✗[/] [red]{exc}[/]")
        raise typer.Exit(1) from exc


@app.command("packet")
def packet(
    pcap_path: Path = typer.Argument(..., help="Path to PCAP/PCAPNG file", exists=True, dir_okay=False),
    number: int = typer.Argument(..., help="Packet number to inspect"),
    mode: AnalysisMode = typer.Option(AnalysisMode.WHITE, "--mode", "-m", help="Analysis mode"),
) -> None:
    """Inspect a single packet in deep detail."""
    try:
        with AnalysisEngine(pcap_path, mode=mode) as engine:
            detail = engine.get_packet_detail(number)
            if not detail:
                # Stream until matching packet is found without loading all into memory
                for raw in engine.tshark.read_packets_json(pcap_path):
                    parsed = PacketParser.parse_json_packet(raw)
                    if parsed and parsed.number == number:
                        detail = PacketInspector.inspect(parsed)
                        break

        if not detail:
            console.print(f"[red bold]✗[/] Packet [white]{number}[/] not found")
            raise typer.Exit(1)

        table = Table(title=f"Packet #{number}", box=box.HEAVY_HEAD)
        table.add_column("Field", style="bright_blue", no_wrap=True)
        table.add_column("Value", style="white")
        for key, value in detail.items():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    if sub_value is not None and sub_value != "":
                        table.add_row(f"{key}.{sub_key}", escape(str(sub_value)))
            elif isinstance(value, list) and value:
                table.add_row(key, escape(", ".join(str(v) for v in value)))
            elif value is not None and value != "" and value != [] and value != {}:
                table.add_row(key, escape(str(value)))
        console.print(table)
    except Exception as exc:
        console.print(f"\n[red bold]✗[/] [red]{exc}[/]")
        raise typer.Exit(1) from exc


@app.command("report")
def report(
    pcap_path: Path = typer.Argument(..., help="Path to PCAP/PCAPNG file", exists=True, dir_okay=False),
    format: str = typer.Option("html", "--format", "-f", help="Report format: html, json, or csv"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    mode: AnalysisMode = typer.Option(AnalysisMode.BLUE, "--mode", "-m", help="Analysis mode"),
) -> None:
    """Generate a professional investigation report (HTML, JSON, CSV)."""
    try:
        from beacon.exports.reports import ReportGenerator

        with AnalysisEngine(pcap_path, mode=mode) as engine:
            results = engine.analyze()
            hosts = HostAnalyzer.query(engine)
            cursor = engine.db_conn.cursor()
            conv_rows = cursor.execute("SELECT * FROM conversations ORDER BY byte_count DESC LIMIT 50").fetchall()
            conversations = [
                {
                    "key": r["conversation_key"],
                    "host1": r["host1"],
                    "host2": r["host2"],
                    "port1": r["port1"],
                    "port2": r["port2"],
                    "protocol": r["protocol"],
                    "packet_count": r["packet_count"],
                    "byte_count": r["byte_count"],
                    "first_seen": r["first_seen"],
                    "last_seen": r["last_seen"],
                }
                for r in conv_rows
            ]
            full_data = {
                **results,
                "hosts": [h.to_dict() for h in hosts],
                "conversations": conversations,
                "timeline": engine.get_timeline_events(),
                "iocs": engine.get_iocs(),
            }

        fmt = format.lower()
        if fmt == "html":
            content = ReportGenerator.generate_html(full_data)
            out_path = output or Path(f"beacon_report_{pcap_path.stem}.html")
            out_path.write_text(content, encoding="utf-8")
        elif fmt == "json":
            content = ReportGenerator.generate_json(full_data)
            out_path = output or Path(f"beacon_report_{pcap_path.stem}.json")
            out_path.write_text(content, encoding="utf-8")
        elif fmt == "csv":
            content = ReportGenerator.generate_findings_csv(full_data.get("findings", []))
            out_path = output or Path(f"beacon_findings_{pcap_path.stem}.csv")
            out_path.write_text(content, encoding="utf-8")
        else:
            console.print(f"[red bold]✗[/] Unsupported report format: [white]{format}[/]. Choose html, json, or csv.")
            raise typer.Exit(1)

        console.print(f"[green bold]✓[/] Generated [bright_blue]{fmt.upper()}[/] report at: [white]{out_path}[/]")
    except Exception as exc:
        console.print(f"\n[red bold]✗[/] [red]{exc}[/]")
        raise typer.Exit(1) from exc



@app.command("info")
def info(pcap_path: Path = typer.Argument(..., help="Path to PCAP/PCAPNG file", exists=True, dir_okay=False)) -> None:
    """Show capture file metadata."""
    try:
        from beacon.core.tshark_interface import get_tshark_interface
        tshark = get_tshark_interface()
        info = tshark.get_capture_info(pcap_path)
        table = Table(title=f"Capture Info: {pcap_path.name}", box=box.HEAVY_HEAD)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        for key, value in info.items():
            table.add_row(key, str(value))
        console.print(table)
    except Exception as exc:
        console.print(f"\n[red bold]✗[/] [red]{exc}[/]")
        raise typer.Exit(1) from exc


@app.command("version-info")
def version_info() -> None:
    """Show Beacon and environment version details."""
    console.print(f"[bold bright_blue]Beacon[/] version [white]{__version__}[/]")
    console.print("\n[bold]Dependencies[/]")
    try:
        from beacon.core.tshark_interface import get_tshark_interface
        tshark = get_tshark_interface()
        console.print(f"  TShark: [green]✓[/] {tshark.tshark_info.version}")
    except Exception as exc:
        console.print(f"  TShark: [red]✗[/] Not found - {exc}")
    console.print(f"  Python: [white]{sys.version.split()[0]}[/]")


# -------------------------------------------------------------------------
# Beacon Memory CLI Commands & Render Helpers
# -------------------------------------------------------------------------

def _render_memory_briefing_cli(briefing: Dict[str, Any]) -> None:
    """Render executive change briefing in Rich panels and tables."""
    health = briefing.get("baseline_health", "established")
    health_colors = {
        "established": "green",
        "limited": "yellow",
        "insufficient": "blue",
        "incompatible": "red bold",
    }
    h_col = health_colors.get(health, "white")

    panel_title = f"[bold cyan]Beacon Memory[/] • [bold {h_col}]Baseline: {health.upper()}[/] ({briefing.get('baseline_captures_count', 0)} captures in memory)"
    warning = briefing.get("baseline_warning")
    warning_text = f"\n[yellow]⚠ {warning}[/]\n" if warning else ""

    brief_grid = Table.grid(padding=(0, 2))
    brief_grid.add_column(style="dim")
    brief_grid.add_column(style="bold white")
    brief_grid.add_column(style="dim")
    brief_grid.add_column(style="bold white")

    brief_grid.add_row("Total Changes:", str(briefing.get("total_changes_detected", 0)), "New Destinations:", str(briefing.get("new_destinations_count", 0)))
    brief_grid.add_row("New Relationships:", str(briefing.get("new_relationships_count", 0)), "Service Shifts:", str(briefing.get("service_shifts_count", 0)))
    brief_grid.add_row("Volume Deviations:", str(briefing.get("volume_deviations_count", 0)), "Recurring Anomalies:", str(briefing.get("recurring_anomalies_count", 0)))

    console.print()
    console.print(Panel(
        brief_grid,
        title=panel_title,
        subtitle=f"History: {format_duration(briefing.get('baseline_duration_seconds', 0.0))} indexed" if briefing.get('baseline_captures_count', 0) > 0 else "Foundational Baseline",
        border_style="cyan",
    ))
    if warning_text:
        console.print(warning_text)

    top_cand = briefing.get("top_investigation_candidate")
    if top_cand:
        cand_panel = Panel(
            f"[bold white]{top_cand.get('title')}[/]\n"
            f"[dim]Fact:[/] {top_cand.get('observed_fact')}\n"
            f"[dim]Hypothesis:[/] [yellow]{top_cand.get('inferred_hypothesis')}[/]\n"
            f"[dim]Alternative:[/] [green]{top_cand.get('alternative_benign_explanation')}[/]\n"
            f"[dim]Priority Score:[/] [bold cyan]{top_cand.get('priority_score', 0):.1f}[/] | [dim]Confidence:[/] [bold]{top_cand.get('confidence', '').upper()}[/]",
            title="[bold yellow]★ Top Investigation Candidate[/]",
            border_style="yellow",
        )
        console.print(cand_panel)

    items = briefing.get("items", [])
    if items:
        _render_changes_table_cli(items[:10])


def _render_changes_table_cli(items: List[Dict[str, Any]], title: str = "Ranked Changes") -> None:
    """Render table of ranked behavioral and structural changes."""
    table = Table(title=title, box=box.HEAVY_HEAD, show_lines=True)
    table.add_column("Rank", style="dim", width=4, justify="right")
    table.add_column("Category", style="cyan", width=18)
    table.add_column("Entity", style="bright_blue", width=22)
    table.add_column("Observed Fact & Hypothesis", style="white")
    table.add_column("Conf", style="green", width=6)
    table.add_column("Status", style="yellow", width=10)

    for idx, item in enumerate(items, 1):
        cat = item.get("category", "").replace("_", " ").title()
        entity = item.get("entity", "")
        fact = item.get("observed_fact", "")
        hypo = item.get("inferred_hypothesis", "")
        conf = item.get("confidence", "med")[:4].upper()
        fb = item.get("analyst_feedback")
        status = "[green]EXPECTED[/]" if fb and fb.get("is_expected") else "[dim]Unreviewed[/]"

        cell_text = Text()
        cell_text.append(f"{fact}\n", style="white")
        cell_text.append("Hypothesis: ", style="bold yellow")
        cell_text.append(f"{hypo}", style="italic dim")

        table.add_row(str(idx), cat, entity, cell_text, conf, status)

    console.print(table)


memory_app = typer.Typer(
    name="memory",
    help="Beacon Memory - Local-first historical baseline and explainable change detection",
    no_args_is_help=True,
)
app.add_typer(memory_app, name="memory")


@memory_app.command("status")
def memory_status() -> None:
    """Show Beacon Memory historical baseline depth, coverage, and tracked entities."""
    from beacon.memory.store import MemoryStore
    store = MemoryStore()
    summary = store.get_baseline_summary()

    table = Table(title="Beacon Memory Baseline Status", box=box.HEAVY_HEAD)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Historical Captures", str(summary["captures_count"]))
    table.add_row("Total History Timespan", format_duration(summary["total_duration_seconds"]))
    table.add_row("Total Wire Volume", format_bytes(summary["total_bytes"]))
    table.add_row("Indexed Hosts", f"{summary['hosts_count']} ({summary['internal_hosts_count']} internal, {summary['external_hosts_count']} external)")
    table.add_row("Communication Relationships", str(summary["relationships_count"]))
    table.add_row("Unique Destinations (IP/Domain)", str(summary["destinations_count"]))
    table.add_row("Tracked DNS Names", str(summary["dns_queries_count"]))
    table.add_row("Recurring Anomalies", str(summary["recurring_anomalies_count"]))
    table.add_row("Analyst Feedback Rules", str(summary["analyst_feedback_count"]))
    table.add_row("Internal Subnet Space", ", ".join(summary["internal_subnets"]) if summary["internal_subnets"] else "Default private CIDRs")
    if summary["last_capture_filename"]:
        from datetime import datetime, timezone
        last_time_str = datetime.fromtimestamp(summary["last_capture_analyzed_at"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if summary.get("last_capture_analyzed_at") else "N/A"
        table.add_row("Most Recent Ingest", f"{summary['last_capture_filename']} ({last_time_str})")

    console.print(table)


@memory_app.command("briefing")
def memory_briefing(
    pcap_path: Path = typer.Argument(..., help="Path to PCAP/PCAPNG file", exists=True, dir_okay=False),
    mode: AnalysisMode = typer.Option(AnalysisMode.WHITE, "--mode", "-m", help="Analysis mode"),
) -> None:
    """Analyze a capture and display its Beacon Memory Change Briefing."""
    with AnalysisEngine(pcap_path, mode=mode) as engine:
        engine.analyze()
        briefing = engine.get_memory_briefing()
    _render_memory_briefing_cli(briefing)


@memory_app.command("changes")
def memory_changes(
    pcap_path: Path = typer.Argument(..., help="Path to PCAP/PCAPNG file", exists=True, dir_okay=False),
    mode: AnalysisMode = typer.Option(AnalysisMode.WHITE, "--mode", "-m", help="Analysis mode"),
    limit: int = typer.Option(20, "--limit", "-l", help="Max candidates to show"),
) -> None:
    """Show ranked investigation candidates and behavioral deviations against baseline."""
    with AnalysisEngine(pcap_path, mode=mode) as engine:
        engine.analyze()
        briefing = engine.get_memory_briefing()
    items = briefing.get("items", [])
    if not items:
        console.print("[green]✓[/] No behavioral deviations or new entities detected against baseline.")
    else:
        _render_changes_table_cli(items[:limit], title=f"Ranked Changes: {pcap_path.name}")


@memory_app.command("recurring")
def memory_recurring() -> None:
    """Show recurring anomalies and security detections observed across multiple captures."""
    from beacon.memory.store import MemoryStore
    from datetime import datetime, timezone
    store = MemoryStore()
    anomalies = store.get_recurring_anomalies()

    if not anomalies:
        console.print("[dim]No recurring anomalies recorded across historical captures.[/]")
        return

    table = Table(title="Tracked Recurring Anomalies", box=box.HEAVY_HEAD)
    table.add_column("Occurrences", style="bold red", width=12, justify="right")
    table.add_column("Category", style="cyan", width=18)
    table.add_column("Entity / Target", style="bright_blue", width=20)
    table.add_column("Anomaly Title", style="white")
    table.add_column("First Seen", style="dim", width=18)
    table.add_column("Status", style="yellow", width=12)

    for a in anomalies:
        first_time = datetime.fromtimestamp(a["first_seen"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M") if a.get("first_seen") else "N/A"
        fb = a.get("feedback")
        status = "[green]EXPECTED[/]" if fb and fb.get("is_expected") else "[dim]Unreviewed[/]"
        table.add_row(
            f"{a['occurrences']} captures",
            a["category"][:18],
            a["entity"][:20],
            a["title"],
            first_time,
            status,
        )

    console.print(table)


@memory_app.command("ack")
def memory_ack(
    target_key: str = typer.Argument(..., help="Entity IP, domain, relationship key, or anomaly signature"),
    note: str = typer.Option("", "--note", "-n", help="Analyst investigation note / justification"),
    expected: bool = typer.Option(True, "--expected/--unexpected", help="Mark behavior as expected or unexpected"),
    target_type: str = typer.Option("host", "--type", "-t", help="Entity type: host, relationship, destination, or anomaly"),
) -> None:
    """Mark an entity, relationship, or anomaly as expected with analyst notes."""
    from beacon.memory.store import MemoryStore
    store = MemoryStore()
    status = "expected" if expected else "investigating"
    record = store.save_analyst_feedback(
        target_key=target_key,
        target_type=target_type,
        status=status,
        is_expected=expected,
        note=note,
    )
    console.print(f"[green bold]✓[/] Recorded analyst feedback for [white]{target_key}[/]: [cyan]{status}[/]")
    if note:
        console.print(f"  Note: [dim italic]{note}[/]")


# -------------------------------------------------------------------------
# Beacon Live — Continuous Network Capture & Smart Evidence Retention CLI
# -------------------------------------------------------------------------

live_app = typer.Typer(
    name="live",
    help="Beacon Live - Continuous 24/7 network capture & smart evidence retention",
    no_args_is_help=True,
)
app.add_typer(live_app, name="live")


@live_app.command("interfaces")
def live_interfaces() -> None:
    """List available network capture interfaces detected by TShark."""
    from beacon.live import get_live_service
    service = get_live_service()
    ifaces = service.get_available_interfaces()

    if not ifaces:
        console.print("[yellow]No network capture interfaces detected by TShark.[/]")
        console.print("[dim]Ensure Npcap / WinPcap is installed and TShark is available in your PATH.[/]")
        return

    table = Table(title="Available Capture Interfaces", box=box.HEAVY_HEAD)
    table.add_column("ID", style="bold cyan", width=6, justify="right")
    table.add_column("Name / Device", style="bright_blue", width=36)
    table.add_column("Description", style="white")
    table.add_column("Addresses", style="dim", width=22)
    table.add_column("Loopback", style="yellow", width=10, justify="center")

    for iface in ifaces:
        addrs = ", ".join(iface.addresses) if iface.addresses else "-"
        is_loop = "[yellow]Yes[/]" if iface.is_loopback else "[dim]No[/]"
        table.add_row(
            str(iface.id),
            iface.name,
            iface.description or "-",
            addrs,
            is_loop,
        )

    console.print(table)
    console.print("\n[dim]To start continuous monitoring, run: [bold white]beacon live start <ID>[/][/]\n")


@live_app.command("status")
def live_status() -> None:
    """Show current Live Capture telemetry, buffer health, and retained incidents."""
    from beacon.live import get_live_service
    service = get_live_service()
    stats = service.get_stats()

    status_color = "green" if stats.status.value == "capturing" else "yellow" if stats.status.value == "paused" else "dim"
    table = Table(title=f"Beacon Live Status: [{status_color}]{stats.status.value.upper()}[/]", box=box.HEAVY_HEAD)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Status", f"[{status_color}]{stats.status.value.upper()}[/]")
    table.add_row("Interface", stats.selected_interface or "None")
    table.add_row("Active Filter", stats.capture_filter or "None (All Packets)")
    table.add_row("Uptime / Duration", format_duration(stats.elapsed_seconds))
    table.add_row("Total Packets", format_int(stats.total_packets))
    table.add_row("Total Wire Bytes", format_bytes(stats.total_bytes))
    table.add_row("Packet Rate", f"{stats.packets_per_second:.1f} pkts/sec")
    table.add_row("Data Rate", f"{format_bytes(int(stats.bytes_per_second))}/s")
    table.add_row("Buffer Occupancy", f"{stats.buffer_occupancy} / {stats.buffer_capacity} packets ({format_bytes(stats.buffer_memory_bytes)})")
    table.add_row("Process RSS Memory", f"{stats.process_memory_mb:.1f} MB")
    table.add_row("Dropped Packets", str(stats.dropped_packets))
    table.add_row("Preserved Incidents", f"{stats.incidents_count} ({stats.pinned_incidents_count} pinned)")
    table.add_row("Active Collection Windows", str(stats.active_collection_windows_count))

    console.print(table)


@live_app.command("start")
def live_start(
    interface: str = typer.Argument(..., help="Interface ID (e.g. 1) or interface name from 'beacon live interfaces'"),
    capture_filter: Optional[str] = typer.Option(None, "--filter", "-f", help="BPF capture filter (e.g. 'tcp port 80 or udp port 53')"),
    buffer: int = typer.Option(1000, "--buffer", "-b", help="Rolling buffer packet capacity"),
    mode: AnalysisMode = typer.Option(AnalysisMode.WHITE, "--mode", "-m", help="Analysis mode (blue, red, white)"),
) -> None:
    """Start continuous live network capture with real-time terminal telemetry and alerts."""
    import time
    from rich.live import Live
    from rich.panel import Panel
    from beacon.live import get_live_service

    service = get_live_service()
    success = service.start_capture(
        interface_id=interface,
        capture_filter=capture_filter,
        buffer_capacity=buffer,
        mode=mode.value,
    )

    if not success:
        console.print(f"[red bold]✗ Failed to start live capture:[/] {service.error_message or 'Unknown error'}")
        raise typer.Exit(code=1)

    console.print(f"[green bold]✓ Live Capture started on interface {interface}[/]")
    console.print(f"[dim]Press [bold white]Ctrl+C[/] at any time to safely stop and review preserved incidents.[/]\n")

    def build_dashboard_display() -> Panel:
        stats = service.get_stats()
        status_style = "bold green" if stats.status.value == "capturing" else "bold yellow"

        # Telemetry header grid
        grid = Table.grid(expand=True)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)

        pct_buf = int((stats.buffer_occupancy / max(1, stats.buffer_capacity)) * 100)
        grid.add_row(
            f"Status: [{status_style}]{stats.status.value.upper()}[/]",
            f"Rate: [bold cyan]{stats.packets_per_second:.1f}[/] pps | [bold cyan]{format_bytes(int(stats.bytes_per_second))}/s[/]",
            f"Buffer: [bold white]{stats.buffer_occupancy}[/]/{stats.buffer_capacity} ({pct_buf}%)",
            f"Incidents: [bold red]{stats.incidents_count}[/] ({stats.pinned_incidents_count} pinned)",
        )
        grid.add_row(
            f"Uptime: [dim]{format_duration(stats.elapsed_seconds)}[/]",
            f"Total: [bold white]{format_int(stats.total_packets)}[/] pkts ({format_bytes(stats.total_bytes)})",
            f"RAM: [dim]{stats.process_memory_mb:.1f} MB[/]",
            f"Windows Open: [dim]{stats.active_collection_windows_count}[/]",
        )

        # Recent Packets Mini Table
        pkts_table = Table(box=box.SIMPLE, expand=True, padding=(0, 1), show_edge=False)
        pkts_table.add_column("#", style="dim", width=6, justify="right")
        pkts_table.add_column("Time", style="dim", width=12)
        pkts_table.add_column("Source", style="cyan", width=22)
        pkts_table.add_column("Destination", style="bright_blue", width=22)
        pkts_table.add_column("Proto", style="yellow", width=8)
        pkts_table.add_column("Bytes", style="dim", width=8, justify="right")
        pkts_table.add_column("Info", style="white")

        recent_packets = service.buffer.get_recent(limit=8)
        for p in reversed(recent_packets):
            from datetime import datetime, timezone
            time_str = datetime.fromtimestamp(p.timestamp, tz=timezone.utc).strftime("%H:%M:%S.%f")[:12] if p.timestamp else "-"
            src_str = f"{p.ip_src}:{p.src_port}" if p.src_port else (p.ip_src or "-")
            dst_str = f"{p.ip_dst}:{p.dst_port}" if p.dst_port else (p.ip_dst or "-")
            proto = (p.app_proto or p.transport_proto or "OTHER").upper()
            info = p.http_uri or p.dns_query_name or p.tls_server_name or p.tcp_flags or ""
            pkts_table.add_row(
                str(p.number),
                time_str,
                src_str[:22],
                dst_str[:22],
                proto[:8],
                str(p.length),
                info[:40],
            )

        container = Table.grid(expand=True)
        container.add_column()
        container.add_row(grid)
        container.add_row(Text("─" * 70, style="dim"))
        container.add_row(pkts_table)

        # If any incidents, display active alert summary
        if stats.incidents_count > 0:
            incidents = service.evidence_store.get_incidents(limit=3)
            alert_lines = []
            for inc in incidents:
                status_badge = f"[{'green' if inc.evidence_status.value == 'complete' else 'yellow'}]{inc.evidence_status.value.upper()}[/]"
                alert_lines.append(f"  • [{inc.severity.lower() == 'critical' and 'bold red' or 'bold yellow'}]{inc.severity.upper()}[/] {inc.title} ({inc.target_entity}) - Status: {status_badge} [{inc.total_retained_packets} pkts preserved]")
            container.add_row(Text("─" * 70, style="red dim"))
            container.add_row(Text("\n".join(alert_lines)))

        return Panel(
            container,
            title=f"[bold bright_blue]Beacon Live Continuous Monitor[/] [dim](Iface: {interface} | Mode: {mode.value.upper()})[/]",
            subtitle="[dim]Press Ctrl+C to stop capture[/]",
            border_style="bright_blue",
        )

    try:
        with Live(build_dashboard_display(), refresh_per_second=2, console=console) as live:
            while service.status.value in ("capturing", "paused"):
                time.sleep(0.5)
                live.update(build_dashboard_display())
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping live capture gracefully...[/]")
    finally:
        service.stop_capture()
        stats = service.get_stats()
        console.print(f"[green]✓ Live capture stopped.[/]")
        console.print(f"  Total Packets: [bold white]{format_int(stats.total_packets)}[/]")
        console.print(f"  Total Duration: [bold white]{format_duration(stats.elapsed_seconds)}[/]")
        console.print(f"  Preserved Incidents: [bold red]{stats.incidents_count}[/] ({stats.pinned_incidents_count} pinned)")
        if stats.incidents_count > 0:
            console.print("[dim]Use [bold white]beacon live incidents[/] to review or [bold white]beacon live export <ID>[/] to save standard PCAP.[/]\n")


@live_app.command("incidents")
def live_incidents(
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity (critical, high, medium, low)"),
    pinned_only: bool = typer.Option(False, "--pinned", "-p", help="Show only analyst-pinned incidents"),
    limit: int = typer.Option(50, "--limit", "-l", help="Maximum incidents to return"),
) -> None:
    """List preserved security incidents with packet evidence status."""
    from beacon.live import get_live_service
    from datetime import datetime, timezone
    service = get_live_service()
    incidents = service.evidence_store.get_incidents(
        severity_filter=severity,
        pinned_only=pinned_only,
        limit=limit,
    )

    if not incidents:
        console.print("[dim]No preserved security incidents found matching criteria.[/]")
        return

    table = Table(title=f"Preserved Incidents ({len(incidents)} shown / {service.evidence_store.incidents_count} total)", box=box.HEAVY_HEAD)
    table.add_column("Incident ID", style="bold cyan", width=18)
    table.add_column("Severity", width=10)
    table.add_column("Title / Category", style="white")
    table.add_column("Target Entity", style="bright_blue", width=20)
    table.add_column("Packets", style="green", width=10, justify="right")
    table.add_column("Evidence Status", width=14, justify="center")
    table.add_column("Pinned", width=8, justify="center")
    table.add_column("Time", style="dim", width=14)

    for inc in incidents:
        sev_color = "bold red" if inc.severity.lower() == "critical" else "bold yellow" if inc.severity.lower() == "high" else "cyan"
        time_str = datetime.fromtimestamp(inc.created_timestamp, tz=timezone.utc).strftime("%H:%M:%S") if inc.created_timestamp else "-"
        status_color = "green" if inc.evidence_status.value == "complete" else "yellow" if inc.evidence_status.value == "collecting" else "magenta"
        pinned_badge = "[bold green]📌 Yes[/]" if inc.analyst_pinned else "[dim]No[/]"

        table.add_row(
            inc.id,
            f"[{sev_color}]{inc.severity.upper()}[/]",
            f"{inc.title}\n[dim]{inc.category}[/]",
            inc.target_entity,
            str(inc.total_retained_packets),
            f"[{status_color}]{inc.evidence_status.value.upper()}[/]",
            pinned_badge,
            time_str,
        )

    console.print(table)
    console.print("\n[dim]To inspect: [bold white]beacon live incident <ID>[/] | To export: [bold white]beacon live export <ID> [out.pcap][/][/]\n")


@live_app.command("incident")
def live_incident_detail(
    incident_id: str = typer.Argument(..., help="ID of the preserved incident (e.g. inc-1718000000-42)"),
) -> None:
    """Inspect complete preserved incident evidence, timeline, and packets."""
    from beacon.live import get_live_service
    from datetime import datetime, timezone
    service = get_live_service()
    inc = service.evidence_store.get_incident(incident_id)

    if not inc:
        console.print(f"[red bold]✗ Incident '{incident_id}' not found.[/]")
        raise typer.Exit(code=1)

    sev_color = "bold red" if inc.severity.lower() == "critical" else "bold yellow" if inc.severity.lower() == "high" else "cyan"
    console.print(Panel.fit(
        f"[{sev_color}]{inc.severity.upper()}[/] [bold white]{inc.title}[/]\n"
        f"Category: [cyan]{inc.category}[/] | Confidence: [yellow]{inc.confidence.upper()}[/] | ID: [bold]{inc.id}[/]\n"
        f"Target: [bright_blue]{inc.target_entity}[/] | Pinned: {'[green]Yes[/]' if inc.analyst_pinned else '[dim]No[/]'}\n"
        f"Evidence Status: [bold]{inc.evidence_status.value.upper()}[/]"
        + (f" ([yellow]{inc.missing_context_reason}[/])" if inc.missing_context_reason else "")
        + (f"\nAnalyst Notes: [italic dim]{inc.analyst_notes}[/]" if inc.analyst_notes else ""),
        title=f"Incident Details: {inc.id}",
        border_style="bright_blue",
    ))

    # Evidence Packet Breakdown
    table = Table(
        title=f"Preserved Packet Evidence ({inc.total_retained_packets} packets: {len(inc.pre_trigger_packets)} pre-trigger, 1 trigger, {len(inc.post_trigger_packets)} post-trigger)",
        box=box.HEAVY_HEAD,
    )
    table.add_column("Type", width=12)
    table.add_column("#", style="dim", width=6, justify="right")
    table.add_column("Time", style="dim", width=12)
    table.add_column("Source", style="cyan", width=22)
    table.add_column("Destination", style="bright_blue", width=22)
    table.add_column("Proto", style="yellow", width=8)
    table.add_column("Bytes", style="dim", width=8, justify="right")
    table.add_column("Summary / Context", style="white")

    all_pkts = inc.get_all_packets_ordered()
    for pkt in all_pkts:
        time_str = datetime.fromtimestamp(pkt.timestamp, tz=timezone.utc).strftime("%H:%M:%S.%f")[:12] if pkt.timestamp else "-"
        src_str = f"{pkt.ip_src}:{pkt.src_port}" if pkt.src_port else (pkt.ip_src or "-")
        dst_str = f"{pkt.ip_dst}:{pkt.dst_port}" if pkt.dst_port else (pkt.ip_dst or "-")
        proto = (pkt.app_proto or pkt.transport_proto or "OTHER").upper()

        if pkt.number == inc.trigger_packet.number:
            pkt_type = "[bold red]⚡ TRIGGER[/]"
        elif pkt.number < inc.trigger_packet.number:
            pkt_type = "[cyan]PRE-TRIGGER[/]"
        else:
            pkt_type = "[yellow]POST-TRIGGER[/]"

        info = pkt.http_uri or pkt.dns_query_name or pkt.tls_server_name or pkt.tcp_flags or ""
        table.add_row(
            pkt_type,
            str(pkt.number),
            time_str,
            src_str[:22],
            dst_str[:22],
            proto[:8],
            str(pkt.length),
            info[:35],
        )

    console.print(table)


@live_app.command("pin")
def live_pin(
    incident_id: str = typer.Argument(..., help="Incident ID to pin or unpin"),
    unpin: bool = typer.Option(False, "--unpin", "-u", help="Unpin the incident instead of pinning"),
) -> None:
    """Pin or unpin an incident to prevent or allow FIFO eviction."""
    from beacon.live import get_live_service
    service = get_live_service()
    success = service.evidence_store.set_incident_pin(incident_id, pinned=not unpin)
    if not success:
        console.print(f"[red bold]✗ Incident '{incident_id}' not found.[/]")
        raise typer.Exit(code=1)
    action = "Unpinned" if unpin else "Pinned"
    console.print(f"[green bold]✓ {action} incident [white]{incident_id}[/]. Protection state updated.[/]")


@live_app.command("note")
def live_note(
    incident_id: str = typer.Argument(..., help="Incident ID to attach note to"),
    note: str = typer.Argument(..., help="Analyst investigation notes"),
) -> None:
    """Attach analyst investigation notes to a preserved incident."""
    from beacon.live import get_live_service
    service = get_live_service()
    success = service.evidence_store.update_incident_notes(incident_id, notes=note)
    if not success:
        console.print(f"[red bold]✗ Incident '{incident_id}' not found.[/]")
        raise typer.Exit(code=1)
    console.print(f"[green bold]✓ Updated analyst notes for incident [white]{incident_id}[/].[/]")


@live_app.command("export")
def live_export(
    incident_id: str = typer.Argument(..., help="Incident ID to export"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Target PCAP output file path"),
) -> None:
    """Export the preserved packets for an incident into a standard PCAP file."""
    from beacon.live import get_live_service
    service = get_live_service()
    out_file = service.evidence_store.export_incident_pcap(incident_id, output_path=output)

    if not out_file or not out_file.exists():
        console.print(f"[red bold]✗ Failed to export incident '{incident_id}'. Incident not found or write error.[/]")
        raise typer.Exit(code=1)

    console.print(f"[green bold]✓ Exported incident [white]{incident_id}[/] to PCAP:[/] [cyan]{out_file}[/]")
    console.print(f"[dim]You can analyze this incident file with: [bold white]beacon analyze {out_file}[/][/]")


@app.command("serve")
def serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host address to bind the server to (use 0.0.0.0 for LAN access)"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to listen on"),
    pin: Optional[str] = typer.Option(None, "--pin", help="Optional access PIN to require from remote clients"),
    low_resource: bool = typer.Option(False, "--low-resource", help="Enable low-resource mode for older hardware"),
    reload: bool = typer.Option(False, "--reload", help="Enable live code reloading for development"),
) -> None:
    """Launch the Beacon investigation web server for local and remote access."""
    import os
    import socket

    if low_resource:
        os.environ["BEACON_LOW_RESOURCE"] = "1"
        os.environ["BEACON_BUFFER_CAPACITY"] = "500"

    if pin:
        os.environ["BEACON_PIN"] = pin.strip()

    # Discover local LAN IP
    local_lan_ip = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_lan_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    # Header display
    console.print()
    profile_text = "[bold green]ACTIVE (RAM & CPU Optimized)[/]" if low_resource else "[dim]Standard[/]"
    pin_text = f"[bold yellow]{pin}[/]" if pin else "[dim]None (Open access on trusted LAN)[/]"
    console.print(Panel.fit(
        f"[bold bright_cyan]BEACON CYBERSECURITY INVESTIGATION PLATFORM[/]\n"
        f"[dim]Version {__version__} • Profile:[/] {profile_text}\n\n"
        f"  [bold green]➜ Local Access:[/]   [white underline]http://localhost:{port}[/]\n"
        f"  [bold cyan]➜ Remote / LAN:[/]   [white underline]http://{local_lan_ip}:{port}[/]  [dim](ASUS laptop, smartphone)[/]\n"
        f"  [bold yellow]➜ Access PIN:[/]     {pin_text}\n\n"
        f"[dim]Firewall rule (Windows):[/] [dim italic]netsh advfirewall firewall add rule name=\"Beacon\" dir=in action=allow protocol=TCP localport={port}[/]",
        title="[bold white]Beacon Server Online[/]",
        border_style="bright_blue",
    ))
    console.print()

    import uvicorn
    uvicorn.run("beacon.api.server:app", host=host, port=port, reload=reload)


def cli_main() -> None:
    app()


if __name__ == "__main__":
    cli_main()

