"""
firewall_manager.py — Dynamic Firewall Manager
===============================================
Portfolio Project | Don Achema (@Don-cybertech)

Commands:
  block    – Block an IP address or CIDR range
  allow    – Whitelist an IP address
  remove   – Remove an active rule by ID
  status   – View all active firewall rules
  monitor  – Auto-block IPs based on threat intelligence
  log      – View recent activity log

Examples:
  python firewall_manager.py block --ip 192.168.1.100 --reason "Suspicious activity"
  python firewall_manager.py allow --ip 10.0.0.5 --reason "Trusted server"
  python firewall_manager.py remove --id FW-0001
  python firewall_manager.py status
  python firewall_manager.py status --blocked
  python firewall_manager.py monitor
  python firewall_manager.py log
"""

import argparse
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.columns import Columns
from rich import box

import rule_engine as re_
import ip_utils    as ipu


console = Console()

BANNER = """[bold cyan]
 ███████╗██╗██████╗ ███████╗██╗    ██╗ █████╗ ██╗     ██╗
 ██╔════╝██║██╔══██╗██╔════╝██║    ██║██╔══██╗██║     ██║
 █████╗  ██║██████╔╝█████╗  ██║ █╗ ██║███████║██║     ██║
 ██╔══╝  ██║██╔══██╗██╔══╝  ██║███╗██║██╔══██║██║     ██║
 ██║     ██║██║  ██║███████╗╚███╔███╔╝██║  ██║███████╗███████╗
 ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝[/bold cyan]
[bold cyan] ███╗   ███╗ █████╗ ███╗   ██╗ █████╗  ██████╗ ███████╗██████╗ [/bold cyan]
[bold cyan] ████╗ ████║██╔══██╗████╗  ██║██╔══██╗██╔════╝ ██╔════╝██╔══██╗[/bold cyan]
[bold cyan] ██╔████╔██║███████║██╔██╗ ██║███████║██║  ███╗█████╗  ██████╔╝[/bold cyan]
[bold cyan] ██║╚██╔╝██║██╔══██║██║╚██╗██║██╔══██║██║   ██║██╔══╝  ██╔══██╗[/bold cyan]
[bold cyan] ██║ ╚═╝ ██║██║  ██║██║ ╚████║██║  ██║╚██████╔╝███████╗██║  ██║[/bold cyan]
[bold cyan] ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝[/bold cyan]
[dim]Dynamic Firewall Manager  |  Portfolio Project  |  Don Achema[/dim]"""


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _action_color(action: str) -> str:
    return "#ff4c4c" if action == "BLOCK" else "#4caf50"


def _threat_style(label: str) -> str:
    return {
        "CRITICAL": "bold red",
        "HIGH":     "bold dark_orange",
        "MEDIUM":   "bold yellow",
        "LOW":      "bold cyan",
        "SAFE":     "bold green",
    }.get(label, "white")


def _print_rule_panel(rule: dict, title: str = "Rule Created"):
    action = rule["action"]
    color  = _action_color(action)
    geo    = rule.get("geo", {})

    content = Text()
    content.append(f"\n  Rule ID:    ", style="dim"); content.append(rule["id"], style="bold")
    content.append(f"\n  Action:     ", style="dim"); content.append(f"  {action}  ", style=f"bold on {color} black")
    content.append(f"\n  IP:         ", style="dim"); content.append(rule["ip"], style="bold cyan")
    content.append(f"\n  Reason:     ", style="dim"); content.append(rule["reason"])
    content.append(f"\n  Added by:   ", style="dim"); content.append(rule["added_by"])
    content.append(f"\n  Threat:     ", style="dim")
    content.append(rule["threat"], style=_threat_style(rule["threat"]))
    content.append(f"  (score: {rule['threat_score']}/100)")
    content.append(f"\n  Location:   ", style="dim")
    content.append(f"{geo.get('city','—')}, {geo.get('country','—')}")
    content.append(f"\n  ISP/Org:    ", style="dim"); content.append(geo.get("org", "—"))
    content.append(f"\n  Created:    ", style="dim"); content.append(rule["created_at"])
    content.append("\n")

    console.print(Panel(content, title=f"[bold]{title}[/bold]",
                        border_style=color, padding=(0, 1)))


# ── Commands ───────────────────────────────────────────────────────────────────

def cmd_block(args):
    console.print(Rule("[bold red]BLOCK IP[/bold red]"))

    if not ipu.is_valid_ip(args.ip):
        console.print(f"[red]✗[/red] Invalid IP address: [cyan]{args.ip}[/cyan]")
        sys.exit(1)

    if ipu.is_loopback(args.ip):
        console.print(f"[red]✗[/red] Cannot block loopback address.")
        sys.exit(1)

    with Progress(SpinnerColumn(), TextColumn("[cyan]Looking up IP info...[/cyan]"),
                  console=console, transient=True) as p:
        p.add_task("geo", total=None)
        geo = ipu.geolocate(args.ip)

    try:
        rule = re_.add_rule(args.ip, "BLOCK",
                            reason=args.reason or "Manually blocked",
                            added_by="manual", geo=geo)
        _print_rule_panel(rule, "✓ IP Blocked")
    except ValueError as exc:
        console.print(f"[red]✗[/red] {exc}")
        sys.exit(1)


def cmd_allow(args):
    console.print(Rule("[bold green]ALLOW IP[/bold green]"))

    if not ipu.is_valid_ip(args.ip):
        console.print(f"[red]✗[/red] Invalid IP address: [cyan]{args.ip}[/cyan]")
        sys.exit(1)

    with Progress(SpinnerColumn(), TextColumn("[cyan]Looking up IP info...[/cyan]"),
                  console=console, transient=True) as p:
        p.add_task("geo", total=None)
        geo = ipu.geolocate(args.ip)

    try:
        rule = re_.add_rule(args.ip, "ALLOW",
                            reason=args.reason or "Manually whitelisted",
                            added_by="manual", geo=geo)
        _print_rule_panel(rule, "✓ IP Whitelisted")
    except ValueError as exc:
        console.print(f"[red]✗[/red] {exc}")
        sys.exit(1)


def cmd_remove(args):
    console.print(Rule("[bold yellow]REMOVE RULE[/bold yellow]"))
    try:
        rule = re_.remove_rule(args.id)
        console.print(f"[bold green]✓[/bold green] Rule [cyan]{rule['id']}[/cyan] "
                      f"removed — {rule['action']} on {rule['ip']}")
    except ValueError as exc:
        console.print(f"[red]✗[/red] {exc}")
        sys.exit(1)


def cmd_status(args):
    console.print(Rule("[bold cyan]FIREWALL STATUS[/bold cyan]"))

    # Stats cards
    stats = re_.get_stats()
    cards = [
        Panel(f"[bold]{stats['active_rules']}[/bold]\n[dim]Active Rules[/dim]",   border_style="cyan"),
        Panel(f"[bold red]{stats['blocked']}[/bold red]\n[dim]Blocked IPs[/dim]", border_style="red"),
        Panel(f"[bold green]{stats['allowed']}[/bold green]\n[dim]Allowed IPs[/dim]", border_style="green"),
        Panel(f"[bold yellow]{stats['auto_blocked']}[/bold yellow]\n[dim]Auto-Blocked[/dim]", border_style="yellow"),
        Panel(f"[bold red]{stats['critical_ips']}[/bold red]\n[dim]Critical IPs[/dim]", border_style="red"),
    ]
    console.print(Columns(cards, equal=True, expand=True))
    console.print()

    # Filter rules
    action = None
    if args.blocked: action = "BLOCK"
    if args.allowed: action = "ALLOW"

    rules = re_.get_rules(action=action, active_only=not args.all)

    if not rules:
        console.print("[dim]No rules found.[/dim]")
        return

    table = Table(box=box.ROUNDED, border_style="cyan", show_header=True,
                  header_style="bold dim")
    table.add_column("ID",       width=9)
    table.add_column("Action",   width=8)
    table.add_column("IP",       min_width=16)
    table.add_column("Threat",   width=10)
    table.add_column("Country",  min_width=12)
    table.add_column("Hits",     justify="right", width=6)
    table.add_column("Added By", width=9)
    table.add_column("Reason",   min_width=25)
    table.add_column("Created",  min_width=19)

    for r in rules:
        ac    = r["action"]
        ac_color = _action_color(ac)
        geo   = r.get("geo", {})
        table.add_row(
            r["id"],
            f"[bold {ac_color}]{ac}[/bold {ac_color}]",
            f"[cyan]{r['ip']}[/cyan]",
            f"[{_threat_style(r['threat'])}]{r['threat']}[/{_threat_style(r['threat'])}]",
            geo.get("country", "—"),
            str(r.get("hits", 0)),
            r.get("added_by", "—"),
            r["reason"][:40] + ("…" if len(r["reason"]) > 40 else ""),
            r["created_at"][:19],
        )

    console.print(table)
    console.print(f"\n[dim]Showing {len(rules)} rule(s).[/dim]")


def cmd_monitor(args):
    console.print(Rule("[bold yellow]AUTO-BLOCK MONITOR[/bold yellow]"))
    console.print(f"[dim]Analysing traffic against threat intelligence...[/dim]\n"
                  f"[dim]Thresholds — Hits: {args.hits}+  |  Threat Score: {args.score}+[/dim]\n")

    with Progress(SpinnerColumn(),
                  TextColumn("[cyan]Scanning traffic and threat feeds...[/cyan]"),
                  console=console, transient=True) as p:
        p.add_task("scan", total=None)
        new_rules = re_.run_auto_block(
            threshold_hits=args.hits,
            threshold_score=args.score,
        )

    if not new_rules:
        console.print(Panel(
            "[bold green]✓  No new threats detected.[/bold green]\n"
            "[dim]All monitored IPs are within acceptable thresholds.[/dim]",
            border_style="green", padding=(1, 2)
        ))
        return

    console.print(f"[bold red]⚠  {len(new_rules)} IP(s) auto-blocked:[/bold red]\n")

    table = Table(box=box.ROUNDED, border_style="red", header_style="bold dim")
    table.add_column("Rule ID",  width=9)
    table.add_column("IP",       min_width=16)
    table.add_column("Threat",   width=10)
    table.add_column("Score",    justify="right", width=7)
    table.add_column("Country",  min_width=12)
    table.add_column("Reason",   min_width=30)

    for r in new_rules:
        geo = r.get("geo", {})
        table.add_row(
            r["id"],
            f"[cyan]{r['ip']}[/cyan]",
            f"[{_threat_style(r['threat'])}]{r['threat']}[/{_threat_style(r['threat'])}]",
            str(r["threat_score"]),
            geo.get("country", "—"),
            r["reason"],
        )

    console.print(table)
    console.print(f"\n[dim]Run [cyan]firewall_manager.py status[/cyan] to view all active rules.[/dim]")


def cmd_log(args):
    console.print(Rule("[bold cyan]ACTIVITY LOG[/bold cyan]"))
    entries = re_.get_activity_log(lines=args.lines)

    if not entries:
        console.print("[dim]No activity logged yet.[/dim]")
        return

    for entry in entries:
        if "[BLOCK]" in entry:
            console.print(f"[red]●[/red] {entry}")
        elif "[ALLOW]" in entry:
            console.print(f"[green]●[/green] {entry}")
        elif "[REMOVE]" in entry:
            console.print(f"[yellow]●[/yellow] {entry}")
        else:
            console.print(f"[dim]●[/dim] {entry}")


# ── CLI setup ──────────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="firewall_manager",
        description="Dynamic Firewall Manager — block, allow, monitor, and audit IPs.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # block
    blk = sub.add_parser("block",  help="Block an IP address or CIDR range")
    blk.add_argument("--ip",     required=True, help="IP address or CIDR to block")
    blk.add_argument("--reason", help="Reason for blocking")

    # allow
    alw = sub.add_parser("allow",  help="Whitelist an IP address")
    alw.add_argument("--ip",     required=True, help="IP address to allow")
    alw.add_argument("--reason", help="Reason for allowing")

    # remove
    rem = sub.add_parser("remove", help="Remove an active rule by ID")
    rem.add_argument("--id", required=True, help="Rule ID to remove (e.g. FW-0001)")

    # status
    sta = sub.add_parser("status", help="View active firewall rules")
    sta.add_argument("--blocked", action="store_true", help="Show only BLOCK rules")
    sta.add_argument("--allowed", action="store_true", help="Show only ALLOW rules")
    sta.add_argument("--all",     action="store_true", help="Include inactive rules")

    # monitor
    mon = sub.add_parser("monitor", help="Auto-block IPs based on threat intelligence")
    mon.add_argument("--hits",  type=int, default=10,
                     help="Auto-block IPs with this many hits (default: 10)")
    mon.add_argument("--score", type=int, default=50,
                     help="Auto-block IPs with threat score >= this (default: 50)")

    # log
    lg = sub.add_parser("log", help="View recent activity log")
    lg.add_argument("--lines", type=int, default=20, help="Number of log lines (default: 20)")

    return parser


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    console.print(BANNER)
    parser = build_parser()
    args   = parser.parse_args()

    try:
        if args.command == "block":   cmd_block(args)
        elif args.command == "allow":   cmd_allow(args)
        elif args.command == "remove":  cmd_remove(args)
        elif args.command == "status":  cmd_status(args)
        elif args.command == "monitor": cmd_monitor(args)
        elif args.command == "log":     cmd_log(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(0)


if __name__ == "__main__":
    main()
