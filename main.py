# File: main.py
#!/usr/bin/env python3

from pathlib import Path
import json
import os
from typing import Dict, List, Tuple

from rich.align import Align
from rich.box import DOUBLE, ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from scanner.nmap_scan import run_nmap_scan
from scanner.nikto_scan import run_nikto_scan
from scanner.gobuster_scan import run_gobuster_scan, choose_wordlist, choose_extensions, choose_recursive, choose_status_blacklist

console = Console()
RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

BANNER = r"""
██████╗ ███████╗██╗  ██╗ █████╗ 
██╔══██╗██╔════╝╚██╗██╔╝██╔══██╗
██████╔╝█████╗   ╚███╔╝ ███████║
██╔══██╗██╔══╝   ██╔██╗ ██╔══██║
██║  ██║███████╗██╔╝ ██╗██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
                                
"""

FEATURES = {
    "1": ("-sS", "SYN scan. Fast and stealthier. Needs root."),
    "2": ("-sT", "TCP connect scan. Safe without root."),
    "3": ("-sV", "Version detection. Identifies service versions."),
    "4": ("-O", "OS detection. Best with root."),
    "5": ("-sC", "Default scripts. Safe script set."),
    "6": ("--script vuln", "Vulnerability scripts. Checks common issues."),
    "7": ("-Pn", "No ping. Useful when hosts block ICMP."),
    "8": ("--traceroute", "Trace the path to the target."),
    "9": ("-A", "Aggressive mode. Combines several discovery features."),
    "10": ("-n", "Skip DNS resolution. Faster and quieter."),
    "11": ("--reason", "Show why ports are in each state."),
}

WEB_PORTS = {80, 81, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888}


def is_root() -> bool:
    return os.geteuid() == 0


def show_banner():
    console.clear()

    banner_text = Text(BANNER, style="bold green")
    console.print(
        Panel(
            Align.center(banner_text),
            title="[bold cyan]rexa[/bold cyan]",
            subtitle="[dim]Guided recon and web assessment assistant[/dim]",
            border_style="green",
            box=DOUBLE,
        )
    )

    status = "enabled" if is_root() else "not enabled"
    console.print(
        Panel(
            f"Root mode is {status}.\n"
            f"• Use normal mode for safe scans.\n"
            f"• Use sudo rexa for SYN scan, OS detection, aggressive mode, and traceroute.\n"
            f"• Nikto and Gobuster work in both modes.",
            title="[bold cyan]Mode guidance[/bold cyan]",
            border_style="cyan",
            box=ROUNDED,
        )
    )


def explain_tools():
    console.print(
        Panel(
            "Nmap discovers hosts, ports, services, and versions.\n"
            "Nikto checks web servers for missing headers and common misconfigurations.\n"
            "Gobuster enumerates hidden directories and files using a wordlist.",
            title="[bold cyan]What rexa does[/bold cyan]",
            border_style="cyan",
            box=ROUNDED,
        )
    )


def ask_target() -> str:
    console.print(
        Panel(
            "Enter an IP address, hostname, or CIDR range.\n"
            "Examples: scanme.nmap.org, 192.168.1.10, 10.10.10.0/24",
            title="[bold cyan]Target guidance[/bold cyan]",
            border_style="cyan",
            box=ROUNDED,
        )
    )
    return Prompt.ask("\n[bold yellow]Enter target[/bold yellow]").strip()


def show_profile_menu():
    table = Table(title="Scan Profiles", box=ROUNDED, show_lines=True)
    table.add_column("#", style="bold cyan", width=5)
    table.add_column("Profile", style="bold white", width=14)
    table.add_column("What it does", style="white")

    table.add_row("1", "Quick", "Fast first pass with version detection.")
    table.add_row("2", "Balanced", "Version detection plus safe scripts.")
    table.add_row("3", "Full", "Broader scan. Best with root.")
    table.add_row("4", "Custom", "Choose flags, speed, and ports yourself.")

    console.print(table)


def choose_profile() -> Dict:
    show_profile_menu()
    choice = Prompt.ask("Select profile", choices=["1", "2", "3", "4"], default="4")

    if choice == "1":
        return {
            "name": "Quick",
            "flags": ["-sV"],
            "speed": "-T4",
            "ports": None,
            "notes": [
                "Quick profile selected.",
                "Good for a fast first look at exposed services.",
            ],
        }

    if choice == "2":
        return {
            "name": "Balanced",
            "flags": ["-sV", "-sC"],
            "speed": "-T4",
            "ports": None,
            "notes": [
                "Balanced profile selected.",
                "Adds safe default scripts to the version scan.",
            ],
        }

    if choice == "3":
        return {
            "name": "Full",
            "flags": ["-sS", "-sV", "-sC", "-O", "--traceroute"],
            "speed": "-T4",
            "ports": "1-65535",
            "notes": [
                "Full profile selected.",
                "This is broader and is best run with root privileges.",
            ],
        }

    return choose_custom_profile()


def choose_custom_profile() -> Dict:
    console.rule("[bold cyan]Custom Scan Builder[/bold cyan]")
    console.print("[bold cyan]Choose one or more features by number, separated by commas.[/bold cyan]")

    feature_table = Table(box=ROUNDED, show_lines=True)
    feature_table.add_column("#", style="bold cyan", width=5)
    feature_table.add_column("Flag", style="bold white", width=16)
    feature_table.add_column("What it means", style="white")

    for key, (flag, desc) in FEATURES.items():
        feature_table.add_row(key, flag, desc)

    console.print(feature_table)

    raw = Prompt.ask(
        "Enter choices (example: 1,3,5 or type 'all')",
        default="3",
    ).strip().lower()

    if raw in {"all", "*"}:
        flags = [flag for flag, _ in FEATURES.values()]
    else:
        flags = []
        for item in raw.split(","):
            item = item.strip()
            if item in FEATURES:
                flag = FEATURES[item][0]
                if flag not in flags:
                    flags.append(flag)

    if not flags:
        flags = ["-sV"]

    console.print("\n[bold cyan]Select speed[/bold cyan]")
    console.print("[1] Conservative (-T2)")
    console.print("[2] Balanced (-T3)")
    console.print("[3] Fast (-T4)")
    console.print("[4] Aggressive (-T5)")
    console.print("[5] Auto (recommended: -T4)")

    speed_choice = Prompt.ask("Enter choice", choices=["1", "2", "3", "4", "5"], default="5")
    speed_map = {
        "1": "-T2",
        "2": "-T3",
        "3": "-T4",
        "4": "-T5",
        "5": "-T4",
    }
    speed = speed_map[speed_choice]

    console.print("\n[bold cyan]Select port strategy[/bold cyan]")
    console.print("[1] Top ports (default)")
    console.print("[2] All ports (1-65535)")
    console.print("[3] Web ports (80,443,8080,8443)")
    console.print("[4] Custom port list or range")

    port_choice = Prompt.ask("Enter choice", choices=["1", "2", "3", "4"], default="1")

    ports = None
    if port_choice == "2":
        ports = "1-65535"
    elif port_choice == "3":
        ports = "80,443,8080,8443"
    elif port_choice == "4":
        ports = Prompt.ask("Enter ports (example: 1-1000 or 22,80,443)").strip()

    return {
        "name": "Custom",
        "flags": flags,
        "speed": speed,
        "ports": ports,
        "notes": [
            "Custom profile selected.",
            "You are controlling the scan scope directly.",
        ],
    }


def explain_flags(flags: List[str]) -> str:
    descriptions = {
        "-sS": "SYN scan",
        "-sT": "TCP connect scan",
        "-sV": "Version detection",
        "-O": "OS detection",
        "-sC": "Default scripts",
        "--script vuln": "Vulnerability scripts",
        "-Pn": "No ping",
        "--traceroute": "Traceroute",
        "-A": "Aggressive mode",
        "-n": "Skip DNS resolution",
        "--reason": "Show scan reasons",
    }

    return "\n".join(
        f"• {flag}: {descriptions.get(flag, 'Enabled')}"
        for flag in flags
    )


def apply_root_rules(flags: List[str]) -> Tuple[List[str], List[str]]:
    cleaned = list(dict.fromkeys(flags))
    notes: List[str] = []

    if not is_root():
        removed = []

        if "-A" in cleaned:
            cleaned = [f for f in cleaned if f != "-A"]
            removed.append("-A")
            for replacement in ["-sV", "-sC", "--reason"]:
                if replacement not in cleaned:
                    cleaned.append(replacement)

        for restricted in ["-sS", "-O", "--traceroute"]:
            if restricted in cleaned:
                cleaned = [f for f in cleaned if f != restricted]
                removed.append(restricted)

        if "-sS" in flags and "-sT" not in cleaned:
            cleaned.append("-sT")

        cleaned = list(dict.fromkeys(cleaned))

        if removed:
            notes.append(
                "Removed root-only features because the process is not running as root: "
                + ", ".join(sorted(set(removed)))
            )
            notes.append(
                "Tip: use sudo rexa to unlock the full Nmap feature set."
            )

    if not cleaned:
        cleaned = ["-sV"]
        notes.append("Falling back to version detection.")

    return cleaned, notes


def show_plan(target: str, profile: Dict):
    table = Table(title="Scan Plan", box=ROUNDED, show_lines=True)
    table.add_column("Field", style="bold cyan", width=18)
    table.add_column("Value", style="white")

    table.add_row("Target", target)
    table.add_row("Profile", profile["name"])
    table.add_row("Flags", " ".join(profile["flags"]))
    table.add_row("Speed", profile["speed"])
    table.add_row("Ports", profile["ports"] if profile["ports"] else "default top ports")

    console.print(table)

    console.print(
        Panel(
            explain_flags(profile["flags"]),
            title="[bold cyan]Selected features explained[/bold cyan]",
            border_style="cyan",
            box=ROUNDED,
        )
    )

    if profile.get("notes"):
        console.print(
            Panel(
                "\n".join(f"• {note}" for note in profile["notes"]),
                title="[bold yellow]Guidance[/bold yellow]",
                border_style="yellow",
                box=ROUNDED,
            )
        )


def save_json(path: Path, payload: Dict):
    path.write_text(json.dumps(payload, indent=4), encoding="utf-8")


def summarize_nmap_result(result: Dict):
    summary = result.get("summary", {})

    summary_table = Table(title="Nmap Summary", box=ROUNDED, show_lines=True)
    summary_table.add_column("Metric", style="bold cyan", width=20)
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Target", result.get("target", "-"))
    summary_table.add_row("Arguments", result.get("arguments", "-"))
    summary_table.add_row("Ports", str(result.get("ports", "default")))
    summary_table.add_row("Hosts total", str(summary.get("hosts_total", 0)))
    summary_table.add_row("Hosts up", str(summary.get("hosts_up", 0)))
    summary_table.add_row("Open ports", str(summary.get("open_ports_total", 0)))
    summary_table.add_row("Closed ports", str(summary.get("closed_ports_total", 0)))
    summary_table.add_row("Filtered ports", str(summary.get("filtered_ports_total", 0)))
    summary_table.add_row("Duration", f'{summary.get("elapsed_seconds", 0)}s')

    console.print(summary_table)

    open_ports = Table(title="Discovered Ports", box=ROUNDED, show_lines=True)
    open_ports.add_column("Host", style="bold cyan")
    open_ports.add_column("Port", style="white", justify="right")
    open_ports.add_column("Proto", style="white")
    open_ports.add_column("State", style="white")
    open_ports.add_column("Service", style="bold white")
    open_ports.add_column("Product", style="white")
    open_ports.add_column("Version", style="white")

    rows_added = 0
    for host in result.get("hosts", []):
        ip = host.get("ip", "-")
        for proto, entries in host.get("protocols", {}).items():
            for entry in entries:
                open_ports.add_row(
                    ip,
                    str(entry.get("port", "-")),
                    proto,
                    entry.get("state", "-") or "-",
                    entry.get("service", "-") or "-",
                    entry.get("product", "-") or "-",
                    entry.get("version", "-") or "-",
                )
                rows_added += 1

    if rows_added:
        console.print(open_ports)
    else:
        console.print(
            Panel(
                "No ports were listed in this result set.",
                title="[bold yellow]Result[/bold yellow]",
                border_style="yellow",
                box=ROUNDED,
            )
        )


def collect_web_targets(nmap_result: Dict) -> List[Dict]:
    targets: List[Dict] = []

    for host in nmap_result.get("hosts", []):
        ip = host.get("ip", "")
        for proto, entries in host.get("protocols", {}).items():
            if proto != "tcp":
                continue
            for entry in entries:
                if entry.get("state") != "open":
                    continue

                port = int(entry.get("port", 0))
                service = (entry.get("service") or "").lower()

                is_web = (
                    port in WEB_PORTS
                    or "http" in service
                    or "ssl/http" in service
                    or "https" in service
                )

                if is_web:
                    targets.append(
                        {
                            "host": ip,
                            "port": port,
                            "ssl": port in {443, 8443},
                            "service": service or "web",
                        }
                    )

    unique = []
    seen = set()
    for item in targets:
        key = (item["host"], item["port"])
        if key not in seen:
            unique.append(item)
            seen.add(key)

    return unique


def choose_nikto_targets(web_targets: List[Dict]) -> List[Dict]:
    if not web_targets:
        console.print(
            Panel(
                "No obvious web services were detected from Nmap. You can still run Nikto manually if you know the target runs HTTP or HTTPS.",
                title="[bold yellow]Nikto hint[/bold yellow]",
                border_style="yellow",
                box=ROUNDED,
            )
        )
        if not Confirm.ask("Run Nikto on a custom target?", default=False):
            return []

        host = Prompt.ask("Host or URL (example: scanme.nmap.org or https://example.com)").strip()
        port = int(Prompt.ask("Port", default="80"))
        ssl = Confirm.ask("Use SSL/HTTPS?", default=port in {443, 8443})
        return [{"host": host, "port": port, "ssl": ssl, "service": "custom"}]

    table = Table(title="Detected Web Targets", box=ROUNDED, show_lines=True)
    table.add_column("#", style="bold cyan", width=5)
    table.add_column("Host", style="white")
    table.add_column("Port", style="white")
    table.add_column("SSL", style="white")
    table.add_column("Service", style="white")

    for idx, item in enumerate(web_targets, start=1):
        table.add_row(
            str(idx),
            item["host"],
            str(item["port"]),
            "yes" if item["ssl"] else "no",
            item["service"],
        )

    console.print(table)

    console.print(
        Panel(
            "Nikto checks web servers for missing security headers, dangerous defaults, and other common web issues.",
            title="[bold cyan]Nikto guidance[/bold cyan]",
            border_style="cyan",
            box=ROUNDED,
        )
    )

    mode = Prompt.ask("Nikto target mode", choices=["1", "2", "3"], default="1")
    if mode == "1":
        return [web_targets[0]]
    if mode == "2":
        return web_targets

    host = Prompt.ask("Host or URL").strip()
    port = int(Prompt.ask("Port", default="80"))
    ssl = Confirm.ask("Use SSL/HTTPS?", default=port in {443, 8443})
    return [{"host": host, "port": port, "ssl": ssl, "service": "custom"}]


def ask_nikto_options() -> int:
    console.print("\n[bold cyan]Nikto options[/bold cyan]")
    console.print("[1] Quick check (60s)")
    console.print("[2] Standard (120s)")
    console.print("[3] Deep (300s)")
    choice = Prompt.ask("Select maxtime", choices=["1", "2", "3"], default="1")
    return {"1": 60, "2": 120, "3": 300}[choice]


def run_nikto_workflow(nmap_result: Dict) -> List[Dict]:
    web_targets = collect_web_targets(nmap_result)

    console.print(
        Panel(
            "Nikto is a web scanner. It becomes useful after Nmap finds HTTP or HTTPS services.",
            title="[bold cyan]Nikto overview[/bold cyan]",
            border_style="cyan",
            box=ROUNDED,
        )
    )

    if not Confirm.ask("Run Nikto now?", default=bool(web_targets)):
        return []

    targets = choose_nikto_targets(web_targets)
    if not targets:
        return []

    maxtime = ask_nikto_options()
    results = []

    for target in targets:
        console.print(
            f"\n[cyan][+] Running Nikto on {target['host']}:{target['port']} "
            f"({'https' if target['ssl'] else 'http'})...[/cyan]"
        )

        nikto_result = run_nikto_scan(
            host=target["host"],
            port=target["port"],
            ssl=target["ssl"],
            maxtime=maxtime,
        )
        results.append(nikto_result)

        result_table = Table(title=f"Nikto Result: {target['host']}:{target['port']}", box=ROUNDED, show_lines=True)
        result_table.add_column("Field", style="bold cyan", width=16)
        result_table.add_column("Value", style="white")

        result_table.add_row("Status", "ok" if nikto_result.get("ok") else "error")
        result_table.add_row("Target", nikto_result.get("target_url", "-"))
        result_table.add_row("Findings", str(nikto_result.get("findings_count", 0)))
        result_table.add_row("Duration", f'{nikto_result.get("duration_seconds", 0)}s')

        console.print(result_table)

        highlights = nikto_result.get("highlights", [])
        if highlights:
            console.print(
                Panel(
                    "\n".join(f"• {item}" for item in highlights[:10]),
                    title="[bold yellow]Nikto highlights[/bold yellow]",
                    border_style="yellow",
                    box=ROUNDED,
                )
            )
        else:
            console.print(
                Panel(
                    "No concise highlights were extracted from the Nikto output.",
                    title="[bold green]Nikto[/bold green]",
                    border_style="green",
                    box=ROUNDED,
                )
            )

    return results


def choose_gobuster_target(web_targets: List[Dict]) -> Dict:
    if web_targets:
        table = Table(title="Detected Web Targets", box=ROUNDED, show_lines=True)
        table.add_column("#", style="bold cyan", width=5)
        table.add_column("Host", style="white")
        table.add_column("Port", style="white")
        table.add_column("SSL", style="white")

        for idx, item in enumerate(web_targets, start=1):
            table.add_row(
                str(idx),
                item["host"],
                str(item["port"]),
                "yes" if item["ssl"] else "no",
            )

        console.print(table)

        console.print(
            Panel(
                "Gobuster finds hidden directories and files. Use a web target for the best results.",
                title="[bold cyan]Gobuster guidance[/bold cyan]",
                border_style="cyan",
                box=ROUNDED,
            )
        )

        mode = Prompt.ask("Gobuster target mode", choices=["1", "2", "3"], default="1")
        if mode == "1":
            return web_targets[0]
        if mode == "2":
            return web_targets[0]
        host = Prompt.ask("Host or URL").strip()
        port = int(Prompt.ask("Port", default="80"))
        ssl = Confirm.ask("Use SSL/HTTPS?", default=port in {443, 8443})
        return {"host": host, "port": port, "ssl": ssl, "service": "custom"}

    console.print(
        Panel(
            "No web target was discovered automatically. You can still run Gobuster if you know the app is web-based.",
            title="[bold yellow]Gobuster hint[/bold yellow]",
            border_style="yellow",
            box=ROUNDED,
        )
    )
    host = Prompt.ask("Host or URL").strip()
    port = int(Prompt.ask("Port", default="80"))
    ssl = Confirm.ask("Use SSL/HTTPS?", default=port in {443, 8443})
    return {"host": host, "port": port, "ssl": ssl, "service": "custom"}


def ask_gobuster_options() -> Tuple[str, str, bool, List[str], int]:
    console.print("\n[bold cyan]Gobuster options[/bold cyan]")
    console.print("Gobuster discovers hidden paths and files using a wordlist.\n")

    wordlist = choose_wordlist()
    extensions = choose_extensions()
    recursive = choose_recursive()
    blacklist = choose_status_blacklist()

    console.print("\n[bold cyan]Thread count[/bold cyan]")
    console.print("[1] 10")
    console.print("[2] 30")
    console.print("[3] 50")
    console.print("[4] 100")

    thread_choice = Prompt.ask("Select threads", choices=["1", "2", "3", "4"], default="2")
    thread_map = {"1": 10, "2": 30, "3": 50, "4": 100}
    threads = thread_map[thread_choice]

    console.print("\n[bold cyan]Timeout[/bold cyan]")
    console.print("[1] 60s")
    console.print("[2] 90s")
    console.print("[3] 120s")
    console.print("[4] 180s")

    timeout_choice = Prompt.ask("Select timeout", choices=["1", "2", "3", "4"], default="2")
    timeout_map = {"1": 60, "2": 90, "3": 120, "4": 180}
    timeout = timeout_map[timeout_choice]

    return wordlist, extensions, recursive, blacklist, threads, timeout


def run_gobuster_workflow(nmap_result: Dict) -> List[Dict]:
    web_targets = collect_web_targets(nmap_result)

    console.print(
        Panel(
            "Gobuster is a directory and file discovery tool. It works best against web applications and static content.",
            title="[bold cyan]Gobuster overview[/bold cyan]",
            border_style="cyan",
            box=ROUNDED,
        )
    )

    if not Confirm.ask("Run Gobuster now?", default=bool(web_targets)):
        return []

    target = choose_gobuster_target(web_targets)
    ssl = bool(target["ssl"])
    base_url = f"{'https' if ssl else 'http'}://{target['host']}:{target['port']}"

    wordlist, extensions, recursive, blacklist, threads, timeout = ask_gobuster_options()

    console.print(f"\n[cyan][+] Running Gobuster against {base_url}...[/cyan]")

    gobuster_result = run_gobuster_scan(
        url=base_url,
        wordlist=wordlist,
        extensions=extensions,
        recursive=recursive,
        blacklist=blacklist,
        threads=threads,
        timeout=timeout,
    )

    result_table = Table(title=f"Gobuster Result: {base_url}", box=ROUNDED, show_lines=True)
    result_table.add_column("Field", style="bold cyan", width=18)
    result_table.add_column("Value", style="white")

    result_table.add_row("Status", "ok" if gobuster_result.get("ok") else "error")
    result_table.add_row("Findings", str(gobuster_result.get("findings_count", 0)))
    result_table.add_row("Duration", f'{gobuster_result.get("duration_seconds", 0)}s')
    result_table.add_row("Wordlist", gobuster_result.get("wordlist", "-"))
    result_table.add_row("Extensions", extensions)
    result_table.add_row("Threads", str(threads))
    result_table.add_row("Recursive", "yes" if recursive else "no")
    result_table.add_row("Blacklist", ",".join(blacklist) if blacklist else "-")

    console.print(result_table)

    highlights = gobuster_result.get("highlights", [])
    if highlights:
        console.print(
            Panel(
                "\n".join(f"• {item}" for item in highlights[:12]),
                title="[bold yellow]Gobuster highlights[/bold yellow]",
                border_style="yellow",
                box=ROUNDED,
            )
        )
    else:
        console.print(
            Panel(
                "No concise highlights were extracted from the Gobuster output.",
                title="[bold green]Gobuster[/bold green]",
                border_style="green",
                box=ROUNDED,
            )
        )

    return [gobuster_result]


def write_report(session: Dict):
    report = RESULTS_DIR / "report.md"

    nmap = session.get("nmap", {})
    nikto = session.get("nikto", [])
    gobuster = session.get("gobuster", [])

    lines = [
        "# rexa Report",
        "",
        f"**Target:** {session.get('target', '-')}",
        f"**Profile:** {session.get('profile', '-')}",
        f"**Run mode:** {'root' if session.get('root') else 'normal'}",
        "",
        "## Nmap",
        f"- Arguments: {nmap.get('arguments', '-')}",
        f"- Open ports: {nmap.get('summary', {}).get('open_ports_total', 0)}",
        f"- Closed ports: {nmap.get('summary', {}).get('closed_ports_total', 0)}",
        f"- Filtered ports: {nmap.get('summary', {}).get('filtered_ports_total', 0)}",
        "",
        "## Nikto",
    ]

    if nikto:
        for item in nikto:
            lines.append(f"- {item.get('target_url', '-')}: {item.get('findings_count', 0)} finding(s)")
    else:
        lines.append("- Not run")

    lines.append("")
    lines.append("## Gobuster")

    if gobuster:
        for item in gobuster:
            lines.append(f"- {item.get('url', '-')}: {item.get('findings_count', 0)} finding(s)")
    else:
        lines.append("- Not run")

    report.write_text("\n".join(lines), encoding="utf-8")
    console.print(f"[green][+] Markdown report saved to {report}[/green]")


def post_scan_menu() -> str:
    console.rule("[bold cyan]Next step[/bold cyan]")
    console.print("[1] Run Nikto")
    console.print("[2] Run Gobuster")
    console.print("[3] Run Nikto + Gobuster")
    console.print("[4] Save report and exit")
    console.print("[5] Exit without report")

    return Prompt.ask(
        "Choose an action",
        choices=["1", "2", "3", "4", "5"],
        default="4",
    )


def main():
    try:
        show_banner()
        explain_tools()

        target = ask_target()
        profile = choose_profile()
        profile["flags"], root_notes = apply_root_rules(profile["flags"])
        profile["notes"] = profile.get("notes", []) + root_notes

        show_plan(target, profile)

        command_preview = ["nmap", *profile["flags"], profile["speed"]]
        if profile["ports"]:
            command_preview.extend(["-p", str(profile["ports"])])
        command_preview.append(target)

        console.print(
            Panel(
                " ".join(command_preview),
                title="[bold cyan]Command preview[/bold cyan]",
                border_style="cyan",
                box=ROUNDED,
            )
        )

        if not Confirm.ask("Proceed with this scan?", default=True):
            console.print("[yellow]Scan cancelled.[/yellow]")
            return

        with console.status("[bold cyan]Running Nmap...[/bold cyan]", spinner="dots"):
            nmap_result = run_nmap_scan(
                target=target,
                scan_flags=profile["flags"],
                speed=profile["speed"],
                ports=profile["ports"],
            )

        if not nmap_result.get("ok", True):
            console.print(
                Panel(
                    nmap_result.get("error", "Unknown error"),
                    title="[bold red]Nmap error[/bold red]",
                    border_style="red",
                    box=ROUNDED,
                )
            )
            save_json(RESULTS_DIR / "nmap_output.json", nmap_result)
            console.print("[green][+] Nmap result saved.[green]")
            return

        console.print("\n[bold green]===== NMAP RESULTS =====[/bold green]")
        summarize_nmap_result(nmap_result)

        save_json(RESULTS_DIR / "nmap_output.json", nmap_result)
        console.print("[green][+] Nmap results saved to results/nmap_output.json[/green]")

        nikto_results: List[Dict] = []
        gobuster_results: List[Dict] = []

        while True:
            action = post_scan_menu()

            if action == "1":
                nikto_results = run_nikto_workflow(nmap_result)
            elif action == "2":
                gobuster_results = run_gobuster_workflow(nmap_result)
            elif action == "3":
                nikto_results = run_nikto_workflow(nmap_result)
                gobuster_results = run_gobuster_workflow(nmap_result)
            elif action == "4":
                break
            else:
                break

            session = {
                "target": target,
                "profile": profile["name"],
                "root": is_root(),
                "nmap": nmap_result,
                "nikto": nikto_results,
                "gobuster": gobuster_results,
            }
            save_json(RESULTS_DIR / "session.json", session)

            if not Confirm.ask("Run another tool or finish now?", default=False):
                break

        session = {
            "target": target,
            "profile": profile["name"],
            "root": is_root(),
            "nmap": nmap_result,
            "nikto": nikto_results,
            "gobuster": gobuster_results,
        }

        save_json(RESULTS_DIR / "session.json", session)
        write_report(session)

        if Confirm.ask("Save a final plain-text summary too?", default=True):
            summary_path = RESULTS_DIR / "summary.txt"
            summary_path.write_text(
                f"Target: {target}\nProfile: {profile['name']}\nRoot: {is_root()}\n",
                encoding="utf-8",
            )
            console.print(f"[green][+] Summary saved to {summary_path}[/green]")

        console.print(
            Panel(
                "Session complete. Your scan data is saved and ready for the next run.",
                title="[bold green]Done[/bold green]",
                border_style="green",
                box=ROUNDED,
            )
        )

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
    except Exception as exc:
        console.print(
            Panel(
                str(exc),
                title="[bold red]Unexpected error[/bold red]",
                border_style="red",
                box=ROUNDED,
            )
        )


if __name__ == "__main__":
    main()