# File: scanner/gobuster_scan.py
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

import subprocess

console = Console()

WORDLIST_OPTIONS = [
    {
        "key": "1",
        "label": "Dirb common",
        "path": "/usr/share/wordlists/dirb/common.txt",
        "desc": "Small and quick. Good first pass.",
    },
    {
        "key": "2",
        "label": "Dirbuster medium",
        "path": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "desc": "A stronger default for web recon.",
    },
    {
        "key": "3",
        "label": "SecLists common",
        "path": "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "desc": "Popular and broad web content list.",
    },
    {
        "key": "4",
        "label": "SecLists raft small",
        "path": "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
        "desc": "Faster than large lists, still useful.",
    },
    {
        "key": "5",
        "label": "SecLists raft medium",
        "path": "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
        "desc": "Bigger search space for deeper enumeration.",
    },
    {
        "key": "6",
        "label": "Custom path",
        "path": None,
        "desc": "Point to your own wordlist file.",
    },
]


def _extract_highlights(output: str) -> List[str]:
    highlights: List[str] = []

    for line in output.splitlines():
        clean = line.strip()
        if not clean:
            continue

        if "Found:" in clean or clean.startswith("/") or clean.startswith("Status:"):
            highlights.append(clean)

    return highlights


def choose_wordlist() -> str:
    table = Table(title="Gobuster Wordlists", show_lines=True)
    table.add_column("#", style="bold cyan", width=5)
    table.add_column("Wordlist", style="bold white", width=22)
    table.add_column("Path", style="white")
    table.add_column("Why use it", style="white")

    for item in WORDLIST_OPTIONS:
        path_display = item["path"] if item["path"] else "custom"
        exists = Path(item["path"]).exists() if item["path"] else True
        status = "found" if exists else "missing"
        table.add_row(item["key"], f"{item['label']} ({status})", path_display, item["desc"])

    console.print(table)

    choice = Prompt.ask("Choose a wordlist", choices=[opt["key"] for opt in WORDLIST_OPTIONS], default="1")
    selected = next(opt for opt in WORDLIST_OPTIONS if opt["key"] == choice)

    if selected["path"] is None:
        custom_path = Prompt.ask("Enter custom wordlist path").strip()
        return custom_path

    if Path(selected["path"]).exists():
        return selected["path"]

    console.print(
        Panel(
            "That wordlist is not installed on this system. You can either install it or provide a custom path.",
            title="[bold yellow]Wordlist missing[/bold yellow]",
            border_style="yellow",
        )
    )
    custom_path = Prompt.ask("Enter custom wordlist path").strip()
    return custom_path


def choose_extensions() -> str:
    console.print("\n[bold cyan]Gobuster extensions[/bold cyan]")
    console.print("[1] Common web extensions: php,txt,html,js")
    console.print("[2] Broader list: php,txt,html,js,asp,aspx,xml,json")
    console.print("[3] Custom")

    choice = Prompt.ask("Select extensions", choices=["1", "2", "3"], default="1")

    if choice == "1":
        return "php,txt,html,js"
    if choice == "2":
        return "php,txt,html,js,asp,aspx,xml,json"

    return Prompt.ask("Enter comma-separated extensions", default="php,txt,html,js").strip()


def choose_recursive() -> bool:
    console.print("\n[bold cyan]Recursive mode[/bold cyan]")
    console.print("Recursive mode tells Gobuster to keep exploring discovered directories.")
    return Prompt.ask("Enable recursive mode?", choices=["y", "n"], default="n") == "y"


def choose_status_blacklist() -> List[str]:
    console.print("\n[bold cyan]Status codes to hide[/bold cyan]")
    console.print("These HTTP response codes will be suppressed in the output.")
    console.print("[1] 404")
    console.print("[2] 403,404")
    console.print("[3] 301,302,307,401,403,404")
    console.print("[4] Custom")

    choice = Prompt.ask("Select blacklist", choices=["1", "2", "3", "4"], default="2")

    if choice == "1":
        return ["404"]
    if choice == "2":
        return ["403", "404"]
    if choice == "3":
        return ["301", "302", "307", "401", "403", "404"]

    raw = Prompt.ask("Enter comma-separated status codes", default="403,404").strip()
    return [item.strip() for item in raw.split(",") if item.strip()]


def run_gobuster_scan(
    url: str,
    wordlist: Optional[str] = None,
    extensions: Optional[str] = "php,txt,html,js",
    recursive: bool = False,
    blacklist: Optional[List[str]] = None,
    threads: int = 30,
    timeout: int = 90,
    extra_args: Optional[Iterable[str]] = None,
):
    """
    Run Gobuster directory enumeration and return structured results.
    """
    started_at = datetime.now()
    chosen_wordlist = wordlist or choose_wordlist()

    if not chosen_wordlist or not Path(chosen_wordlist).exists():
        return {
            "ok": False,
            "url": url,
            "timestamp": started_at.isoformat(sep=" ", timespec="seconds"),
            "error": "Wordlist not found. Install a wordlist or provide a valid custom path.",
        }

    command = [
        "gobuster",
        "dir",
        "-u",
        url,
        "-w",
        chosen_wordlist,
        "-q",
        "-t",
        str(threads),
    ]

    if extensions:
        command.extend(["-x", extensions])

    if recursive:
        command.append("-r")

    if blacklist:
        command.extend(["-b", ",".join(blacklist)])

    if extra_args:
        for item in extra_args:
            value = str(item).strip()
            if value:
                command.append(value)

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "url": url,
            "wordlist": chosen_wordlist,
            "timestamp": started_at.isoformat(sep=" ", timespec="seconds"),
            "error": "Gobuster timed out",
        }
    except FileNotFoundError:
        return {
            "ok": False,
            "url": url,
            "wordlist": chosen_wordlist,
            "timestamp": started_at.isoformat(sep=" ", timespec="seconds"),
            "error": "Gobuster is not installed or not available in PATH",
        }
    except Exception as exc:
        return {
            "ok": False,
            "url": url,
            "wordlist": chosen_wordlist,
            "timestamp": started_at.isoformat(sep=" ", timespec="seconds"),
            "error": str(exc),
        }

    finished_at = datetime.now()
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    highlights = _extract_highlights(stdout)

    return {
        "ok": completed.returncode == 0 or bool(stdout),
        "url": url,
        "wordlist": chosen_wordlist,
        "extensions": extensions,
        "recursive": recursive,
        "blacklist": blacklist or [],
        "threads": threads,
        "timestamp": started_at.isoformat(sep=" ", timespec="seconds"),
        "finished_at": finished_at.isoformat(sep=" ", timespec="seconds"),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 2),
        "returncode": completed.returncode,
        "findings_count": len(highlights),
        "highlights": highlights,
        "raw_output": stdout,
        "stderr": stderr,
    }