# File: scanner/nikto_scan.py
from datetime import datetime
from urllib.parse import urlparse
from typing import Iterable, List, Optional

import subprocess


def _extract_highlights(output: str) -> List[str]:
    highlights: List[str] = []

    for line in output.splitlines():
        clean = line.strip()
        if not clean.startswith("+ "):
            continue

        skip_prefixes = (
            "+ Nikto",
            "+---------------------------------------------------------------------------",
            "+ Target IP:",
            "+ Target Hostname:",
            "+ Target Port:",
            "+ Start Time:",
            "+ End Time:",
            "+ Multiple IPs found:",
            "+ 1 host(s) tested",
        )

        if clean.startswith(skip_prefixes):
            continue

        highlights.append(clean[2:].strip())

    return highlights


def _normalize_host_input(host: str) -> str:
    raw = host.strip()

    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        if parsed.hostname:
            return parsed.hostname
        return raw.replace("https://", "").replace("http://", "").split("/")[0]

    return raw


def run_nikto_scan(
    host: str,
    port: int = 80,
    ssl: bool = False,
    maxtime: int = 60,
    extra_args: Optional[Iterable[str]] = None,
):
    """
    Run Nikto against one web target and return structured results.
    """
    started_at = datetime.now()
    clean_host = _normalize_host_input(host)

    command = [
        "nikto",
        "-h",
        clean_host,
        "-p",
        str(port),
        "-maxtime",
        str(maxtime),
        "-nointeractive",
    ]

    if ssl:
        command.append("-ssl")

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
            timeout=maxtime + 20,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "target_url": f"{'https' if ssl else 'http'}://{clean_host}:{port}",
            "host": clean_host,
            "port": port,
            "ssl": ssl,
            "timestamp": started_at.isoformat(sep=" ", timespec="seconds"),
            "error": "Nikto timed out",
        }
    except FileNotFoundError:
        return {
            "ok": False,
            "target_url": f"{'https' if ssl else 'http'}://{clean_host}:{port}",
            "host": clean_host,
            "port": port,
            "ssl": ssl,
            "timestamp": started_at.isoformat(sep=" ", timespec="seconds"),
            "error": "Nikto is not installed or not available in PATH",
        }
    except Exception as exc:
        return {
            "ok": False,
            "target_url": f"{'https' if ssl else 'http'}://{clean_host}:{port}",
            "host": clean_host,
            "port": port,
            "ssl": ssl,
            "timestamp": started_at.isoformat(sep=" ", timespec="seconds"),
            "error": str(exc),
        }

    finished_at = datetime.now()
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    highlights = _extract_highlights(stdout)

    return {
        "ok": completed.returncode == 0 or bool(stdout),
        "target_url": f"{'https' if ssl else 'http'}://{clean_host}:{port}",
        "host": clean_host,
        "port": port,
        "ssl": ssl,
        "timestamp": started_at.isoformat(sep=" ", timespec="seconds"),
        "finished_at": finished_at.isoformat(sep=" ", timespec="seconds"),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 2),
        "returncode": completed.returncode,
        "findings_count": len(highlights),
        "highlights": highlights,
        "raw_output": stdout,
        "stderr": stderr,
    }