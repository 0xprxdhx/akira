# File: scanner/nmap_scan.py
from datetime import datetime
from typing import Iterable, List, Optional

import os
import nmap


def _normalize_flags(scan_flags: Optional[Iterable[str]]) -> List[str]:
    if scan_flags is None:
        return []

    if isinstance(scan_flags, str):
        items = scan_flags.split()
    else:
        items = list(scan_flags)

    flags: List[str] = []
    for item in items:
        flag = str(item).strip()
        if flag and flag not in flags:
            flags.append(flag)

    return flags


def _apply_safe_fallbacks(flags: List[str]) -> tuple[list[str], list[str]]:
    notes: List[str] = []
    cleaned = list(dict.fromkeys(flags))

    if os.geteuid() != 0:
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

    if not cleaned:
        cleaned = ["-sV"]
        notes.append("Falling back to version detection.")

    return cleaned, notes


def run_nmap_scan(
    target: str,
    scan_flags: Optional[Iterable[str]] = None,
    speed: str = "-T4",
    ports: Optional[str] = None,
):
    """
    Run Nmap and return a JSON-friendly structured result.
    Records every discovered TCP port state, not only open ports.
    """
    started_at = datetime.now()
    flags = _normalize_flags(scan_flags)

    if not flags:
        flags = ["-sV"]

    flags, notes = _apply_safe_fallbacks(flags)

    if not speed:
        speed = "-T4"

    arguments = " ".join([*flags, speed]).strip()

    nm = nmap.PortScanner()

    try:
        if ports:
            nm.scan(hosts=target, ports=str(ports), arguments=arguments)
        else:
            nm.scan(hosts=target, arguments=arguments)
    except Exception as exc:
        return {
            "ok": False,
            "target": target,
            "timestamp": started_at.isoformat(sep=" ", timespec="seconds"),
            "arguments": arguments,
            "ports": ports if ports else "default",
            "notes": notes,
            "error": str(exc),
        }

    hosts = []

    for host in nm.all_hosts():
        host_data = {
            "ip": host,
            "hostname": nm[host].hostname(),
            "state": nm[host].state(),
            "protocols": {},
            "open_ports": [],
            "closed_ports": [],
            "filtered_ports": [],
            "other_ports": [],
        }

        for proto in nm[host].all_protocols():
            proto_entries = []

            for port in sorted(nm[host][proto].keys()):
                service = nm[host][proto][port]
                state = service.get("state", "")

                entry = {
                    "port": port,
                    "state": state,
                    "service": service.get("name", ""),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "extrainfo": service.get("extrainfo", ""),
                    "cpe": service.get("cpe", []),
                }

                proto_entries.append(entry)

                bucket = {
                    "proto": proto,
                    **entry,
                }

                if state == "open":
                    host_data["open_ports"].append(bucket)
                elif state == "closed":
                    host_data["closed_ports"].append(bucket)
                elif state == "filtered":
                    host_data["filtered_ports"].append(bucket)
                else:
                    host_data["other_ports"].append(bucket)

            host_data["protocols"][proto] = proto_entries

        hosts.append(host_data)

    finished_at = datetime.now()
    elapsed_seconds = round((finished_at - started_at).total_seconds(), 2)

    summary = {
        "hosts_total": len(hosts),
        "hosts_up": sum(1 for host in hosts if host.get("state") == "up"),
        "open_ports_total": sum(len(host.get("open_ports", [])) for host in hosts),
        "closed_ports_total": sum(len(host.get("closed_ports", [])) for host in hosts),
        "filtered_ports_total": sum(len(host.get("filtered_ports", [])) for host in hosts),
        "other_ports_total": sum(len(host.get("other_ports", [])) for host in hosts),
        "elapsed_seconds": elapsed_seconds,
    }

    try:
        scanstats = nm.scanstats()
    except Exception:
        scanstats = {}

    return {
        "ok": True,
        "target": target,
        "timestamp": started_at.isoformat(sep=" ", timespec="seconds"),
        "finished_at": finished_at.isoformat(sep=" ", timespec="seconds"),
        "arguments": arguments,
        "ports": ports if ports else "default",
        "notes": notes,
        "scanstats": scanstats,
        "summary": summary,
        "hosts": hosts,
    }