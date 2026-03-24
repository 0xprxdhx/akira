<div align="center">

```
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░                                                           ░
░    ▄▀█ █▄▀ █ █▀█ ▄▀█                                     ░
░    █▀█ █░█ █ █▀▄ █▀█                                     ░
░                                                           ░
░    guided penetration testing cli                         ░
░    recon · web assessment · ethical hacking               ░
░                                                           ░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
```

<br/>

![Python](https://img.shields.io/badge/Python-3.x-red?style=flat-square&labelColor=111&color=cc0000)
![License](https://img.shields.io/badge/License-MIT-red?style=flat-square&labelColor=111&color=cc0000)
![Platform](https://img.shields.io/badge/Platform-Linux-red?style=flat-square&labelColor=111&color=cc0000)
![Status](https://img.shields.io/badge/Status-Active-red?style=flat-square&labelColor=111&color=cc0000)

<br/>

> **rexa** is a Python-based interactive CLI that combines **Nmap**, **Nikto**, and **Gobuster**  
> into one clean, guided penetration testing workflow — built for clarity, power, and reporting.

<br/>

</div>

---

## `>` What is rexa?

rexa automates the early stages of penetration testing and reconnaissance. It wraps three industry-standard tools into a single guided workflow — ideal for both beginners learning the ropes and professionals who want faster, structured output.

No more juggling flags across three terminals. rexa does it with you, step by step.

---

## `>` Features

```
[ CORE ]
  ✦  Interactive CLI with a clean terminal experience
  ✦  Metasploit-inspired banner and guided prompts
  ✦  Root-aware scanning support
  ✦  Beginner-friendly guidance at each step
  ✦  Works in both normal and root mode

[ NMAP ]
  ✦  Quick / Balanced / Full / Custom scan profiles
  ✦  Custom feature selection (SYN, OS detection, aggressive, traceroute)
  ✦  Scan speed selection
  ✦  Port strategies — top ports, all ports, web ports, custom range

[ WEB ]
  ✦  Automatic web service detection
  ✦  Nikto integration for vulnerability checks
  ✦  Gobuster directory and file enumeration
  ✦  Wordlist selection & recursive mode
  ✦  Status code filtering

[ OUTPUT ]
  ✦  Structured JSON output
  ✦  Markdown report generation
  ✦  Summary file for quick review
```

---

## `>` How It Works

rexa strings together three tools into one coherent workflow:

```
  TARGET INPUT
       │
       ▼
  ┌─────────┐     discovers hosts, ports, services
  │  NMAP   │ ──────────────────────────────────────────────────────┐
  └─────────┘                                                       │
       │                                                            │
       ▼  (web service detected?)                                   │
  ┌─────────┐     checks web servers for common vulnerabilities     │
  │  NIKTO  │ ──────────────────────────────────────────────────────┤
  └─────────┘                                                       │
       │                                                            │
       ▼                                                            │
  ┌──────────┐    enumerates hidden directories and files           │
  │ GOBUSTER │ ──────────────────────────────────────────────────────┤
  └──────────┘                                                       │
       │                                                            │
       ▼                                                            ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │              results/   →   JSON + Markdown + Summary            │
  └──────────────────────────────────────────────────────────────────┘
```

> Root mode unlocks advanced Nmap features: SYN scan, OS detection, aggressive mode, traceroute.

---

## `>` Installation

### 1 — Clone the repository

```bash
git clone https://github.com/0xprxdhx/rexa.git
cd rexa
```

### 2 — Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3 — Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4 — Install system tools

```bash
sudo apt update
sudo apt install -y nmap nikto gobuster seclists dirb
```

### 5 — Install rexa as a command

```bash
chmod +x install.sh
./install.sh
```

After installation, launch with:

```bash
rexa          # normal mode
sudo rexa     # root mode (recommended)
```

---

## `>` Usage

### Normal mode

```bash
rexa
```

### Root mode

```bash
sudo rexa
```

Root mode is recommended for SYN scanning, OS detection, aggressive mode, and traceroute.

---

## `>` Scan Workflow

rexa guides you through 10 steps — no flags to memorize:

```
  01  Enter a target
  02  Choose a scan profile
  03  Select scan features
  04  Choose scan speed
  05  Choose port strategy
  06  Review the scan plan
  07  Run Nmap
  08  Choose whether to run Nikto
  09  Choose whether to run Gobuster
  10  Save results and generate report
```

---

## `>` Gobuster Wordlists

rexa supports six wordlist options out of the box:

| # | Wordlist | Use Case |
|---|----------|----------|
| 1 | `dirb/common.txt` | Fast common directory scan |
| 2 | `dirbuster/directory-list-2.3-medium.txt` | Medium-depth enumeration |
| 3 | `SecLists/Discovery/Web-Content/common.txt` | SecLists common |
| 4 | `SecLists/.../raft-small-words.txt` | Raft small |
| 5 | `SecLists/.../raft-medium-words.txt` | Raft medium (thorough) |
| 6 | Custom path | Bring your own wordlist |

---

## `>` Output Files

All results are saved inside the `results/` folder:

```
results/
├── nmap_output.json       ← port and service data
├── nikto_output.json      ← web vulnerability findings
├── gobuster_output.json   ← directory enumeration results
├── session.json           ← full session data
├── report.md              ← human-readable markdown report
└── summary.txt            ← quick overview
```

---

## `>` Project Structure

```
rexa/
├── main.py
├── install.sh
├── requirements.txt
├── README.md
├── LICENSE
├── scanner/
│   ├── nmap_scan.py
│   ├── nikto_scan.py
│   └── gobuster_scan.py
├── results/
└── venv/
```

---

## `>` Planned Improvements

```
  ◻  ffuf integration
  ◻  httpx integration
  ◻  whatweb integration
  ◻  sslscan integration
  ◻  HTML report export
  ◻  Session history and comparison
  ◻  Plugin system for additional scanners
  ◻  Faster parallel execution
```

---

## `>` Contributing

Contributions are welcome.

```
  1  Fork the repository
  2  Create a feature branch
  3  Make your changes
  4  Submit a pull request
```

Please keep contributions focused on **usability**, **reliability**, and **ethical security testing**.

---

## `>` License

This project is licensed under the **MIT License**.

---

## `>` Disclaimer

```
╔══════════════════════════════════════════════════════════════╗
║  rexa is intended for authorized security testing,          ║
║  learning, and defensive use only.                           ║
║                                                              ║
║  Do not scan systems you do not own or do not have           ║
║  explicit permission to test.                                ║
╚══════════════════════════════════════════════════════════════╝
```

---

<div align="center">

```
made by  0xprxdhx  ·  Pradhyuman Singh
github.com/0xprxdhx/rexa
```

</div>
