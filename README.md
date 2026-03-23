```
   ___    __ __ ____  ____   ___ 
  / _ |  / //_//  _/ / __ \ / _ |
 / __ | / ,<  _/ /  / /_/ // __ |
/_/ |_|/_/|_|/___/  \____//_/ |_|
```
> *Guided penetration testing CLI for ethical hacking, recon, and web assessment.*

---

```
[ TARGET ACQUIRED ]  [ SCAN INITIATED ]  [ REPORT GENERATED ]
```

---

## What is AKIRA?

AKIRA is a Python-based, interactive CLI security tool that combines **Nmap**, **Nikto**, and **Gobuster** into a guided workflow designed for cybersecurity learners, bug bounty hunters, and ethical hackers.

It simplifies reconnaissance by making scan choices easier to understand, while still supporting advanced options, root mode, and structured output.

---

## Features

```
┌─────────────────────────────────────────────────────────┐
│                    AKIRA CAPABILITIES                   │
├─────────────────────────────────────────────────────────┤
│  ◈  Interactive, beginner-friendly CLI                  │
│  ◈  Metasploit-inspired terminal experience             │
│  ◈  Root-aware scanning support                         │
│  ◈  Custom Nmap flags and scan speed selection          │
│  ◈  Automatic discovery of web targets                  │
│  ◈  Nikto integration for web vulnerability checks      │
│  ◈  Gobuster integration for directory enumeration      │
│  ◈  Recursive Gobuster mode                             │
│  ◈  Structured scan output in JSON                      │
│  ◈  Markdown report generation                          │
│  ◈  Clear explanations and usage hints throughout       │
└─────────────────────────────────────────────────────────┘
```

### Nmap Profile Selection

| Profile  | Description                          |
|----------|--------------------------------------|
| Quick    | Fast scan of common ports            |
| Balanced | Service detection with moderate speed|
| Full     | Complete scan with all features      |
| Custom   | Define your own flags and options    |

### Port Strategy Options

| Strategy       | Description                        |
|----------------|------------------------------------|
| Default        | Top ports (fastest)                |
| All Ports      | Full range 1–65535                 |
| Web Ports      | 80, 443, 8080, 8443, etc.          |
| Custom Range   | Define your own range              |

---

## What AKIRA Does

AKIRA automates the early stages of penetration testing and reconnaissance.

```
  [1] Scan a target with Nmap
       └─► [2] Identify open, closed, and filtered ports
                └─► [3] Detect services and service versions
                         └─► [4] Detect web services automatically
                                  └─► [5] Run Nikto against web targets
                                           └─► [6] Run Gobuster with chosen wordlist
                                                    └─► [7] Save results for review
```

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/0xprxdhx/akira.git
cd akira
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python dependencies

```bash
pip install python-nmap rich
```

### 4. Install system tools

On Parrot OS / Debian-based systems:

```bash
sudo apt update
sudo apt install nmap nikto gobuster seclists dirb -y
```

---

## Usage

### Run in normal mode

```bash
akira
```

### Run in root mode for full Nmap features

```bash
sudo akira
```

> **Root mode** enables Nmap features such as SYN scan, OS detection, aggressive mode, and traceroute.

### Workflow

AKIRA guides you step by step:

```
  [1]  Enter a target
  [2]  Choose a scan profile
  [3]  Pick Nmap features, speed, and ports
  [4]  Run the scan
  [5]  Review results
  [6]  Choose whether to run Nikto
  [7]  Choose whether to run Gobuster
  [8]  Save results and generate a report
```

---

## Output

AKIRA stores all results in the `results/` folder:

```
results/
├── nmap_output.json
├── nikto_output.json
├── gobuster_output.json
├── session.json
└── report.md
```

---

## Project Structure

```
akira/
├── main.py
├── scanner/
│   ├── nmap_scan.py
│   ├── nikto_scan.py
│   └── gobuster_scan.py
├── results/
├── venv/
└── README.md
```

---

## Supported Tools

```
┌──────────────┬────────────────────────────────────────────┐
│  Tool        │  Purpose                                   │
├──────────────┼────────────────────────────────────────────┤
│  Nmap        │  Port scanning, service & OS detection     │
│  Nikto       │  Web server vulnerability scanning         │
│  Gobuster    │  Directory & file enumeration              │
└──────────────┴────────────────────────────────────────────┘
```

---

## Planned Improvements

```
  [ ]  ffuf integration
  [ ]  whatweb integration
  [ ]  httpx integration
  [ ]  sslscan integration
  [ ]  Better session history
  [ ]  HTML report export
  [ ]  Plugin-based scan modules
  [ ]  Faster parallel scan execution
```

---

## Contributing

Contributions are welcome.

If you want to contribute:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Open a pull request

Please keep contributions focused on **usability**, **reliability**, and **ethical security testing**.

---

## Disclaimer

```
╔══════════════════════════════════════════════════════════════╗
║  AKIRA is intended for authorized security testing,          ║
║  learning, and defensive use only.                           ║
║                                                              ║
║  Do not scan systems you do not own or have explicit         ║
║  permission to test. Unauthorized scanning is illegal.       ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Author

**Pradhyuman Singh**  
GitHub: [@0xprxdhx](https://github.com/0xprxdhx)

---

```
[ AKIRA v1.0 ]  [ ETHICAL HACKING ONLY ]  [ STAY LEGAL ]
```
