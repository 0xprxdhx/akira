# AKIRA

> Guided penetration testing CLI for ethical hacking, recon, and web assessment.

AKIRA is a Python-based, interactive CLI security tool that combines **Nmap**, **Nikto**, and **Gobuster** into a guided workflow designed for cybersecurity learners, bug bounty hunters, and ethical hackers.

It simplifies reconnaissance by making scan choices easier to understand, while still supporting advanced options, root mode, and structured output.

---

## Features

- Interactive, beginner-friendly CLI
- Metasploit-inspired terminal experience
- Nmap profile selection:
  - Quick
  - Balanced
  - Full
  - Custom
- Root-aware scanning support
- Custom Nmap flags and scan speed selection
- Port strategy options:
  - Default top ports
  - All ports
  - Web ports
  - Custom range
- Automatic discovery of web targets
- Nikto integration for web vulnerability checks
- Gobuster integration for directory and file enumeration
- Gobuster wordlist selection
- Recursive Gobuster mode
- Structured scan output in JSON
- Markdown report generation
- Clear explanations and usage hints throughout the workflow

---

## What AKIRA Does

AKIRA helps automate the early stages of penetration testing and reconnaissance.

It can:

1. Scan a target with Nmap
2. Identify open, closed, and filtered ports
3. Detect services and service versions
4. Detect web services automatically
5. Run Nikto against web targets
6. Run Gobuster with a chosen wordlist
7. Save results for later review

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/0xprxdhx/akira.git
cd akira
2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate
3. Install Python dependencies
pip install python-nmap rich
4. Install system tools

On Parrot OS / Debian-based systems:

sudo apt update
sudo apt install nmap nikto gobuster seclists dirb -y
Usage
Run in normal mode
akira
Run in root mode for full Nmap features
sudo akira

Root mode enables Nmap features such as SYN scan, OS detection, aggressive mode, and traceroute.

Workflow

AKIRA guides you step by step:

Enter a target
Choose a scan profile
Pick Nmap features, speed, and ports
Run the scan
Review results
Choose whether to run Nikto
Choose whether to run Gobuster
Save results and generate a report
Output

AKIRA stores results in the results/ folder:

nmap_output.json
nikto_output.json
gobuster_output.json
session.json
report.md
Project Structure
akira/
├── main.py
├── scanner/
│   ├── nmap_scan.py
│   ├── nikto_scan.py
│   └── gobuster_scan.py
├── results/
├── venv/
└── README.md
Supported Tools
Nmap
Nikto
Gobuster
Planned Improvements
ffuf integration
whatweb integration
httpx integration
sslscan integration
Better session history
HTML report export
Plugin-based scan modules
Faster parallel scan execution
Contributing

Contributions are welcome.

If you want to contribute:

Fork the repository
Create a feature branch
Make your changes
Open a pull request

Please keep contributions focused on usability, reliability, and ethical security testing.

Disclaimer

AKIRA is intended for authorized security testing, learning, and defensive use only.

Do not scan systems you do not own or have permission to test.

Author

Pradhyuman Singh
GitHub: 0xprxdhx