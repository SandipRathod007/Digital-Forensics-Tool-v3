# Digital-Forensics-Tool-v3
Read-only Python Digital Forensics &amp; Incident Triage Tool with Live GUI Monitor and PDF export.
# Digital Forensics & Incident Triage Tool v3.0

A lightweight, strictly read-only Python tool for fast live system triage and real-time monitoring on Windows and Linux. Built using **Python 3.6+ standard library only** (zero external packages required).

## Key Features
* **4 Modular Collectors:**
  * `os_info.py` — OS details, hardware, network interfaces, active TCP connections, firewall, Defender status, and USB history.
  * `process_startup.py` — Running processes, Top-25 RAM consumers, startup persistence (Registry/Autostart), and suspicious process checks.
  * `event_logs.py` — System, Application, and Security logs with hunting for Event IDs `4625`, `1102`, `7045`, and `4688`.
  * `file_metadata.py` — Scans `Downloads`, `Desktop`, and `Documents` for SHA-256 hashes, double-extension masquerades, and timestomping.
* **Live Desktop GUI (`gui.py`):** Includes a **Triage Scan** tab and a **Live Monitor** tab that polls every 2 seconds for file changes (Created/Deleted/Modified), USB plug-in/plug-out events, and new system logs.
* **Automated Reporting (`main.py`):** Generates a 0–100 Threat Risk Score, unified Incident Timeline, JSON output, an interactive HTML dashboard with **Export to PDF**, and a SHA-256 integrity seal (`ISO/IEC 27037` compliant).
* **Non-Admin Friendly:** Works with Standard User accounts without crashing when restricted logs are inaccessible.

## How to Run

### 1. Launch the Live GUI (Recommended)
```bash
python3 gui.py
