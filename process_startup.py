"""
=============================================================================
Digital Forensics & Incident Triage Tool  v3.0
Module  : Processes, Persistence & Anomaly Detection
File    : process_startup.py

Author  : Principal Security Engineer
Purpose : Read-only forensic collection of running processes, startup
          persistence mechanisms, and behavioural suspicious indicators.

Dependencies : Python 3.6+ standard library ONLY
               os, sys, subprocess, csv, io, datetime, json, platform
               winreg  (Windows only – imported conditionally)

Usage   :
    from process_startup import collect_artifacts
    result = collect_artifacts()
    print(json.dumps(result, indent=2))
=============================================================================
"""

import os
import sys
import subprocess
import csv
import io
import json
import platform
from datetime import datetime

# ---------------------------------------------------------------------------
# Optional Windows-only import
# ---------------------------------------------------------------------------
try:
    import winreg
    _WINREG_AVAILABLE = True
except ImportError:
    _WINREG_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODULE_NAME    = "Processes, Persistence & Anomaly Detection"
MODULE_VERSION = "3.0"

# Processes that commonly run as multiple instances; they are grouped to
# reduce noise in the individual process list.
GROUPED_PROCESS_NAMES = {
    "svchost.exe",
    "runtimebroker.exe",
    "conhost.exe",
    "dllhost.exe",
    "searchprotocolhost.exe",
    "searchfilterhost.exe",
    "wmiprvse.exe",
    "audiodg.exe",
}

# Known offensive / IoC tooling – immediate HIGH_RISK flag.
IOC_TOOL_NAMES = {
    "mimikatz.exe",
    "nc.exe",
    "ncat.exe",
    "psexec.exe",
    "psexec64.exe",
    "meterpreter",
    "cobaltstrike",
    "beacon.exe",
    "wce.exe",
    "fgdump.exe",
    "pwdump.exe",
}

# Common typo-squatting names targeting core Windows processes.
TYPOSQUAT_NAMES = {
    "scvhost.exe",
    "svchosts.exe",
    "csrss32.exe",
    "lssas.exe",
    "lsass32.exe",
    "iexplore32.exe",
    "rundl132.exe",
    "taskhost32.exe",
    "powershel.exe",
    "explorer32.exe",
}

# Path fragments that indicate a process is running from a suspicious location.
SUSPICIOUS_PATH_FRAGMENTS = [
    "\\temp\\",
    "\\downloads\\",
    "\\appdata\\local\\temp\\",
    "users\\public\\",
    "\\appdata\\roaming\\",
]

# File extensions considered executable for path-based heuristics.
EXECUTABLE_EXTENSIONS = {".exe", ".bat", ".cmd", ".ps1"}

# Registry run-key definitions: (hive_short, hive_label, sub_key, source_label)
REGISTRY_RUN_KEYS = [
    (
        "HKCU",
        "HKEY_CURRENT_USER",
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "Registry (HKCU)",
    ),
    (
        "HKCU",
        "HKEY_CURRENT_USER",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "Registry (HKCU)",
    ),
    (
        "HKLM",
        "HKEY_LOCAL_MACHINE",
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        "Registry (HKLM)",
    ),
    (
        "HKLM",
        "HKEY_LOCAL_MACHINE",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "Registry (HKLM)",
    ),
]

# Approximate total RAM assumed for Linux %mem → KB conversion (8 GB).
LINUX_ASSUMED_RAM_KB = 8 * 1024 * 1024  # 8,388,608 KB


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _now_str() -> str:
    """Return the current local datetime as a human-readable string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _run(cmd_list: list, timeout: int = 12) -> subprocess.CompletedProcess:
    """
    Execute *cmd_list* as a subprocess in a strictly read-only, non-interactive
    manner.  Returns a CompletedProcess; never raises – errors surface via the
    caller examining returncode / stderr.
    """
    return subprocess.run(
        cmd_list,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        shell=False,
        timeout=timeout,
    )


def _parse_windows_memory(raw: str) -> int:
    """
    Convert a Windows tasklist memory string such as ``"12,345 K"`` to an
    integer number of kilobytes (12345).  Returns 0 on any parse failure.
    """
    try:
        cleaned = raw.strip().replace(",", "").replace(" K", "").replace("K", "")
        return int(cleaned)
    except (ValueError, AttributeError):
        return 0


def _parse_linux_mem_percent(raw: str) -> int:
    """
    Convert a ``ps`` ``%mem`` value (e.g. ``"1.5"``) to an approximate
    kilobyte figure based on *LINUX_ASSUMED_RAM_KB*.  Returns 0 on failure.
    """
    try:
        pct = float(raw.strip())
        return int((pct / 100.0) * LINUX_ASSUMED_RAM_KB)
    except (ValueError, AttributeError):
        return 0


def _file_ext(name: str) -> str:
    """Return the lower-case file extension including the dot, or empty string."""
    _, ext = os.path.splitext(name)
    return ext.lower()


# ---------------------------------------------------------------------------
# Process collection – Windows
# ---------------------------------------------------------------------------

def _collect_processes_windows() -> tuple:
    """
    Run ``tasklist /FO CSV /V`` and parse the CSV output.

    Returns
    -------
    processes : list[dict]
        Each dict contains keys: ``name``, ``pid``, ``memory_kb``,
        ``status``, ``user``, ``window_title``.
    limitation : str | None
        A human-readable error string, or *None* on success.
    """
    processes = []
    limitation = None

    try:
        result = _run(["tasklist", "/FO", "CSV", "/V"], timeout=12)
    except FileNotFoundError:
        return processes, "tasklist.exe not found on this system."
    except subprocess.TimeoutExpired:
        return processes, "tasklist /FO CSV /V timed out after 12 seconds."
    except Exception as exc:
        return processes, f"tasklist execution error: {exc}"

    if result.returncode != 0 and not result.stdout.strip():
        return processes, (
            f"tasklist returned non-zero exit ({result.returncode}): "
            f"{result.stderr.strip()}"
        )

    # Parse CSV – tasklist /FO CSV /V produces a header row followed by data.
    # Field names (English locale):
    #   "Image Name","PID","Session Name","Session#","Mem Usage",
    #   "Status","User Name","CPU Time","Window Title"
    try:
        reader = csv.DictReader(io.StringIO(result.stdout))
        for row in reader:
            name         = row.get("Image Name", "").strip()
            pid          = row.get("PID", "").strip()
            mem_raw      = row.get("Mem Usage", "0 K").strip()
            status       = row.get("Status", "").strip()
            user         = row.get("User Name", "").strip()
            window_title = row.get("Window Title", "").strip()

            if not name:
                continue

            processes.append({
                "name"         : name,
                "pid"          : pid,
                "memory_kb"    : _parse_windows_memory(mem_raw),
                "status"       : status,
                "user"         : user,
                "window_title" : window_title,
            })
    except Exception as exc:
        limitation = f"CSV parse error from tasklist output: {exc}"

    return processes, limitation


# ---------------------------------------------------------------------------
# Process collection – Linux / Darwin
# ---------------------------------------------------------------------------

def _collect_processes_linux() -> tuple:
    """
    Run ``ps -eo pid,comm,user,%mem,stat`` and parse the output.

    Returns
    -------
    processes : list[dict]
        Each dict contains keys: ``name``, ``pid``, ``memory_kb``,
        ``status``, ``user``, ``window_title`` (always empty on Linux).
    limitation : str | None
    """
    processes = []
    limitation = None

    try:
        result = _run(["ps", "-eo", "pid,comm,user,%mem,stat"], timeout=12)
    except FileNotFoundError:
        return processes, "ps command not found on this system."
    except subprocess.TimeoutExpired:
        return processes, "ps -eo timed out after 12 seconds."
    except Exception as exc:
        return processes, f"ps execution error: {exc}"

    if result.returncode != 0 and not result.stdout.strip():
        return processes, (
            f"ps returned non-zero exit ({result.returncode}): "
            f"{result.stderr.strip()}"
        )

    lines = result.stdout.splitlines()
    # Skip the header line (index 0).
    for line in lines[1:]:
        parts = line.split(None, 4)  # split on whitespace, max 5 tokens
        if len(parts) < 4:
            continue
        pid     = parts[0].strip()
        name    = parts[1].strip()
        user    = parts[2].strip()
        mem_pct = parts[3].strip()
        stat    = parts[4].strip() if len(parts) > 4 else ""

        processes.append({
            "name"         : name,
            "pid"          : pid,
            "memory_kb"    : _parse_linux_mem_percent(mem_pct),
            "status"       : stat,
            "user"         : user,
            "window_title" : "",
        })

    return processes, limitation


# ---------------------------------------------------------------------------
# Process grouping & ranking
# ---------------------------------------------------------------------------

def _group_and_rank(processes: list) -> tuple:
    """
    Split *processes* into:
    1. ``grouped``  – known multi-instance benign processes, aggregated.
    2. ``top25``    – top-25 memory consumers from the remaining processes.

    Parameters
    ----------
    processes : Full flat list of collected process dicts.

    Returns
    -------
    grouped : list[dict]
        Sorted by ``instance_count`` descending.
    top25 : list[dict]
        Sorted by ``memory_kb`` descending, rank 1–25.
    """
    grouped_accumulator: dict = {}  # lower_name → {"name", "instance_count", "total_memory_kb"}
    remaining = []

    for proc in processes:
        lower_name = proc["name"].lower()
        if lower_name in GROUPED_PROCESS_NAMES:
            if lower_name not in grouped_accumulator:
                grouped_accumulator[lower_name] = {
                    "name"           : proc["name"],
                    "instance_count" : 0,
                    "total_memory_kb": 0,
                }
            grouped_accumulator[lower_name]["instance_count"] += 1
            grouped_accumulator[lower_name]["total_memory_kb"] += proc["memory_kb"]
        else:
            remaining.append(proc)

    # Sort grouped by instance count descending.
    grouped = sorted(
        grouped_accumulator.values(),
        key=lambda g: g["instance_count"],
        reverse=True,
    )

    # Sort remaining by memory descending and slice top 25.
    remaining_sorted = sorted(remaining, key=lambda p: p["memory_kb"], reverse=True)
    top25 = []
    for rank, proc in enumerate(remaining_sorted[:25], start=1):
        top25.append({
            "rank"      : rank,
            "name"      : proc["name"],
            "pid"       : proc["pid"],
            "memory_kb" : proc["memory_kb"],
            "user"      : proc["user"],
            "status"    : proc["status"],
        })

    return grouped, top25


# ---------------------------------------------------------------------------
# Registry startup collection (Windows only)
# ---------------------------------------------------------------------------

def _collect_registry_run_keys() -> tuple:
    """
    Open each of the four standard Run/RunOnce registry keys with KEY_READ
    and enumerate their values.

    Returns
    -------
    entries : list[dict]
        Each dict: ``name``, ``command``, ``location``, ``source``.
    limitations : list[str]
        Any access errors encountered.
    """
    entries     = []
    limitations = []

    if not _WINREG_AVAILABLE:
        limitations.append("winreg module unavailable – not a Windows environment.")
        return entries, limitations

    hive_map = {
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
    }

    for hive_short, hive_label, sub_key, source_label in REGISTRY_RUN_KEYS:
        hive_const = hive_map.get(hive_short)
        if hive_const is None:
            limitations.append(f"Unknown hive identifier: {hive_short}")
            continue

        location = f"{hive_label}\\{sub_key}"

        try:
            with winreg.OpenKey(hive_const, sub_key, 0, winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        value_name, value_data, _value_type = winreg.EnumValue(key, index)
                        entries.append({
                            "name"    : value_name,
                            "command" : str(value_data),
                            "location": location,
                            "source"  : source_label,
                        })
                        index += 1
                    except OSError:
                        # No more values under this key – EnumValue raises
                        # OSError (WindowsError) when the index is exhausted.
                        break
        except PermissionError:
            limitations.append(f"Access denied reading registry key: {location}")
        except FileNotFoundError:
            # Key does not exist on this system – perfectly normal, not an error.
            pass
        except OSError as exc:
            limitations.append(f"OS error reading registry key {location}: {exc}")

    return entries, limitations


# ---------------------------------------------------------------------------
# Startup folder collection
# ---------------------------------------------------------------------------

def _collect_startup_folder_windows() -> tuple:
    """
    Enumerate the current-user Windows startup folder located at:
    ``%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup``

    Returns
    -------
    items : list[dict]
        Each dict: ``name``, ``path``, ``size_bytes``, ``modified_time``.
    limitation : str | None
    """
    items = []

    startup_dir = os.path.expandvars(
        r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    if not os.path.isdir(startup_dir):
        return items, f"Startup folder not found: {startup_dir}"

    try:
        for entry_name in os.listdir(startup_dir):
            full_path = os.path.join(startup_dir, entry_name)
            try:
                stat_info   = os.stat(full_path)
                size_bytes  = stat_info.st_size
                mod_time    = datetime.fromtimestamp(stat_info.st_mtime).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            except OSError:
                size_bytes = 0
                mod_time   = "unknown"

            items.append({
                "name"         : entry_name,
                "path"         : full_path,
                "size_bytes"   : size_bytes,
                "modified_time": mod_time,
            })
    except PermissionError:
        return items, f"Permission denied listing startup folder: {startup_dir}"
    except OSError as exc:
        return items, f"Error listing startup folder: {exc}"

    return items, None


def _collect_startup_folder_linux() -> tuple:
    """
    Enumerate ``/etc/init.d/`` and ``~/.config/autostart/`` on Linux/Darwin.

    Returns
    -------
    items : list[dict]
    limitation : str | None
    """
    items = []
    limitations = []

    candidate_dirs = [
        "/etc/init.d",
        os.path.expanduser("~/.config/autostart"),
    ]

    for scan_dir in candidate_dirs:
        if not os.path.isdir(scan_dir):
            continue
        try:
            for entry_name in os.listdir(scan_dir):
                full_path = os.path.join(scan_dir, entry_name)
                if not os.path.isfile(full_path):
                    continue
                try:
                    stat_info   = os.stat(full_path)
                    size_bytes  = stat_info.st_size
                    mod_time    = datetime.fromtimestamp(stat_info.st_mtime).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                except OSError:
                    size_bytes = 0
                    mod_time   = "unknown"

                items.append({
                    "name"         : entry_name,
                    "path"         : full_path,
                    "size_bytes"   : size_bytes,
                    "modified_time": mod_time,
                })
        except PermissionError:
            limitations.append(f"Permission denied listing autostart dir: {scan_dir}")
        except OSError as exc:
            limitations.append(f"Error listing autostart dir {scan_dir}: {exc}")

    limitation = "; ".join(limitations) if limitations else None
    return items, limitation


# ---------------------------------------------------------------------------
# Suspicious indicator analysis
# ---------------------------------------------------------------------------

def _build_suspicious_indicators(
    all_processes    : list,
    registry_entries : list,
    startup_items    : list,
) -> list:
    """
    Examine collected data against forensic heuristics and return a list of
    indicator dicts.

    Each indicator contains:
    - ``severity``  : "HIGH_RISK" | "SUSPICIOUS" | "INFO"
    - ``indicator`` : Short human-readable label.
    - ``details``   : Full contextual description.
    - ``timestamp`` : Current datetime string.

    Parameters
    ----------
    all_processes    : Full flat list of collected process dicts.
    registry_entries : Registry run-key entries.
    startup_items    : Startup folder items.
    """
    indicators = []
    ts = _now_str()

    # ------------------------------------------------------------------
    # 1. Known IoC tool names  →  HIGH_RISK
    # ------------------------------------------------------------------
    for proc in all_processes:
        lower_name = proc["name"].lower()
        if lower_name in IOC_TOOL_NAMES:
            indicators.append({
                "severity" : "HIGH_RISK",
                "indicator": f"Known offensive tool detected: {proc['name']}",
                "details"  : (
                    f"Process '{proc['name']}' (PID: {proc['pid']}) matches a known "
                    f"offensive/IoC tool name. Immediate investigation required."
                ),
                "timestamp": ts,
            })

    # ------------------------------------------------------------------
    # 2. Typo-squatting names  →  HIGH_RISK
    # ------------------------------------------------------------------
    for proc in all_processes:
        lower_name = proc["name"].lower()
        if lower_name in TYPOSQUAT_NAMES:
            indicators.append({
                "severity" : "HIGH_RISK",
                "indicator": f"Typo-squatting process name detected: {proc['name']}",
                "details"  : (
                    f"Process '{proc['name']}' (PID: {proc['pid']}) resembles a "
                    f"legitimate Windows system process name but contains a known "
                    f"typo-squatting pattern. Likely malicious masquerade attempt."
                ),
                "timestamp": ts,
            })

    # ------------------------------------------------------------------
    # 3. Suspicious executable paths  →  SUSPICIOUS
    #
    #    tasklist /FO CSV /V does not expose the full ImagePath directly.
    #    The "Window Title" column is used as a best-effort path hint;
    #    some processes populate it with their working directory or path.
    #    A production environment with WMI access would query Win32_Process
    #    for ExecutablePath, but we stay stdlib-only here.
    # ------------------------------------------------------------------
    for proc in all_processes:
        path_hint = proc.get("window_title", "").lower()
        name_ext  = _file_ext(proc["name"])
        if name_ext not in EXECUTABLE_EXTENSIONS:
            continue
        for fragment in SUSPICIOUS_PATH_FRAGMENTS:
            if fragment in path_hint:
                indicators.append({
                    "severity" : "SUSPICIOUS",
                    "indicator": f"Process running from suspicious path: {proc['name']}",
                    "details"  : (
                        f"Process '{proc['name']}' (PID: {proc['pid']}) appears to "
                        f"execute from a suspicious location containing "
                        f"'{fragment.strip(chr(92))}'. "
                        f"Path hint (Window Title): '{proc.get('window_title', 'N/A')}'"
                    ),
                    "timestamp": ts,
                })
                break  # One indicator per process is sufficient.

    # ------------------------------------------------------------------
    # 4. Registry persistence entries  →  INFO
    # ------------------------------------------------------------------
    for entry in registry_entries:
        indicators.append({
            "severity" : "INFO",
            "indicator": f"Registry startup entry: {entry['name']}",
            "details"  : (
                f"Startup persistence entry '{entry['name']}' registered at "
                f"[{entry['location']}]. Command: {entry['command']}"
            ),
            "timestamp": ts,
        })

    # ------------------------------------------------------------------
    # 5. Executable startup folder items  →  SUSPICIOUS
    # ------------------------------------------------------------------
    for item in startup_items:
        if _file_ext(item["name"]) in {".exe", ".bat"}:
            indicators.append({
                "severity" : "SUSPICIOUS",
                "indicator": f"Executable file in startup folder: {item['name']}",
                "details"  : (
                    f"An executable item '{item['name']}' was found in the system/user "
                    f"startup folder at '{item['path']}'. "
                    f"Size: {item['size_bytes']} bytes. "
                    f"Modified: {item['modified_time']}."
                ),
                "timestamp": ts,
            })

    return indicators


# ---------------------------------------------------------------------------
# Main public API
# ---------------------------------------------------------------------------

def collect_artifacts() -> dict:
    """
    Perform a complete, read-only forensic snapshot of:

    * Running processes (grouped system processes + top-25 memory consumers)
    * Windows startup registry run keys (HKCU/HKLM Run & RunOnce)
    * Windows startup folder / Linux autostart directories
    * Behavioural suspicious indicators derived from the above data

    Returns
    -------
    dict
        A structured forensic artifact dictionary conforming to the v3.0
        schema.  ``status`` is ``"success"`` when no access limitations
        were encountered, or ``"limited_access"`` otherwise.
    """
    access_limitations: list = []
    collection_time            = _now_str()
    os_type                    = platform.system()   # "Windows", "Linux", "Darwin"

    # ------------------------------------------------------------------ #
    # Step 1 – Collect running processes                                   #
    # ------------------------------------------------------------------ #
    if os_type == "Windows":
        all_processes, proc_limitation = _collect_processes_windows()
    else:
        all_processes, proc_limitation = _collect_processes_linux()

    if proc_limitation:
        access_limitations.append(proc_limitation)

    # ------------------------------------------------------------------ #
    # Step 2 – Group benign multi-instance processes & rank the rest       #
    # ------------------------------------------------------------------ #
    grouped_system_procs, top_25 = _group_and_rank(all_processes)

    # ------------------------------------------------------------------ #
    # Step 3 – Registry run keys (Windows only)                            #
    # ------------------------------------------------------------------ #
    if os_type == "Windows":
        registry_entries, reg_limitations = _collect_registry_run_keys()
        access_limitations.extend(reg_limitations)
    else:
        registry_entries = []

    # ------------------------------------------------------------------ #
    # Step 4 – Startup folder items                                        #
    # ------------------------------------------------------------------ #
    if os_type == "Windows":
        startup_items, startup_limitation = _collect_startup_folder_windows()
        if startup_limitation:
            access_limitations.append(startup_limitation)
    else:
        startup_items, startup_limitation = _collect_startup_folder_linux()
        if startup_limitation:
            access_limitations.append(startup_limitation)

    # ------------------------------------------------------------------ #
    # Step 5 – Build suspicious indicators                                  #
    # ------------------------------------------------------------------ #
    suspicious_indicators = _build_suspicious_indicators(
        all_processes    = all_processes,
        registry_entries = registry_entries,
        startup_items    = startup_items,
    )

    # ------------------------------------------------------------------ #
    # Step 6 – Assemble and return the artifact dict                       #
    # ------------------------------------------------------------------ #
    status = "success" if not access_limitations else "limited_access"

    artifact = {
        "module_name"          : MODULE_NAME,
        "version"              : MODULE_VERSION,
        "status"               : status,
        "collection_time"      : collection_time,
        "access_limitations"   : access_limitations,
        "suspicious_indicators": suspicious_indicators,
        "artifacts"            : {
            "process_summary"   : {
                "total_processes"         : len(all_processes),
                "grouped_system_processes": grouped_system_procs,
                "top_25_memory_consumers" : top_25,
            },
            "startup_persistence": {
                "registry_run_keys"   : registry_entries,
                "startup_folder_items": startup_items,
            },
        },
    }

    return artifact


# ---------------------------------------------------------------------------
# CLI entry-point (optional stand-alone execution)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Digital Forensics & Incident Triage Tool v3.0 – "
            "Process & Persistence Module"
        )
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write JSON output to FILE instead of stdout.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        default=True,
        help="Pretty-print JSON output (default: True).",
    )
    args = parser.parse_args()

    result      = collect_artifacts()
    indent_val  = 2 if args.pretty else None
    json_output = json.dumps(result, indent=indent_val)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(json_output)
            print(f"[+] Output written to: {args.output}")
        except OSError as e:
            print(f"[-] Failed to write output file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(json_output)
