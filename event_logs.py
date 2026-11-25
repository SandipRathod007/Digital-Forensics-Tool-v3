# =============================================================================
# Digital Forensics & Incident Triage Tool v3.0
# Module: event_logs.py  —  Event Log Correlation & Threat Hunting
# =============================================================================
# Description:
#   Collects and correlates Windows Event Logs (System, Application, Security)
#   via wevtutil, or falls back to journalctl / syslog on Linux.
#   Performs forensic hunting for critical Event IDs associated with:
#     - Brute-force logon attempts (4625)
#     - Audit log tampering     (1102)
#     - Rogue service installs  (7045)
#     - Suspicious process creation / IoC strings (4688)
#
# Constraints:
#   - Zero external dependencies — Python 3.6+ stdlib only.
#   - Read-only: no system state is ever modified.
#   - All subprocess calls are non-shell with a 12-second timeout.
#   - Access-denied conditions are logged, never raised.
# =============================================================================

import datetime
import json
import platform
import subprocess
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODULE_NAME  = "Event Log Correlation & Threat Hunting"
VERSION      = "3.0"

# Windows Event Log channels to query
WINDOWS_CHANNELS = ["System", "Application", "Security"]

# Maximum events to retrieve per channel
MAX_EVENTS = 25

# Numeric level → human-readable mapping (Windows ETW levels)
LEVEL_MAP = {
    "0": "LogAlways",
    "1": "Critical",
    "2": "Error",
    "3": "Warning",
    "4": "Information",
    "5": "Verbose",
}

# Known Indicator-of-Compromise process name fragments (case-insensitive)
IOC_PROCESS_NAMES = ["mimikatz", "psexec", "nc.exe", "meterpreter", "cobalt"]

# XML namespace used by Windows Event Log schema
EVTNS = "http://schemas.microsoft.com/win/2004/08/events/event"


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _now_str() -> str:
    """Return current local datetime as a formatted string."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _fmt_time(raw: str) -> str:
    """
    Convert an ISO-8601 / Windows SystemTime attribute string to
    'YYYY-MM-DD HH:MM:SS'.  Returns the original string on parse failure.

    Windows stores times like: '2024-05-10T14:32:01.1234567Z'
    """
    if not raw:
        return ""
    # Strip trailing 'Z' and fractional seconds for uniform parsing
    cleaned = raw.rstrip("Z").split(".")[0]  # e.g. '2024-05-10T14:32:01'
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.datetime.strptime(cleaned, fmt).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            continue
    return raw  # fallback: return as-is


def _level_name(level_code: str) -> str:
    """Map a numeric ETW level string to its human-readable name."""
    return LEVEL_MAP.get(str(level_code).strip(), f"Unknown({level_code})")


def _ns(tag: str) -> str:
    """Prepend the Windows Event Log XML namespace to a tag name."""
    return f"{{{EVTNS}}}{tag}"


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------

def _parse_events_xml(raw_xml: str, channel: str) -> list:
    """
    Parse a block of raw XML returned by wevtutil (one or more <Event> nodes).

    Wraps the content in a synthetic <Events> root element so ElementTree
    can handle multi-event responses, then extracts the fields needed for
    forensic analysis.

    Parameters
    ----------
    raw_xml : str
        Raw XML string from wevtutil stdout.
    channel : str
        Logical channel name (e.g. 'System') — stamped onto every event dict.

    Returns
    -------
    list[dict]
        List of parsed event dictionaries.
    """
    if not raw_xml.strip():
        return []

    # Wrap in a container root so ET can parse multiple sibling <Event> nodes
    wrapped = f"<Events>{raw_xml}</Events>"

    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError as exc:
        # Partial / malformed XML — return empty rather than crashing
        return [
            {
                "parse_error": str(exc),
                "channel": channel,
                "raw_snippet": raw_xml[:200],
            }
        ]

    events = []
    for event_elem in root.findall(_ns("Event")):
        event_dict = _extract_event_fields(event_elem, channel)
        events.append(event_dict)

    return events


def _extract_event_fields(event_elem: ET.Element, channel: str) -> dict:
    """
    Extract forensically-relevant fields from a single <Event> XML element.

    Fields extracted:
      - event_id      : EventID text
      - level         : numeric level code
      - level_name    : human-readable level
      - provider      : Provider/@Name attribute
      - time_created  : TimeCreated/@SystemTime (formatted)
      - computer      : Computer text
      - channel       : caller-supplied channel label
      - event_data_summary : first 3 <Data> values from <EventData>

    Parameters
    ----------
    event_elem : xml.etree.ElementTree.Element
        A single <Event> element.
    channel : str
        Logical channel name stamped onto the returned dict.

    Returns
    -------
    dict
    """
    system_elem = event_elem.find(_ns("System"))

    # --- Event ID ---
    event_id = ""
    if system_elem is not None:
        eid_elem = system_elem.find(_ns("EventID"))
        if eid_elem is not None and eid_elem.text:
            event_id = eid_elem.text.strip()

    # --- Level (numeric code) ---
    level_code = ""
    if system_elem is not None:
        lvl_elem = system_elem.find(_ns("Level"))
        if lvl_elem is not None and lvl_elem.text:
            level_code = lvl_elem.text.strip()

    # --- Provider name ---
    provider = ""
    if system_elem is not None:
        prov_elem = system_elem.find(_ns("Provider"))
        if prov_elem is not None:
            provider = prov_elem.get("Name", "")

    # --- TimeCreated SystemTime ---
    time_created = ""
    if system_elem is not None:
        tc_elem = system_elem.find(_ns("TimeCreated"))
        if tc_elem is not None:
            raw_time = tc_elem.get("SystemTime", "")
            time_created = _fmt_time(raw_time)

    # --- Computer ---
    computer = ""
    if system_elem is not None:
        comp_elem = system_elem.find(_ns("Computer"))
        if comp_elem is not None and comp_elem.text:
            computer = comp_elem.text.strip()

    # --- EventData: first 3 <Data> children ---
    event_data_summary = []
    evt_data_elem = event_elem.find(_ns("EventData"))
    if evt_data_elem is not None:
        for data_child in evt_data_elem.findall(_ns("Data")):
            text_val = (data_child.text or "").strip()
            event_data_summary.append(text_val)
            if len(event_data_summary) >= 3:
                break

    return {
        "event_id":           event_id,
        "level":              level_code,
        "level_name":         _level_name(level_code),
        "provider":           provider,
        "time_created":       time_created,
        "computer":           computer,
        "channel":            channel,
        "event_data_summary": event_data_summary,
    }


# ---------------------------------------------------------------------------
# Windows Event Log collection
# ---------------------------------------------------------------------------

def _query_windows_channel(channel: str) -> dict:
    """
    Query a single Windows Event Log channel using wevtutil.

    Command:
        wevtutil qe <channel> /c:25 /rd:true /f:xml

    Returns a dict with:
        {
            "event_count": int,
            "events":      list[dict],
            # Only present for Security channel on access-denied:
            "access_note": str   (optional)
        }
    and may also return side-channel info about access failure via the
    'access_denied' boolean key (stripped before final output).

    Parameters
    ----------
    channel : str
        Windows Event Log channel name (e.g. 'System', 'Security').

    Returns
    -------
    dict
    """
    result = {
        "event_count":   0,
        "events":        [],
        "access_denied": False,  # internal flag; removed before final return
    }

    cmd = [
        "wevtutil",
        "qe",
        channel,
        f"/c:{MAX_EVENTS}",
        "/rd:true",
        "/f:xml",
    ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            shell=False,
            timeout=12,
        )
    except FileNotFoundError:
        # wevtutil not present (e.g. running on Wine or non-Windows)
        result["access_denied"] = True
        result["access_note"]   = "wevtutil not found — not a supported Windows environment"
        return result
    except subprocess.TimeoutExpired:
        result["access_note"] = f"wevtutil query for '{channel}' timed out after 12 s"
        return result
    except OSError as exc:
        result["access_note"] = f"OS error querying '{channel}': {exc}"
        return result

    # Detect access-denied conditions for the Security channel (or any channel)
    stderr_lower = proc.stderr.lower() if proc.stderr else ""
    access_denied_signals = [
        "access denied",
        "0x5",
        "5): the access",
        "access is denied",
    ]
    if proc.returncode != 0 or any(sig in stderr_lower for sig in access_denied_signals):
        result["access_denied"] = True
        result["access_note"] = (
            "Security Event Log access denied (requires Administrator privilege)"
        )
        return result

    # Parse successful XML output
    raw_xml = proc.stdout or ""
    events  = _parse_events_xml(raw_xml, channel)
    result["event_count"] = len(events)
    result["events"]      = events
    return result


def _collect_windows() -> dict:
    """
    Collect events from all three Windows channels and perform forensic hunting.

    Returns
    -------
    dict  — the full artifact payload (without top-level metadata fields)
    """
    access_limitations = []
    channels_data      = {}
    all_events         = []  # flat list of all successfully parsed events

    for channel in WINDOWS_CHANNELS:
        channel_result = _query_windows_channel(channel)

        # Pull out internal flag before storing
        access_denied = channel_result.pop("access_denied", False)

        if access_denied:
            limitation_msg = channel_result.get(
                "access_note",
                f"Access denied or error reading '{channel}' channel",
            )
            # Only add to limitations if not already recorded
            if limitation_msg not in access_limitations:
                access_limitations.append(limitation_msg)

        # Accumulate valid events for forensic hunting
        for evt in channel_result.get("events", []):
            if "parse_error" not in evt:
                all_events.append(evt)

        channels_data[channel] = channel_result

    # Forensic hunting across all collected events
    forensic_hits, indicators = _hunt_forensic_events(all_events)

    # Determine overall status
    status = "limited_access" if access_limitations else "success"

    return {
        "access_limitations":    access_limitations,
        "suspicious_indicators": indicators,
        "artifacts": {
            "channels":      channels_data,
            "forensic_hits": forensic_hits,
        },
        "status": status,
    }


# ---------------------------------------------------------------------------
# Forensic Event ID Hunting
# ---------------------------------------------------------------------------

def _hunt_forensic_events(all_events: list) -> tuple:
    """
    Scan the flat list of collected events for forensically significant
    Event IDs and known Indicators of Compromise.

    Targeted Event IDs
    ------------------
    4625 — Failed Logon (potential brute force)
    1102 — Security Audit Log Cleared (evidence tampering)
    7045 — New Service Installed (persistence mechanism)
    4688 — Process Creation (IoC process name matching)

    Parameters
    ----------
    all_events : list[dict]
        Flat list of all parsed event dicts from every channel.

    Returns
    -------
    tuple (forensic_hits: dict, indicators: list[dict])
    """
    forensic_hits = {
        "failed_logons_4625":         [],
        "audit_log_cleared_1102":     [],
        "new_service_installed_7045":  [],
        "process_creation_4688":      [],
    }
    indicators = []
    current_ts = _now_str()

    for evt in all_events:
        eid = str(evt.get("event_id", "")).strip()

        # ------------------------------------------------------------------
        # 4625 — Failed Logon
        # ------------------------------------------------------------------
        if eid == "4625":
            hit = {
                "event_id":           evt.get("event_id"),
                "time_created":       evt.get("time_created"),
                "computer":           evt.get("computer"),
                "event_data_summary": evt.get("event_data_summary", []),
            }
            forensic_hits["failed_logons_4625"].append(hit)

        # ------------------------------------------------------------------
        # 1102 — Audit Log Cleared
        # ------------------------------------------------------------------
        elif eid == "1102":
            hit = {
                "event_id":           evt.get("event_id"),
                "time_created":       evt.get("time_created"),
                "computer":           evt.get("computer"),
                "event_data_summary": evt.get("event_data_summary", []),
            }
            forensic_hits["audit_log_cleared_1102"].append(hit)
            indicators.append({
                "severity":  "HIGH_RISK",
                "indicator": "Security Audit Log Cleared - Potential Evidence Tampering",
                "details":   (
                    f"Event 1102 detected on '{evt.get('computer', 'unknown')}' "
                    f"at {evt.get('time_created', 'unknown time')}. "
                    "Log clearing is a classic anti-forensic technique."
                ),
                "timestamp": current_ts,
            })

        # ------------------------------------------------------------------
        # 7045 — New Service Installed
        # ------------------------------------------------------------------
        elif eid == "7045":
            # First Data element is typically the service name
            data_summary = evt.get("event_data_summary", [])
            service_name = data_summary[0] if data_summary else "unknown"
            hit = {
                "event_id":           evt.get("event_id"),
                "time_created":       evt.get("time_created"),
                "computer":           evt.get("computer"),
                "event_data_summary": data_summary,
            }
            forensic_hits["new_service_installed_7045"].append(hit)
            indicators.append({
                "severity":  "SUSPICIOUS",
                "indicator": "New Service Installation Detected",
                "details":   (
                    f"Service '{service_name}' was installed on "
                    f"'{evt.get('computer', 'unknown')}' at "
                    f"{evt.get('time_created', 'unknown time')}. "
                    "Review the service binary path for legitimacy."
                ),
                "timestamp": current_ts,
            })

        # ------------------------------------------------------------------
        # 4688 — Process Creation
        # ------------------------------------------------------------------
        elif eid == "4688":
            data_summary = evt.get("event_data_summary", [])
            hit = {
                "event_id":           evt.get("event_id"),
                "time_created":       evt.get("time_created"),
                "computer":           evt.get("computer"),
                "event_data_summary": data_summary,
            }
            forensic_hits["process_creation_4688"].append(hit)

            # Check for IoC process name fragments (case-insensitive)
            combined_data = " ".join(str(d) for d in data_summary).lower()
            matched_iocs  = [
                ioc for ioc in IOC_PROCESS_NAMES if ioc.lower() in combined_data
            ]
            if matched_iocs:
                indicators.append({
                    "severity":  "HIGH_RISK",
                    "indicator": "Known Malicious / Dual-Use Tool Detected in Process Creation",
                    "details":   (
                        f"Event 4688 on '{evt.get('computer', 'unknown')}' at "
                        f"{evt.get('time_created', 'unknown time')} matched IoC "
                        f"string(s): {', '.join(matched_iocs)}. "
                        f"Event data: {data_summary}"
                    ),
                    "timestamp": current_ts,
                })

    # ------------------------------------------------------------------
    # Post-collection: evaluate 4625 brute-force threshold
    # ------------------------------------------------------------------
    failed_logon_count = len(forensic_hits["failed_logons_4625"])
    if failed_logon_count >= 5:
        indicators.insert(0, {
            "severity":  "HIGH_RISK",
            "indicator": "Potential Brute Force / Multiple Failed Logons Detected",
            "details":   (
                f"{failed_logon_count} failed logon event(s) (ID 4625) collected "
                f"within the queried window. Threshold: 5+. "
                "Investigate source IP / account names in event_data_summary."
            ),
            "timestamp": current_ts,
        })
    elif failed_logon_count > 0:
        # Still informational even if below brute-force threshold
        indicators.append({
            "severity":  "INFO",
            "indicator": "Failed Logon Event(s) Observed",
            "details":   (
                f"{failed_logon_count} failed logon event(s) (ID 4625) in the "
                "queried window. Below brute-force threshold (5) but worth reviewing."
            ),
            "timestamp": current_ts,
        })

    return forensic_hits, indicators


# ---------------------------------------------------------------------------
# Linux Fallback
# ---------------------------------------------------------------------------

def _collect_linux() -> dict:
    """
    Fallback collection path for non-Windows systems.

    Attempts, in order:
      1. journalctl -n 25 --no-pager -o json  (systemd environments)
      2. tail -n 50 /var/log/syslog           (traditional syslog)

    Forensic Event ID hunting is not available on Linux (wevtutil-specific).

    Returns
    -------
    dict  — artifact payload matching the same schema as _collect_windows()
    """
    access_limitations = [
        "Windows wevtutil not available on Linux, using journalctl fallback"
    ]
    raw_journal_lines = []
    syslog_lines      = []
    collection_errors = []

    # --- Attempt 1: journalctl ---
    journal_ok = False
    try:
        proc = subprocess.run(
            ["journalctl", "-n", "25", "--no-pager", "-o", "json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            shell=False,
            timeout=12,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            # journalctl -o json emits one JSON object per line
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line:
                    raw_journal_lines.append(line)
            journal_ok = True
        else:
            collection_errors.append(
                f"journalctl returned code {proc.returncode}: "
                + (proc.stderr.strip() or "no output")
            )
    except FileNotFoundError:
        collection_errors.append("journalctl not found on this system")
    except subprocess.TimeoutExpired:
        collection_errors.append("journalctl timed out after 12 s")
    except OSError as exc:
        collection_errors.append(f"OS error running journalctl: {exc}")

    # --- Attempt 2: syslog tail (only if journalctl yielded nothing) ---
    if not journal_ok:
        try:
            proc = subprocess.run(
                ["tail", "-n", "50", "/var/log/syslog"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                shell=False,
                timeout=12,
            )
            if proc.returncode == 0:
                syslog_lines = [
                    ln for ln in proc.stdout.splitlines() if ln.strip()
                ]
            else:
                collection_errors.append(
                    "/var/log/syslog read error: " + proc.stderr.strip()
                )
        except FileNotFoundError:
            collection_errors.append("tail command not found")
        except subprocess.TimeoutExpired:
            collection_errors.append("syslog tail timed out after 12 s")
        except OSError as exc:
            collection_errors.append(f"OS error reading syslog: {exc}")

    # Merge collection errors into access_limitations
    access_limitations.extend(collection_errors)

    # Build channel-like structure so schema is consistent
    linux_channel_data = {
        "journal": {
            "event_count": len(raw_journal_lines),
            "events":      raw_journal_lines,
        },
        "syslog": {
            "event_count": len(syslog_lines),
            "events":      syslog_lines,
        },
    }

    # Empty forensic_hits on Linux — wevtutil Event IDs don't apply
    forensic_hits = {
        "failed_logons_4625":         [],
        "audit_log_cleared_1102":     [],
        "new_service_installed_7045":  [],
        "process_creation_4688":      [],
    }

    indicators = []
    if access_limitations:
        indicators.append({
            "severity":  "INFO",
            "indicator": "Linux / Non-Windows Host — Windows Event ID hunting skipped",
            "details":   (
                "This module's forensic Event ID rules (4625, 1102, 7045, 4688) "
                "are Windows-specific. Manual review of journalctl / syslog output "
                "is recommended for Linux incident triage."
            ),
            "timestamp": _now_str(),
        })

    return {
        "access_limitations":    access_limitations,
        "suspicious_indicators": indicators,
        "artifacts": {
            "channels":      linux_channel_data,
            "forensic_hits": forensic_hits,
        },
        "status": "limited_access",
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def collect_artifacts() -> dict:
    """
    Entry point for the Event Log Correlation & Threat Hunting module.

    Dispatches to the Windows (wevtutil) or Linux (journalctl/syslog)
    collection path based on the current platform, then assembles and
    returns a standardised forensic artifact dictionary.

    Returns
    -------
    dict
        {
            "module_name": str,
            "version": str,
            "status": "success" | "limited_access",
            "collection_time": "YYYY-MM-DD HH:MM:SS",
            "access_limitations": [str],
            "suspicious_indicators": [
                {
                    "severity": "HIGH_RISK" | "SUSPICIOUS" | "INFO",
                    "indicator": str,
                    "details": str,
                    "timestamp": str
                }
            ],
            "artifacts": {
                "channels": {
                    "System":      {"event_count": int, "events": [...]},
                    "Application": {"event_count": int, "events": [...]},
                    "Security":    {"event_count": int, "events": [...],
                                   "access_note": str}   # if denied
                },
                "forensic_hits": {
                    "failed_logons_4625":         [...],
                    "audit_log_cleared_1102":     [...],
                    "new_service_installed_7045":  [...],
                    "process_creation_4688":      [...]
                }
            }
        }
    """
    collection_time = _now_str()

    try:
        os_name = platform.system()
        if os_name == "Windows":
            payload = _collect_windows()
        else:
            payload = _collect_linux()
    except Exception as exc:  # pylint: disable=broad-except
        # Last-resort safety net — module must never crash the parent tool
        payload = {
            "access_limitations":    [f"Unexpected collection error: {exc}"],
            "suspicious_indicators": [],
            "artifacts": {
                "channels":      {},
                "forensic_hits": {
                    "failed_logons_4625":         [],
                    "audit_log_cleared_1102":     [],
                    "new_service_installed_7045":  [],
                    "process_creation_4688":      [],
                },
            },
            "status": "limited_access",
        }

    # Assemble the final top-level document
    artifact_doc = {
        "module_name":           MODULE_NAME,
        "version":               VERSION,
        "status":                payload.get("status", "limited_access"),
        "collection_time":       collection_time,
        "access_limitations":    payload.get("access_limitations", []),
        "suspicious_indicators": payload.get("suspicious_indicators", []),
        "artifacts":             payload.get("artifacts", {}),
    }

    return artifact_doc


# ---------------------------------------------------------------------------
# CLI self-test  (python event_logs.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    result = collect_artifacts()
    print(json.dumps(result, indent=2, default=str))
