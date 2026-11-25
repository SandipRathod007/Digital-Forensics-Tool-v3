"""
=============================================================================
Digital Forensics & Incident Triage Tool v3.0
Module: os_info.py  —  OS, Hardware & Network Security Posture
=============================================================================
Author      : Principal Security Engineer
Version     : 3.0
Python      : 3.6+
Dependencies: ZERO external — stdlib only
              os, sys, platform, subprocess, datetime, json,
              socket, getpass, ctypes, winreg (Windows only, try-import)

Purpose     : Collect a comprehensive, read-only forensic snapshot of the
              host OS, hardware configuration, network posture, and security
              state.  Returns a single normalised dict suitable for JSON
              serialisation or downstream report generation.

IMPORTANT   : This module is STRICTLY READ-ONLY.  It never modifies registry
              keys, files, network settings, or any other system state.
=============================================================================
"""

import os
import sys
import platform
import subprocess
import datetime
import json
import socket
import getpass
import ctypes
import re

# ---------------------------------------------------------------------------
# Optional Windows-only import
# ---------------------------------------------------------------------------
try:
    import winreg
    _WINREG_AVAILABLE = True
except ImportError:
    _WINREG_AVAILABLE = False

# ---------------------------------------------------------------------------
# Platform detection (evaluated once at import time)
# ---------------------------------------------------------------------------
_IS_WINDOWS = sys.platform.startswith("win")
_IS_LINUX   = sys.platform.startswith("linux")
_IS_DARWIN  = sys.platform.startswith("darwin")


# ===========================================================================
# INTERNAL HELPERS
# ===========================================================================

def _now_str() -> str:
    """Return current local datetime as a human-readable string."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _run(args: list, timeout: int = 12) -> str:
    """
    Execute *args* as a subprocess (no shell) and return stdout as a string.
    stderr is silently discarded.  Returns an empty string on any error.

    Parameters
    ----------
    args    : list of str — command + arguments (shell=False)
    timeout : int — seconds before the process is killed (default 12)
    """
    try:
        result = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            shell=False,
            timeout=timeout,
        )
        return result.stdout or ""
    except FileNotFoundError:
        # Binary not present on this system
        return ""
    except subprocess.TimeoutExpired:
        return ""
    except PermissionError:
        return ""
    except Exception:
        return ""


def _make_indicator(severity: str, indicator: str, details: str) -> dict:
    """
    Build a normalised suspicious_indicator entry.

    Parameters
    ----------
    severity  : "HIGH_RISK" | "SUSPICIOUS" | "INFO"
    indicator : short label string
    details   : human-readable explanation
    """
    return {
        "severity":  severity,
        "indicator": indicator,
        "details":   details,
        "timestamp": _now_str(),
    }


# ===========================================================================
# SECTION 1 — OS DETAILS
# ===========================================================================

def _collect_os_details(access_limitations: list) -> dict:
    """
    Collect operating-system identification data.

    Includes uptime_hours computed from the boot_time string extracted by
    _collect_system_config() — this function stores the raw boot_time for
    later use; uptime_hours is patched in by collect_artifacts() after
    system_config is built.
    """
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "UNKNOWN"

    try:
        current_user = getpass.getuser()
    except Exception:
        current_user = os.environ.get("USERNAME", os.environ.get("USER", "UNKNOWN"))

    # architecture_details: 32-bit / 64-bit process information
    bits, linkage = platform.architecture()
    arch_details = "{} {} {}".format(bits, linkage, platform.machine()).strip()

    return {
        "os_name":            platform.system(),
        "os_version":         platform.version(),
        "os_release":         platform.release(),
        "architecture":       platform.machine(),
        "architecture_details": arch_details,
        "platform_string":    platform.platform(),
        "hostname":           hostname,
        "current_user":       current_user,
        "python_version":     sys.version,
        "uptime_hours":       "N/A",   # patched later
    }


# ===========================================================================
# SECTION 2 — SYSTEM CONFIGURATION
# ===========================================================================

def _parse_systeminfo(raw: str) -> dict:
    """
    Parse the multi-line output of `systeminfo` into a flat key-value dict.
    Keys are normalised (stripped, lowercased, spaces → underscores).
    Values are plain strings.
    """
    result: dict = {}
    for line in raw.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            key   = key.strip().lower().replace(" ", "_")
            value = value.strip()
            if key and value:
                result[key] = value
    return result


def _collect_system_config_windows(access_limitations: list) -> dict:
    """
    Windows-specific system configuration harvesting via `systeminfo`.
    Returns a flat dict of string values.
    """
    raw = _run(["systeminfo"])
    if not raw:
        access_limitations.append("systeminfo command unavailable or access denied")
        return {
            "boot_time":               "N/A",
            "total_physical_memory":   "N/A",
            "available_physical_memory": "N/A",
            "os_build_type":           "N/A",
            "system_manufacturer":     "N/A",
            "system_model":            "N/A",
            "system_type":             "N/A",
            "bios_version":            "N/A",
            "domain":                  "N/A",
            "logon_server":            "N/A",
            "time_zone":               "N/A",
        }

    parsed = _parse_systeminfo(raw)

    def _get(*keys) -> str:
        """Try multiple possible key names; return first match."""
        for k in keys:
            v = parsed.get(k)
            if v:
                return v
        return "N/A"

    return {
        "boot_time":               _get("system_boot_time"),
        "total_physical_memory":   _get("total_physical_memory"),
        "available_physical_memory": _get("available_physical_memory"),
        "os_build_type":           _get("os_build_type"),
        "system_manufacturer":     _get("system_manufacturer"),
        "system_model":            _get("system_model"),
        "system_type":             _get("system_type"),
        "bios_version":            _get("bios_version"),
        "domain":                  _get("domain"),
        "logon_server":            _get("logon_server"),
        "time_zone":               _get("time_zone"),
    }


def _collect_system_config_linux(access_limitations: list) -> dict:
    """
    Linux/macOS system configuration via `uname -a` and `uptime`.
    Returns a flat dict of string values.
    """
    uname_raw  = _run(["uname", "-a"])
    uptime_raw = _run(["uptime"])

    # Try to get more details from /proc/meminfo on Linux
    total_mem = "N/A"
    avail_mem = "N/A"
    if _IS_LINUX:
        try:
            with open("/proc/meminfo", "r") as fh:
                for mline in fh:
                    if mline.startswith("MemTotal:"):
                        total_mem = mline.split(":", 1)[1].strip()
                    elif mline.startswith("MemAvailable:"):
                        avail_mem = mline.split(":", 1)[1].strip()
        except Exception:
            pass

    return {
        "boot_time":                 uptime_raw.strip() if uptime_raw else "N/A",
        "total_physical_memory":     total_mem,
        "available_physical_memory": avail_mem,
        "os_build_type":             uname_raw.strip() if uname_raw else "N/A",
        "system_manufacturer":       "N/A",
        "system_model":              "N/A",
        "system_type":               platform.machine(),
        "bios_version":              "N/A",
        "domain":                    "N/A",
        "logon_server":              "N/A",
        "time_zone":                 _run(["date", "+%Z"]).strip() or "N/A",
    }


def _collect_system_config(access_limitations: list) -> dict:
    """Entry-point: delegate to OS-specific system_config collector."""
    if _IS_WINDOWS:
        return _collect_system_config_windows(access_limitations)
    return _collect_system_config_linux(access_limitations)


def _compute_uptime_hours(boot_time_str: str) -> str:
    """
    Given a boot_time string (e.g. '11/04/2026, 08:30:00 AM') attempt to
    parse it and compute elapsed hours since boot.
    Returns a formatted string like "12.5 hours" or "N/A" on failure.
    """
    if not boot_time_str or boot_time_str == "N/A":
        return "N/A"

    # Windows systeminfo formats: "11/4/2026, 8:30:00 AM" or locale variants
    formats = [
        "%m/%d/%Y, %I:%M:%S %p",
        "%m/%d/%Y, %H:%M:%S",
        "%d/%m/%Y, %H:%M:%S",
        "%d-%m/%Y, %H:%M:%S",
        "%d-%m-%Y, %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ]
    for fmt in formats:
        try:
            boot_dt   = datetime.datetime.strptime(boot_time_str.strip(), fmt)
            now_dt    = datetime.datetime.now()
            delta_hrs = (now_dt - boot_dt).total_seconds() / 3600.0
            return "{:.2f} hours".format(delta_hrs)
        except ValueError:
            continue
    return "N/A"


# ===========================================================================
# SECTION 3 — NETWORK CONFIGURATION
# ===========================================================================

def _socket_primary_ip() -> str:
    """
    Determine the primary outbound IP by connecting a UDP socket to a
    well-known external address (no data is actually sent).
    Returns "N/A" on failure.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "N/A"


def _resolve_ips(hostname: str) -> list:
    """
    Resolve all IP addresses associated with *hostname*.
    Returns a list of address strings.
    """
    try:
        info = socket.getaddrinfo(hostname, None)
        # Each entry: (family, type, proto, canonname, sockaddr)
        seen = set()
        result = []
        for entry in info:
            addr = entry[4][0]
            if addr not in seen:
                seen.add(addr)
                result.append(addr)
        return result
    except Exception:
        return []


def _parse_ipconfig_all(raw: str) -> tuple:
    """
    Parse `ipconfig /all` output into:
      - a list of adapter dicts (flat key-value, no nested objects)
      - an ipconfig_summary dict

    Returns (adapters: list, summary: dict)
    """
    adapters: list = []
    all_ipv4:  list = []
    all_ipv6:  list = []
    gateways:  list = []

    if not raw:
        return adapters, {"all_ipv4_addresses": all_ipv4,
                          "all_ipv6_addresses": all_ipv6,
                          "default_gateways":   gateways}

    current: dict = {}
    adapter_name = ""

    # ipconfig /all header lines start at column 0 and end with ":"
    adapter_header_re = re.compile(r"^[A-Za-z].*:$")

    for line in raw.splitlines():
        # Detect adapter block headers (non-indented lines ending with ":")
        if adapter_header_re.match(line.strip()) and not line.startswith(" "):
            # Save the previous adapter if it had content
            if current.get("adapter_name"):
                adapters.append(current)
            adapter_name = line.strip().rstrip(":")
            current = {
                "adapter_name": adapter_name,
                "ipv4":         "N/A",
                "ipv6":         "N/A",
                "mac":          "N/A",
                "dhcp_enabled": "N/A",
                "gateway":      "N/A",
            }
            continue

        # Parse indented key-value lines inside an adapter block
        if current and ":" in line:
            stripped = line.strip()
            key, _, value = stripped.partition(":")
            key   = key.strip().lower()
            value = value.strip()

            if "ipv4" in key and "address" in key:
                # Strip "(Preferred)" annotation
                clean_ip = value.replace("(Preferred)", "").replace("(Duplicate)", "").strip()
                if clean_ip:
                    current["ipv4"] = clean_ip
                    if clean_ip not in all_ipv4:
                        all_ipv4.append(clean_ip)

            elif "ipv6" in key and "address" in key:
                clean_ip6 = value.replace("(Preferred)", "").strip()
                if clean_ip6:
                    current["ipv6"] = clean_ip6
                    if clean_ip6 not in all_ipv6:
                        all_ipv6.append(clean_ip6)

            elif "physical address" in key or "mac" in key:
                if value and value != "N/A":
                    current["mac"] = value

            elif "dhcp enabled" in key:
                current["dhcp_enabled"] = value

            elif "default gateway" in key:
                if value:
                    current["gateway"] = value
                    if value not in gateways:
                        gateways.append(value)

    # Flush the last adapter
    if current.get("adapter_name"):
        adapters.append(current)

    summary = {
        "all_ipv4_addresses": all_ipv4,
        "all_ipv6_addresses": all_ipv6,
        "default_gateways":   gateways,
    }
    return adapters, summary


def _parse_ip_addr(raw: str) -> tuple:
    """
    Parse `ip addr show` output (Linux) into adapter list and summary.
    Returns (adapters: list, summary: dict)
    """
    adapters: list = []
    all_ipv4:  list = []
    all_ipv6:  list = []
    gateways:  list = []

    if not raw:
        return adapters, {"all_ipv4_addresses": all_ipv4,
                          "all_ipv6_addresses": all_ipv6,
                          "default_gateways":   gateways}

    current: dict = {}
    iface_re = re.compile(r"^\d+:\s+(\S+):")
    mac_re   = re.compile(r"link/ether\s+([\da-fA-F:]+)")
    ipv4_re  = re.compile(r"inet\s+([\d.]+)/")
    ipv6_re  = re.compile(r"inet6\s+([\da-fA-F:]+)/")

    for line in raw.splitlines():
        m = iface_re.match(line)
        if m:
            if current.get("adapter_name"):
                adapters.append(current)
            current = {
                "adapter_name": m.group(1),
                "ipv4":         "N/A",
                "ipv6":         "N/A",
                "mac":          "N/A",
                "dhcp_enabled": "N/A",
                "gateway":      "N/A",
            }
            continue

        if current:
            m = mac_re.search(line)
            if m:
                current["mac"] = m.group(1)

            m = ipv4_re.search(line)
            if m:
                ip = m.group(1)
                current["ipv4"] = ip
                if ip not in all_ipv4:
                    all_ipv4.append(ip)

            m = ipv6_re.search(line)
            if m:
                ip6 = m.group(1)
                current["ipv6"] = ip6
                if ip6 not in all_ipv6:
                    all_ipv6.append(ip6)

    if current.get("adapter_name"):
        adapters.append(current)

    # Linux gateway via `ip route`
    route_raw = _run(["ip", "route", "show", "default"])
    for rline in route_raw.splitlines():
        gw_match = re.search(r"default via ([\d.]+)", rline)
        if gw_match:
            gw = gw_match.group(1)
            if gw not in gateways:
                gateways.append(gw)

    summary = {
        "all_ipv4_addresses": all_ipv4,
        "all_ipv6_addresses": all_ipv6,
        "default_gateways":   gateways,
    }
    return adapters, summary


def _collect_tcp_connections() -> list:
    """
    Run netstat (Windows) or ss (Linux) and return the top 15 connection
    lines as plain strings.  Header lines are excluded.
    """
    if _IS_WINDOWS:
        raw = _run(["netstat", "-ano"], timeout=12)
    else:
        raw = _run(["ss", "-tnp"], timeout=12)

    if not raw:
        return []

    lines = []
    for line in raw.splitlines():
        stripped = line.strip()
        # Skip blank lines and typical header lines
        if not stripped:
            continue
        lower = stripped.lower()
        if lower.startswith("active") or lower.startswith("proto") \
                or lower.startswith("netid") or lower.startswith("state\t"):
            continue
        lines.append(stripped)
        if len(lines) >= 15:
            break
    return lines


def _collect_network_config(access_limitations: list) -> dict:
    """
    Assemble the complete network_config section.
    """
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "UNKNOWN"

    try:
        fqdn = socket.getfqdn()
    except Exception:
        fqdn = hostname

    primary_ip   = _socket_primary_ip()
    resolved_ips = _resolve_ips(hostname)

    # Parse interface details
    if _IS_WINDOWS:
        ipconfig_raw           = _run(["ipconfig", "/all"])
        active_interfaces, summary = _parse_ipconfig_all(ipconfig_raw)
    else:
        ip_raw                 = _run(["ip", "addr", "show"])
        active_interfaces, summary = _parse_ip_addr(ip_raw)

    tcp_connections = _collect_tcp_connections()

    return {
        "hostname":               hostname,
        "fqdn":                   fqdn,
        "primary_ip":             primary_ip,
        "resolved_ips":           resolved_ips,
        "active_interfaces":      active_interfaces,
        "active_tcp_connections": tcp_connections,
        "ipconfig_summary":       summary,
    }


# ===========================================================================
# SECTION 4 — SECURITY POSTURE
# ===========================================================================

def _check_is_admin() -> bool:
    """
    Return True if the current process has administrative / root privileges.
    """
    if _IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        # POSIX: uid == 0 means root
        try:
            return os.getuid() == 0
        except AttributeError:
            return False


def _collect_firewall_windows(suspicious_indicators: list, access_limitations: list) -> dict:
    """
    Parse `netsh advfirewall show allprofiles` output on Windows.
    Returns {"domain": str, "private": str, "public": str}.
    Adds HIGH_RISK indicators for any profile that is OFF.
    """
    raw = _run(["netsh", "advfirewall", "show", "allprofiles"])
    profiles = {"domain": "UNKNOWN", "private": "UNKNOWN", "public": "UNKNOWN"}

    if not raw:
        access_limitations.append("netsh advfirewall command unavailable")
        return profiles

    # State appears after each profile header:
    #   Domain Profile Settings:
    #     State                                 ON
    current_profile = None
    profile_map = {
        "domain profile":  "domain",
        "private profile": "private",
        "public profile":  "public",
    }

    for line in raw.splitlines():
        lower = line.strip().lower()

        # Detect profile header
        for header, key in profile_map.items():
            if header in lower:
                current_profile = key
                break

        # Detect State line within a profile block
        if current_profile and re.match(r"^state\s+", lower):
            state_value = line.strip().split()[-1].upper()   # ON or OFF
            profiles[current_profile] = state_value
            if state_value == "OFF":
                suspicious_indicators.append(
                    _make_indicator(
                        "HIGH_RISK",
                        "Windows Firewall Disabled on {} profile".format(
                            current_profile.title()
                        ),
                        "Windows Firewall {} Profile State is OFF. "
                        "Host may be unprotected from inbound threats.".format(
                            current_profile.title()
                        ),
                    )
                )

    return profiles


def _collect_firewall_linux(suspicious_indicators: list, access_limitations: list) -> dict:
    """
    Attempt to retrieve firewall state on Linux via `ufw status`,
    falling back to `iptables -L` for a basic presence check.
    """
    ufw_raw = _run(["ufw", "status"])
    if ufw_raw:
        status_line = ufw_raw.splitlines()[0].strip().lower() if ufw_raw.splitlines() else ""
        state = "active" if "active" in status_line else "inactive"
        if state == "inactive":
            suspicious_indicators.append(
                _make_indicator(
                    "HIGH_RISK",
                    "UFW Firewall Inactive",
                    "ufw status reports firewall is inactive. Host may be unprotected.",
                )
            )
        return {"domain": "N/A", "private": "N/A", "public": "ufw:{}".format(state)}

    # Fallback: iptables presence check
    ipt_raw = _run(["iptables", "-L", "-n", "--line-numbers"])
    if ipt_raw:
        return {"domain": "N/A", "private": "N/A", "public": "iptables:present"}

    access_limitations.append("No firewall query tool available (ufw/iptables)")
    return {"domain": "N/A", "private": "N/A", "public": "UNKNOWN"}


def _collect_defender_status(suspicious_indicators: list, access_limitations: list) -> str:
    """
    Query Windows Defender via PowerShell Get-MpComputerStatus.
    Returns a human-readable status string.
    Adds HIGH_RISK indicator if Defender or Real-Time Protection is disabled.
    """
    if not _IS_WINDOWS:
        return "N/A (Linux/macOS)"

    ps_cmd = (
        "Get-MpComputerStatus | "
        "Select-Object -Property AntivirusEnabled,RealTimeProtectionEnabled | "
        "ConvertTo-Json"
    )
    raw = _run(
        ["powershell", "-NonInteractive", "-Command", ps_cmd],
        timeout=12,
    )

    if not raw or not raw.strip():
        access_limitations.append(
            "PowerShell Get-MpComputerStatus unavailable"
        )
        return "Query failed — access denied or Windows Defender service not running"

    try:
        data = json.loads(raw.strip())
        av_enabled  = data.get("AntivirusEnabled",           None)
        rtp_enabled = data.get("RealTimeProtectionEnabled",  None)

        # Build human-readable status
        av_str  = "Enabled" if av_enabled  else "DISABLED"
        rtp_str = "Enabled" if rtp_enabled else "DISABLED"
        status_str = "AntivirusEnabled={}, RealTimeProtectionEnabled={}".format(
            av_str, rtp_str
        )

        if av_enabled is False or rtp_enabled is False:
            suspicious_indicators.append(
                _make_indicator(
                    "HIGH_RISK",
                    "Antivirus/Real-Time Protection Disabled",
                    "Windows Defender reports: {}. Host is at elevated risk of "
                    "malware infection.".format(status_str),
                )
            )

        return status_str

    except (json.JSONDecodeError, KeyError, TypeError):
        # Non-JSON response (e.g. error message from PS)
        access_limitations.append(
            "Could not parse Windows Defender JSON response"
        )
        return "Parse error — raw output: {}".format(raw.strip()[:200])


def _collect_usb_history_windows(suspicious_indicators: list, access_limitations: list) -> list:
    """
    Enumerate HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR subkeys (read-only)
    to identify USB storage devices that have been connected to this host.
    Returns a list of device descriptor strings (up to 20).
    """
    devices: list = []

    if not _WINREG_AVAILABLE:
        access_limitations.append("winreg module not available on this platform")
        return devices

    usbstor_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    try:
        hive = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            usbstor_path,
            0,
            winreg.KEY_READ,
        )
    except OSError as exc:
        # Expected if the key doesn't exist or access is denied
        access_limitations.append(
            "USBSTOR registry key inaccessible: {}".format(str(exc))
        )
        return devices
    except Exception as exc:
        access_limitations.append(
            "Unexpected error reading USBSTOR registry: {}".format(str(exc))
        )
        return devices

    try:
        # Level-1: device type subkeys (e.g. "Disk&Ven_SanDisk&Prod_...&Rev_...")
        idx = 0
        while len(devices) < 20:
            try:
                device_type_name = winreg.EnumKey(hive, idx)
                idx += 1

                # Level-2: individual device instances
                try:
                    device_key = winreg.OpenKey(
                        hive, device_type_name, 0, winreg.KEY_READ
                    )
                    sub_idx = 0
                    while len(devices) < 20:
                        try:
                            instance_name = winreg.EnumKey(device_key, sub_idx)
                            sub_idx += 1
                            # Build a descriptive label
                            label = "{} :: {}".format(device_type_name, instance_name)
                            devices.append(label)
                        except OSError:
                            break
                    winreg.CloseKey(device_key)
                except OSError:
                    # Can't open the sub-key; still record the type name
                    devices.append(device_type_name)

            except OSError:
                # No more subkeys
                break
    finally:
        winreg.CloseKey(hive)

    if devices:
        suspicious_indicators.append(
            _make_indicator(
                "INFO",
                "USB Storage Devices Detected in Registry",
                "{} USB storage device(s) found in USBSTOR registry hive. "
                "Review for unauthorised removable media usage.".format(len(devices)),
            )
        )

    return devices


def _collect_usb_history_linux(suspicious_indicators: list, access_limitations: list) -> list:
    """
    Attempt to find USB storage references in /var/log/syslog on Linux.
    Returns up to 20 matching log lines.
    """
    devices: list = []
    syslog_path = "/var/log/syslog"

    if not os.path.isfile(syslog_path):
        access_limitations.append("/var/log/syslog not found (may need root)")
        return devices

    try:
        with open(syslog_path, "r", errors="replace") as fh:
            for line in fh:
                lower_line = line.lower()
                if "usb" in lower_line and (
                    "storage" in lower_line
                    or "mass storage" in lower_line
                    or "uas" in lower_line
                    or "sd" in lower_line
                ):
                    devices.append(line.strip())
                    if len(devices) >= 20:
                        break
    except PermissionError:
        access_limitations.append("/var/log/syslog read access denied")
    except Exception as exc:
        access_limitations.append("syslog read error: {}".format(str(exc)))

    if devices:
        suspicious_indicators.append(
            _make_indicator(
                "INFO",
                "USB Storage Devices Detected in syslog",
                "{} USB storage reference(s) found in /var/log/syslog.".format(
                    len(devices)
                ),
            )
        )

    return devices


def _collect_security_posture(suspicious_indicators: list, access_limitations: list) -> dict:
    """
    Assemble the complete security_posture section.
    """
    is_admin = _check_is_admin()

    if _IS_WINDOWS:
        firewall_profiles = _collect_firewall_windows(
            suspicious_indicators, access_limitations
        )
        defender_status = _collect_defender_status(
            suspicious_indicators, access_limitations
        )
        usb_history = _collect_usb_history_windows(
            suspicious_indicators, access_limitations
        )
    else:
        firewall_profiles = _collect_firewall_linux(
            suspicious_indicators, access_limitations
        )
        defender_status = "N/A (Linux/macOS)"
        usb_history = _collect_usb_history_linux(
            suspicious_indicators, access_limitations
        )

    return {
        "is_admin":            is_admin,
        "firewall_profiles":   firewall_profiles,
        "defender_status":     defender_status,
        "usb_storage_history": usb_history,
    }


# ===========================================================================
# SECTION 5 — GATEWAY / NETWORK ANOMALY CHECKS
# ===========================================================================

def _check_gateway_anomalies(network_config: dict, suspicious_indicators: list) -> None:
    """
    Examine the network_config to detect suspicious network conditions.
    Modifies *suspicious_indicators* in-place.
    """
    gateways = network_config.get("ipconfig_summary", {}).get("default_gateways", [])
    # Filter out blank or N/A entries
    real_gateways = [g for g in gateways if g and g.lower() not in ("n/a", "")]

    if not real_gateways:
        suspicious_indicators.append(
            _make_indicator(
                "SUSPICIOUS",
                "No Default Gateway Detected",
                "No default gateway was found in the network configuration. "
                "This may indicate network isolation, misconfiguration, or an "
                "active attempt to prevent communication.",
            )
        )


# ===========================================================================
# PUBLIC API — collect_artifacts()
# ===========================================================================

def collect_artifacts() -> dict:
    """
    Collect a complete forensic snapshot of the host's OS, hardware,
    network, and security posture.

    Returns
    -------
    dict
        A fully normalised artifact dictionary ready for JSON serialisation.
        Schema:
        {
          "module_name":          str,
          "version":              str,
          "status":               "success" | "limited_access",
          "collection_time":      "YYYY-MM-DD HH:MM:SS",
          "access_limitations":   [str],
          "suspicious_indicators": [
              {"severity": str, "indicator": str, "details": str, "timestamp": str}
          ],
          "artifacts": {
              "os_details":       {...},
              "system_config":    {...},
              "network_config":   {...},
              "security_posture": {...}
          }
        }

    Notes
    -----
    - This function is entirely READ-ONLY; it never mutates system state.
    - All subprocess calls use shell=False and timeout=12 seconds.
    - On partial failures, affected fields are set to "N/A" and an entry is
      appended to access_limitations; collection continues for other fields.
    """
    collection_time     = _now_str()
    access_limitations: list  = []
    suspicious_indicators: list = []

    # ------------------------------------------------------------------
    # 1. OS Details
    # ------------------------------------------------------------------
    os_details = _collect_os_details(access_limitations)

    # ------------------------------------------------------------------
    # 2. System Configuration
    # ------------------------------------------------------------------
    system_config = _collect_system_config(access_limitations)

    # Patch uptime_hours into os_details now that boot_time is known
    boot_time_str = system_config.get("boot_time", "N/A")
    if _IS_WINDOWS:
        os_details["uptime_hours"] = _compute_uptime_hours(boot_time_str)
    else:
        # On Linux, `uptime` output is already human-readable; store it verbatim
        os_details["uptime_hours"] = boot_time_str

    # ------------------------------------------------------------------
    # 3. Network Configuration
    # ------------------------------------------------------------------
    network_config = _collect_network_config(access_limitations)

    # ------------------------------------------------------------------
    # 4. Gateway anomaly check (needs network_config built first)
    # ------------------------------------------------------------------
    _check_gateway_anomalies(network_config, suspicious_indicators)

    # ------------------------------------------------------------------
    # 5. Security Posture
    # ------------------------------------------------------------------
    security_posture = _collect_security_posture(suspicious_indicators, access_limitations)

    # ------------------------------------------------------------------
    # 6. Determine overall status
    # ------------------------------------------------------------------
    status = "limited_access" if access_limitations else "success"

    # ------------------------------------------------------------------
    # 7. Assemble and return the final artifact document
    # ------------------------------------------------------------------
    return {
        "module_name":           "OS, Hardware & Network Security Posture",
        "version":               "3.0",
        "status":                status,
        "collection_time":       collection_time,
        "access_limitations":    access_limitations,
        "suspicious_indicators": suspicious_indicators,
        "artifacts": {
            "os_details":       os_details,
            "system_config":    system_config,
            "network_config":   network_config,
            "security_posture": security_posture,
        },
    }


# ===========================================================================
# CLI ENTRY POINT (for standalone testing)
# ===========================================================================

if __name__ == "__main__":
    import json as _json

    print("=" * 72)
    print(" Digital Forensics & Incident Triage Tool v3.0")
    print(" Module: OS, Hardware & Network Security Posture")
    print("=" * 72)
    print()

    result = collect_artifacts()

    # Pretty-print the full artifact to stdout
    print(_json.dumps(result, indent=2, default=str))

    print()
    print("=" * 72)
    print(" Collection Status : {}".format(result["status"].upper()))
    print(" Indicators Found  : {}".format(len(result["suspicious_indicators"])))
    print(" Access Limitations: {}".format(len(result["access_limitations"])))
    print("=" * 72)
