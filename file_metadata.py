"""
===============================================================================
Digital Forensics & Incident Triage Tool v3.0
Module: File Integrity, Timestomping & Masquerade Detection
File:   file_metadata.py

Description:
    Scans common user folders (Downloads, Desktop, Documents) and collects
    per-file metadata including timestamps, hashes, and behavioural flags for:
      - Double-extension masquerade attacks
      - Timestamp manipulation (timestomping)
      - Recently modified executables/scripts
      - Known dangerous file extensions

Dependencies: Python 3.6+ standard library ONLY
              (datetime, hashlib, json, os, stat, platform)

Usage:
    from file_metadata import collect_artifacts
    result = collect_artifacts()   # returns dict
    # -- or run standalone --
    python file_metadata.py

Author:  Digital Forensics & Incident Triage Tool v3.0
License: For authorised forensic / incident-response use only.
         Read-only: this module NEVER modifies any file on disk.
===============================================================================
"""

import datetime
import hashlib
import json
import os
import stat
import platform


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Folders to scan inside the user home directory
TARGET_FOLDER_NAMES: list = ["Downloads", "Desktop", "Documents"]

# Maximum files to process per folder (prevents runaway scans on large dirs)
MAX_FILES_PER_FOLDER: int = 40

# SHA-256 is computed only for files at or below this size (10 MB)
MAX_HASH_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB

# Read chunk size used while hashing (64 KB)
HASH_CHUNK_SIZE: int = 65536

# Extensions considered "known dangerous" for the INFO-level flag
DANGEROUS_EXTENSIONS: set = {".exe", ".ps1", ".bat", ".vbs", ".cmd",
                               ".scr", ".hta", ".jar"}

# Known harmless decoy extensions used in double-extension masquerade detection
DECOY_EXTENSIONS: set = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".rtf", ".csv", ".odt", ".ods", ".odp",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv",
}

# Extensions that trigger SUSPICIOUS "recent executable" detection
RECENT_EXEC_EXTENSIONS: set = {".exe", ".ps1", ".bat", ".vbs", ".cmd",
                                 ".scr", ".jar", ".hta"}

# Seconds in 24 hours (used by recent-exec check)
SECONDS_24H: int = 3600 * 24

# Timestomping tolerance: flag only if mtime < ctime by more than this many s
TIMESTOMP_TOLERANCE_SECS: int = 60


# ---------------------------------------------------------------------------
# Helper: human-readable file size
# ---------------------------------------------------------------------------

def format_size(size_bytes: int) -> str:
    """Convert a byte count to a human-readable string.

    Examples:
        1_234_567_890  -> "1.15 GB"
        1_234_567      -> "1.18 MB"
        12_345         -> "12.06 KB"
        512            -> "512 B"
    """
    if size_bytes >= 1024 ** 3:
        return f"{size_bytes / 1024 ** 3:.2f} GB"
    if size_bytes >= 1024 ** 2:
        return f"{size_bytes / 1024 ** 2:.2f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.2f} KB"
    return f"{size_bytes} B"


# ---------------------------------------------------------------------------
# Helper: epoch timestamp -> formatted string
# ---------------------------------------------------------------------------

def format_time(epoch) -> str:
    """Convert a POSIX epoch float to a readable datetime string.

    Returns "N/A" if epoch is None or conversion fails.
    """
    if epoch is None:
        return "N/A"
    try:
        return datetime.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "N/A"


# ---------------------------------------------------------------------------
# Helper: current datetime string (used for indicator timestamps)
# ---------------------------------------------------------------------------

def _now_str() -> str:
    """Return the current local datetime as a formatted string."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Helper: resolve user home directory (cross-platform)
# ---------------------------------------------------------------------------

def _resolve_home() -> str:
    """Return the user's home directory path.

    On Windows  : uses %USERPROFILE% env-var, falling back to expanduser("~").
    On Linux/Mac: uses os.path.expanduser("~").
    """
    if platform.system() == "Windows":
        return os.environ.get("USERPROFILE", os.path.expanduser("~"))
    return os.path.expanduser("~")


# ---------------------------------------------------------------------------
# Helper: compute SHA-256 digest for a file
# ---------------------------------------------------------------------------

def _sha256(full_path: str) -> str:
    """Compute the SHA-256 hex digest of a file using 64 KB read chunks.

    Returns:
        Hex digest string on success.
        "Skipped (>10MB)"       if the file exceeds MAX_HASH_SIZE_BYTES.
        "Error: <reason>"       if any exception is raised during hashing.

    This function is strictly read-only: it opens the file in binary mode
    and never writes to it.
    """
    try:
        file_size = os.path.getsize(full_path)
    except OSError as exc:
        return f"Error: {exc}"

    if file_size > MAX_HASH_SIZE_BYTES:
        return "Skipped (>10MB)"

    hasher = hashlib.sha256()
    try:
        with open(full_path, "rb") as fh:
            while True:
                chunk = fh.read(HASH_CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as exc:
        return f"Error: {exc}"


# ---------------------------------------------------------------------------
# Helper: check for double-extension masquerade
# ---------------------------------------------------------------------------

def _has_double_extension(file_name: str) -> bool:
    """Return True when *file_name* appears to use a double-extension trick.

    Hidden/lock files starting with '.' (such as '.~lock...') are ignored.
    A double-extension masquerade is flagged only when the final extension is
    in DANGEROUS_EXTENSIONS (or '.sh') AND the immediately preceding extension
    is a known harmless decoy extension (in DECOY_EXTENSIONS), so normal dots
    in versions (v1.3), timestamps (10.04.40), or abbreviations (B.Sc.) are
    not flagged.

        report.pdf.exe  ->  last = ".exe", inner = ".pdf"  TRUE
        photo.jpg.sh    ->  last = ".sh",  inner = ".jpg"  TRUE
        .~lock.a.pdf#   ->  starts with "."                FALSE
        app_v1.3.exe    ->  last = ".exe", inner = ".3"    FALSE
        log_10.04.40.sh ->  last = ".sh",  inner = ".40"   FALSE
        notes_B.Sc.exe  ->  last = ".exe", inner = ".sc"   FALSE
        invoice.docx    ->  last = ".docx" (not dangerous) FALSE
    """
    if not file_name or file_name.startswith("."):
        return False

    base, last_ext = os.path.splitext(file_name)
    last_ext = last_ext.lower()
    if last_ext not in DANGEROUS_EXTENSIONS and last_ext != ".sh":
        return False

    inner_base, inner_ext = os.path.splitext(base)
    if not inner_base:
        return False
    return inner_ext.lower() in DECOY_EXTENSIONS


# ---------------------------------------------------------------------------
# Core: collect per-file metadata and apply flag logic
# ---------------------------------------------------------------------------

def _process_file(entry,
                  now_epoch: float,
                  is_windows: bool,
                  suspicious_indicators: list) -> dict:
    """Build the metadata dict for a single file *entry*.

    Args:
        entry:                 os.DirEntry object for the file.
        now_epoch:             Current time as POSIX epoch (float).
        is_windows:            True when running on Windows.
        suspicious_indicators: Shared list to which HIGH_RISK / SUSPICIOUS
                               indicator dicts are appended in-place.

    Returns:
        A dict matching the per-file schema defined in collect_artifacts().
    """
    full_path: str = entry.path
    file_name: str = entry.name
    _base, raw_ext = os.path.splitext(file_name)
    extension: str = raw_ext.lower()

    # ------------------------------------------------------------------ stat
    try:
        st = entry.stat(follow_symlinks=False)
        size_bytes: int = st.st_size
        ctime: float = st.st_ctime   # Windows: creation time; Linux: inode change time
        mtime: float = st.st_mtime
        atime: float = st.st_atime
    except OSError:
        # If stat fails return a minimal record so the file is still counted
        return {
            "file_name": file_name,
            "full_path": full_path,
            "extension": extension,
            "size_bytes": 0,
            "size_human": "N/A",
            "created": "N/A",
            "modified": "N/A",
            "accessed": "N/A",
            "sha256": "Error: stat failed",
            "flags": ["STAT_ERROR: Could not read file metadata"],
        }

    size_human: str = format_size(size_bytes)
    created_str: str = format_time(ctime)
    modified_str: str = format_time(mtime)
    accessed_str: str = format_time(atime)

    # ------------------------------------------------------------------ hash
    sha256_digest: str = _sha256(full_path)

    # ------------------------------------------------------------------ flags
    flags: list = []
    current_time: str = _now_str()

    # --- Flag 1: Double-extension masquerade (HIGH_RISK) -------------------
    if _has_double_extension(file_name):
        flag_text = f"MASQUERADE: Double Extension ({file_name})"
        flags.append(flag_text)
        suspicious_indicators.append({
            "severity": "HIGH_RISK",
            "indicator": "Double Extension Masquerade Detected",
            "details": (
                f"File: {full_path} | "
                f"Size: {size_human} | "
                f"Modified: {modified_str}"
            ),
            "timestamp": current_time,
        })

    # --- Flag 2: Timestomping – Windows only (HIGH_RISK) -------------------
    # On Windows st_ctime is the true file creation time, so a modified time
    # that is earlier than the creation time (minus tolerance) is a strong
    # signal of deliberate timestamp manipulation (timestomping).
    # On Linux/Mac, st_ctime is the inode-change time and can legitimately
    # precede st_mtime, so this check is intentionally skipped on those OSes.
    if is_windows and (mtime < ctime - TIMESTOMP_TOLERANCE_SECS):
        flag_text = "TIMESTOMPING: Modified before Created"
        flags.append(flag_text)
        suspicious_indicators.append({
            "severity": "HIGH_RISK",
            "indicator": "Timestamp Manipulation (Timestomping) Detected",
            "details": (
                f"File: {full_path} | "
                f"Size: {size_human} | "
                f"Modified: {modified_str}"
            ),
            "timestamp": current_time,
        })

    # --- Flag 3: Recently modified executable / script (SUSPICIOUS) --------
    # Flag any executable or script that was last modified within the past
    # 24 hours.  age_seconds >= 0 guards against system clock skew where
    # mtime could appear to be slightly in the future.
    if extension in RECENT_EXEC_EXTENSIONS:
        age_seconds = now_epoch - mtime
        if 0 <= age_seconds <= SECONDS_24H:
            flag_text = "RECENT_EXEC: Modified in last 24h"
            flags.append(flag_text)
            suspicious_indicators.append({
                "severity": "SUSPICIOUS",
                "indicator": "Recently Modified Executable or Script",
                "details": (
                    f"File: {full_path} | "
                    f"Size: {size_human} | "
                    f"Modified: {modified_str}"
                ),
                "timestamp": current_time,
            })

    # --- Flag 4: Known dangerous extension (INFO) --------------------------
    # This is an informational flag only.  Every executable/script extension
    # is noted regardless of age or other attributes.
    if extension in DANGEROUS_EXTENSIONS:
        flags.append("EXEC_EXT: Executable/Script file type")

    # ---------------------------------------------------------------- result
    return {
        "file_name": file_name,
        "full_path": full_path,
        "extension": extension,
        "size_bytes": size_bytes,
        "size_human": size_human,
        "created": created_str,
        "modified": modified_str,
        "accessed": accessed_str,
        "sha256": sha256_digest,
        "flags": flags,
    }


# ---------------------------------------------------------------------------
# Core: scan a single folder
# ---------------------------------------------------------------------------

def _scan_folder(folder_path: str,
                 now_epoch: float,
                 is_windows: bool,
                 suspicious_indicators: list,
                 access_limitations: list) -> list:
    """Scan *folder_path* and return a list of per-file metadata dicts.

    At most MAX_FILES_PER_FOLDER regular files are processed.  Subdirectories
    and symlinks pointing to directories are skipped silently.

    If the folder does not exist or cannot be listed, a warning string is
    appended to *access_limitations* and an empty list is returned.
    """
    if not os.path.isdir(folder_path):
        access_limitations.append(
            f"Folder not found or inaccessible: {folder_path}"
        )
        return []

    file_records: list = []
    files_processed: int = 0

    try:
        entries = list(os.scandir(folder_path))
    except PermissionError as exc:
        access_limitations.append(
            f"Permission denied scanning {folder_path}: {exc}"
        )
        return []
    except OSError as exc:
        access_limitations.append(
            f"OS error scanning {folder_path}: {exc}"
        )
        return []

    for entry in entries:
        if files_processed >= MAX_FILES_PER_FOLDER:
            # Cap reached – record that additional files were not processed
            access_limitations.append(
                f"Scan cap ({MAX_FILES_PER_FOLDER} files) reached in: "
                f"{folder_path}. Additional files were not processed."
            )
            break

        # Only process regular files (skip dirs, symlinks-to-dirs, special)
        try:
            if not entry.is_file(follow_symlinks=False):
                continue
        except OSError:
            continue

        record = _process_file(
            entry=entry,
            now_epoch=now_epoch,
            is_windows=is_windows,
            suspicious_indicators=suspicious_indicators,
        )
        file_records.append(record)
        files_processed += 1

    return file_records


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def collect_artifacts() -> dict:
    """Collect file-integrity and threat-indicator metadata from common user
    folders (Downloads, Desktop, Documents).

    Returns a dict with the following top-level keys:

        module_name           – human-readable module label
        version               – module version string
        status                – "success" | "limited_access"
        collection_time       – ISO-like datetime string when scan was run
        access_limitations    – list of warning strings (empty on full success)
        suspicious_indicators – list of indicator dicts (severity / detail)
        artifacts             – nested dict containing:
            scan_summary      – scanned folder paths + file counts
            files             – list of all per-file metadata dicts
            flagged_files     – subset of *files* where flags list is non-empty

    This function is strictly read-only.  It never creates, modifies, or
    deletes any file on the target system.
    """

    # ------------------------------------------------------------------
    # Initialise shared accumulators
    # ------------------------------------------------------------------
    collection_time: str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    now_epoch: float = datetime.datetime.now().timestamp()
    is_windows: bool = platform.system() == "Windows"

    access_limitations: list = []
    suspicious_indicators: list = []
    all_files: list = []
    scanned_folder_paths: list = []

    # ------------------------------------------------------------------
    # Resolve home directory and build target folder absolute paths
    # ------------------------------------------------------------------
    home: str = _resolve_home()

    for folder_name in TARGET_FOLDER_NAMES:
        folder_path: str = os.path.join(home, folder_name)
        scanned_folder_paths.append(folder_path)

        folder_records = _scan_folder(
            folder_path=folder_path,
            now_epoch=now_epoch,
            is_windows=is_windows,
            suspicious_indicators=suspicious_indicators,
            access_limitations=access_limitations,
        )
        all_files.extend(folder_records)

    # ------------------------------------------------------------------
    # Build derived collections
    # ------------------------------------------------------------------
    flagged_files: list = [f for f in all_files if f.get("flags")]

    scan_summary: dict = {
        "scanned_folders": scanned_folder_paths,
        "total_files_scanned": len(all_files),
        "total_flagged_files": len(flagged_files),
    }

    # Status is "limited_access" if any warnings were generated during scan
    status: str = "limited_access" if access_limitations else "success"

    # ------------------------------------------------------------------
    # Assemble and return the final result dict
    # ------------------------------------------------------------------
    return {
        "module_name": "File Integrity, Timestomping & Masquerade Detection",
        "version": "3.0",
        "status": status,
        "collection_time": collection_time,
        "access_limitations": access_limitations,
        "suspicious_indicators": suspicious_indicators,
        "artifacts": {
            "scan_summary": scan_summary,
            "files": all_files,
            "flagged_files": flagged_files,
        },
    }


# ---------------------------------------------------------------------------
# Standalone entry point (for quick testing / CLI usage)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    result = collect_artifacts()

    # Pretty-print the full result as JSON to stdout
    print(json.dumps(result, indent=2))

    # Print a concise human-readable summary below the JSON output
    summary = result["artifacts"]["scan_summary"]
    print("\n" + "=" * 60)
    print(f"  Module     : {result['module_name']} v{result['version']}")
    print(f"  Status     : {result['status'].upper()}")
    print(f"  Collected  : {result['collection_time']}")
    print(f"  Scanned    : {summary['total_files_scanned']} file(s) across "
          f"{len(summary['scanned_folders'])} folder(s)")
    print(f"  Flagged    : {summary['total_flagged_files']} file(s)")
    print(f"  Indicators : {len(result['suspicious_indicators'])}")
    if result["access_limitations"]:
        print("\n  Access Limitations:")
        for limitation in result["access_limitations"]:
            print(f"    • {limitation}")
    print("=" * 60)
