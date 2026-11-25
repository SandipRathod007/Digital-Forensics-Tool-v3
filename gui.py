"""
Digital Forensics & Incident Triage Tool — v3.0
GUI Launcher: Native tkinter Desktop Application
=================================================
Zero-install, dark-slate themed desktop launcher.
Runs the forensic triage engine in a background thread.
Streams live console output. Opens HTML/JSON reports with one click.

Dependencies: Python 3.6+ standard library only (tkinter, threading, subprocess, webbrowser).
"""

import os
import sys
import platform
import ctypes
import threading
import subprocess
import webbrowser
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import datetime
import time
import collections
import xml.etree.ElementTree as ET

# ============================================================
# PATHS
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MAIN_PY = os.path.join(BASE_DIR, "main.py")
HTML_REPORT = os.path.join(BASE_DIR, "forensic_report.html")
JSON_REPORT = os.path.join(BASE_DIR, "forensic_report.json")
INTEGRITY_FILE = os.path.join(BASE_DIR, "forensic_report_integrity.sha256")

# ============================================================
# THEME
# ============================================================
COLORS = {
    "bg":          "#0D1117",
    "card":        "#161B22",
    "card2":       "#1C2128",
    "border":      "#30363D",
    "text":        "#E6EDF3",
    "text2":       "#8B949E",
    "accent":      "#2F81F7",
    "success":     "#3FB950",
    "warning":     "#D29922",
    "danger":      "#F85149",
    "purple":      "#A371F7",
    "btn_primary": "#238636",
    "btn_hover":   "#2EA043",
}

FONT_MONO = ("Consolas", 9)
FONT_BODY = ("Segoe UI", 10)
FONT_TITLE = ("Segoe UI", 15, "bold")
FONT_LABEL = ("Segoe UI", 9)
FONT_BADGE = ("Segoe UI", 8, "bold")

# ============================================================
# PRIVILEGE DETECTION
# ============================================================
def is_admin():
    try:
        if platform.system() == "Windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            return os.geteuid() == 0
    except Exception:
        return False


# ============================================================
# MAIN APP
# ============================================================
class ForensicGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Digital Forensics & Incident Triage Tool — v3.0")
        self.geometry("900x680")
        self.minsize(760, 520)
        self.configure(bg=COLORS["bg"])

        # Set icon if on Windows (suppress errors if ico absent)
        try:
            self.iconbitmap(default="")
        except Exception:
            pass

        # DPI awareness
        if platform.system() == "Windows":
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                pass

        self._is_running = False
        self._process = None
        self._admin = is_admin()
        self._live_running = False
        self._live_stop_event = threading.Event()
        self._live_threads = []

        self._build_ui()
        self._update_report_buttons()

    # ----------------------------------------------------------
    # UI CONSTRUCTION
    # ----------------------------------------------------------
    def _build_ui(self):
        # --- HEADER BANNER ---
        header = tk.Frame(self, bg="#0A0E14", pady=0)
        header.pack(fill="x")

        inner_header = tk.Frame(header, bg="#0A0E14")
        inner_header.pack(fill="x", padx=20, pady=14)

        # Logo + Title
        title_lbl = tk.Label(
            inner_header,
            text="🛡  Digital Forensics & Incident Triage",
            font=FONT_TITLE,
            fg=COLORS["text"],
            bg="#0A0E14",
        )
        title_lbl.pack(side="left")

        version_lbl = tk.Label(
            inner_header,
            text="v3.0 Enterprise",
            font=("Segoe UI", 9),
            fg=COLORS["text2"],
            bg="#0A0E14",
        )
        version_lbl.pack(side="left", padx=(10, 0), pady=(4, 0))

        # Privilege badge
        priv_color = COLORS["danger"] if not self._admin else COLORS["success"]
        priv_text = ("🔴  Standard User" if not self._admin else "🟢  Administrator")
        self._priv_badge = tk.Label(
            inner_header,
            text=priv_text,
            font=FONT_BADGE,
            fg=priv_color,
            bg="#0A0E14",
            padx=10,
            pady=4,
            relief="solid",
            bd=1,
        )
        self._priv_badge.pack(side="right")
        self._priv_badge.config(highlightbackground=priv_color)

        # Separator line
        sep = tk.Frame(self, bg=COLORS["border"], height=1)
        sep.pack(fill="x")

        # --- STATUS STRIP ---
        status_strip = tk.Frame(self, bg=COLORS["card2"], pady=0)
        status_strip.pack(fill="x")

        status_inner = tk.Frame(status_strip, bg=COLORS["card2"])
        status_inner.pack(fill="x", padx=20, pady=8)

        tk.Label(status_inner, text="Status:", font=FONT_LABEL, fg=COLORS["text2"], bg=COLORS["card2"]).pack(side="left")
        self._status_lbl = tk.Label(
            status_inner,
            text="  ⚫  Idle — Ready for forensic triage",
            font=FONT_LABEL,
            fg=COLORS["text2"],
            bg=COLORS["card2"],
        )
        self._status_lbl.pack(side="left", padx=4)

        # Last run time
        self._lastrun_lbl = tk.Label(
            status_inner,
            text="",
            font=FONT_LABEL,
            fg=COLORS["text2"],
            bg=COLORS["card2"],
        )
        self._lastrun_lbl.pack(side="right")

        sep2 = tk.Frame(self, bg=COLORS["border"], height=1)
        sep2.pack(fill="x")

        # --- TOOLBAR ---
        toolbar = tk.Frame(self, bg=COLORS["card"], pady=10)
        toolbar.pack(fill="x")

        btn_frame = tk.Frame(toolbar, bg=COLORS["card"])
        btn_frame.pack(padx=20, fill="x")

        # RUN button
        self._run_btn = tk.Button(
            btn_frame,
            text="  ▶  RUN FORENSIC TRIAGE  ",
            font=("Segoe UI", 11, "bold"),
            fg="#FFFFFF",
            bg=COLORS["btn_primary"],
            activebackground=COLORS["btn_hover"],
            activeforeground="#FFFFFF",
            relief="flat",
            padx=16,
            pady=8,
            cursor="hand2",
            bd=0,
            command=self._start_triage,
        )
        self._run_btn.pack(side="left", padx=(0, 10))

        # STOP button
        self._stop_btn = tk.Button(
            btn_frame,
            text="  ■  STOP  ",
            font=("Segoe UI", 10, "bold"),
            fg="#FFFFFF",
            bg=COLORS["danger"],
            activebackground="#c0392b",
            activeforeground="#FFFFFF",
            relief="flat",
            padx=10,
            pady=8,
            cursor="hand2",
            bd=0,
            state="disabled",
            command=self._stop_triage,
        )
        self._stop_btn.pack(side="left", padx=(0, 10))

        # Separator
        tk.Frame(btn_frame, bg=COLORS["border"], width=1, height=36).pack(side="left", padx=10)

        # Open HTML report
        self._html_btn = tk.Button(
            btn_frame,
            text="  🌐  Open HTML Report  ",
            font=FONT_BODY,
            fg=COLORS["text"],
            bg=COLORS["card2"],
            activebackground=COLORS["border"],
            relief="flat",
            padx=10,
            pady=7,
            cursor="hand2",
            bd=0,
            command=self._open_html,
        )
        self._html_btn.pack(side="left", padx=(0, 6))

        # Open JSON report
        self._json_btn = tk.Button(
            btn_frame,
            text="  📄  Open JSON Report  ",
            font=FONT_BODY,
            fg=COLORS["text"],
            bg=COLORS["card2"],
            activebackground=COLORS["border"],
            relief="flat",
            padx=10,
            pady=7,
            cursor="hand2",
            bd=0,
            command=self._open_json,
        )
        self._json_btn.pack(side="left", padx=(0, 6))

        # Open folder
        self._folder_btn = tk.Button(
            btn_frame,
            text="  📁  Open Folder  ",
            font=FONT_BODY,
            fg=COLORS["text"],
            bg=COLORS["card2"],
            activebackground=COLORS["border"],
            relief="flat",
            padx=10,
            pady=7,
            cursor="hand2",
            bd=0,
            command=self._open_folder,
        )
        self._folder_btn.pack(side="left", padx=(0, 6))

        # Clear console
        clr_btn = tk.Button(
            btn_frame,
            text="  🗑  Clear  ",
            font=FONT_BODY,
            fg=COLORS["text2"],
            bg=COLORS["card2"],
            activebackground=COLORS["border"],
            relief="flat",
            padx=8,
            pady=7,
            cursor="hand2",
            bd=0,
            command=self._clear_console,
        )
        clr_btn.pack(side="right")

        sep3 = tk.Frame(self, bg=COLORS["border"], height=1)
        sep3.pack(fill="x")

        # --- NOTEBOOK TABS (Triage Scan & Live Monitor) ---
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Forensic.TNotebook",
            background=COLORS["bg"],
            borderwidth=0,
            tabmargins=[20, 6, 20, 0],
        )
        style.configure(
            "Forensic.TNotebook.Tab",
            background=COLORS["card"],
            foreground=COLORS["text2"],
            padding=[14, 6],
            font=("Segoe UI", 9, "bold"),
            borderwidth=0,
        )
        style.map(
            "Forensic.TNotebook.Tab",
            background=[("selected", COLORS["card2"])],
            foreground=[("selected", COLORS["accent"])],
        )
        style.configure(
            "Forensic.Horizontal.TProgressbar",
            troughcolor=COLORS["card"],
            background=COLORS["accent"],
            darkcolor=COLORS["accent"],
            lightcolor=COLORS["accent"],
            bordercolor=COLORS["border"],
            thickness=6,
        )

        self._notebook = ttk.Notebook(self, style="Forensic.TNotebook")
        self._notebook.pack(fill="both", expand=True)

        triage_tab = tk.Frame(self._notebook, bg=COLORS["bg"])
        live_tab = tk.Frame(self._notebook, bg=COLORS["bg"])
        self._notebook.add(triage_tab, text="  🔍  Triage Scan  ")
        self._notebook.add(live_tab, text="  📡  Live Monitor  ")

        # --- PROGRESS BAR ---
        progress_frame = tk.Frame(triage_tab, bg=COLORS["bg"], pady=6)
        progress_frame.pack(fill="x", padx=20)

        self._progress_lbl = tk.Label(
            progress_frame,
            text="",
            font=FONT_LABEL,
            fg=COLORS["text2"],
            bg=COLORS["bg"],
        )
        self._progress_lbl.pack(anchor="w", pady=(0, 4))

        self._progress = ttk.Progressbar(
            progress_frame,
            style="Forensic.Horizontal.TProgressbar",
            mode="indeterminate",
            length=860,
        )
        self._progress.pack(fill="x")

        # --- MODULE STATUS CARDS ---
        cards_frame = tk.Frame(triage_tab, bg=COLORS["bg"])
        cards_frame.pack(fill="x", padx=20, pady=(10, 4))

        self._module_cards = {}
        modules = [
            ("os_info", "🖥  OS & Network"),
            ("process_startup", "⚙  Processes & Persistence"),
            ("event_logs", "📋  Event Logs"),
            ("file_metadata", "📁  File Metadata"),
        ]

        for mod_key, mod_label in modules:
            card = tk.Frame(
                cards_frame,
                bg=COLORS["card"],
                relief="flat",
                padx=10,
                pady=8,
                bd=1,
            )
            card.pack(side="left", expand=True, fill="x", padx=(0, 8))

            lbl = tk.Label(card, text=mod_label, font=FONT_LABEL, fg=COLORS["text2"], bg=COLORS["card"])
            lbl.pack(anchor="w")

            status_var = tk.StringVar(value="⚫  Pending")
            status_lbl = tk.Label(card, textvariable=status_var, font=FONT_BADGE, fg=COLORS["text2"], bg=COLORS["card"])
            status_lbl.pack(anchor="w", pady=(2, 0))

            self._module_cards[mod_key] = {
                "frame": card,
                "status_var": status_var,
                "status_lbl": status_lbl,
            }

        # --- CONSOLE LOG ---
        console_frame = tk.Frame(triage_tab, bg=COLORS["bg"])
        console_frame.pack(fill="both", expand=True, padx=20, pady=(8, 12))

        console_hdr = tk.Frame(console_frame, bg=COLORS["card2"], pady=6)
        console_hdr.pack(fill="x")
        tk.Label(
            console_hdr,
            text="  🖥  Live Console Output",
            font=("Segoe UI", 9, "bold"),
            fg=COLORS["text2"],
            bg=COLORS["card2"],
        ).pack(side="left", padx=8)

        self._console = scrolledtext.ScrolledText(
            console_frame,
            font=FONT_MONO,
            bg="#010409",
            fg="#C9D1D9",
            insertbackground=COLORS["accent"],
            selectbackground=COLORS["accent"],
            relief="flat",
            bd=0,
            wrap="word",
            state="disabled",
            padx=10,
            pady=8,
        )
        self._console.pack(fill="both", expand=True)

        # Colour tags for the console
        self._console.tag_config("ok",      foreground="#3FB950")
        self._console.tag_config("warn",    foreground="#D29922")
        self._console.tag_config("error",   foreground="#F85149")
        self._console.tag_config("info",    foreground="#58A6FF")
        self._console.tag_config("heading", foreground="#E6EDF3", font=("Consolas", 9, "bold"))
        self._console.tag_config("dim",     foreground="#484F58")

        # --- LIVE MONITOR TAB ---
        self._build_live_tab(live_tab)

        # --- FOOTER ---
        footer = tk.Frame(self, bg=COLORS["card2"], pady=5)
        footer.pack(fill="x", side="bottom")
        tk.Label(
            footer,
            text=f"  Digital Forensics & Incident Triage Tool v3.0  |  ISO/IEC 27037  |  Zero external dependencies  |  {platform.system()} {platform.machine()}",
            font=("Segoe UI", 8),
            fg=COLORS["text2"],
            bg=COLORS["card2"],
        ).pack(side="left")

        # Initial greeting
        self._log("=" * 62, "heading")
        self._log("  DIGITAL FORENSICS & INCIDENT TRIAGE TOOL  v3.0", "heading")
        self._log("  Enterprise Edition — ISO/IEC 27037 Chain-of-Custody", "dim")
        self._log("=" * 62, "heading")
        self._log(f"  Platform : {platform.system()} {platform.machine()}", "info")
        self._log(f"  Python   : {sys.version.split()[0]}", "info")
        priv_note = "Administrator (Elevated)" if self._admin else "Standard User (Non-Admin)"
        priv_tag = "ok" if self._admin else "warn"
        self._log(f"  Privilege: {priv_note}", priv_tag)
        self._log(f"  Base Dir : {BASE_DIR}", "dim")
        self._log("-" * 62, "dim")
        self._log("  Press  ▶ RUN FORENSIC TRIAGE  to begin collection.", "info")
        self._log("-" * 62, "dim")

    # ----------------------------------------------------------
    # CONSOLE HELPERS
    # ----------------------------------------------------------
    def _log(self, text, tag=None):
        """Thread-safe console logging."""
        def _do():
            self._console.config(state="normal")
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            if tag:
                self._console.insert("end", f"[{ts}] {text}\n", tag)
            else:
                self._console.insert("end", f"[{ts}] {text}\n")
            self._console.see("end")
            self._console.config(state="disabled")
        self.after(0, _do)

    def _clear_console(self):
        self._console.config(state="normal")
        self._console.delete("1.0", "end")
        self._console.config(state="disabled")

    # ----------------------------------------------------------
    # MODULE CARD HELPERS
    # ----------------------------------------------------------
    def _reset_cards(self):
        for key, card in self._module_cards.items():
            card["status_var"].set("⚫  Pending")
            card["status_lbl"].config(fg=COLORS["text2"])

    def _set_card_running(self, key):
        if key in self._module_cards:
            def _do():
                self._module_cards[key]["status_var"].set("🔵  Running...")
                self._module_cards[key]["status_lbl"].config(fg=COLORS["accent"])
            self.after(0, _do)

    def _set_card_done(self, key, ok=True, label="Done"):
        if key in self._module_cards:
            sym = "🟢" if ok else "🟡"
            color = COLORS["success"] if ok else COLORS["warning"]
            def _do():
                self._module_cards[key]["status_var"].set(f"{sym}  {label}")
                self._module_cards[key]["status_lbl"].config(fg=color)
            self.after(0, _do)

    def _set_card_error(self, key, label="Error"):
        if key in self._module_cards:
            def _do():
                self._module_cards[key]["status_var"].set(f"🔴  {label}")
                self._module_cards[key]["status_lbl"].config(fg=COLORS["danger"])
            self.after(0, _do)

    # ----------------------------------------------------------
    # STATUS UPDATES
    # ----------------------------------------------------------
    def _set_status(self, text, color=None):
        def _do():
            self._status_lbl.config(text=f"  {text}", fg=color or COLORS["text2"])
        self.after(0, _do)

    def _set_progress_label(self, text):
        def _do():
            self._progress_lbl.config(text=text)
        self.after(0, _do)

    # ----------------------------------------------------------
    # TRIAGE EXECUTION
    # ----------------------------------------------------------
    def _start_triage(self):
        if self._is_running:
            return

        self._is_running = True
        self._run_btn.config(state="disabled", text="  ⏳  Running...")
        self._stop_btn.config(state="normal")
        self._html_btn.config(state="disabled")
        self._json_btn.config(state="disabled")
        self._reset_cards()
        self._progress.start(12)
        self._set_status("⚙  Forensic triage in progress...", COLORS["accent"])
        self._set_progress_label("🔬  Collecting forensic artifacts — please wait...")

        self._log("=" * 62, "heading")
        self._log("  STARTING FORENSIC TRIAGE ENGINE", "heading")
        self._log(f"  Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "info")
        self._log("=" * 62, "heading")

        t = threading.Thread(target=self._triage_thread, daemon=True)
        t.start()

    def _triage_thread(self):
        """Runs main.py as a subprocess and streams output to the console."""
        try:
            python_exe = sys.executable
            cmd = [python_exe, MAIN_PY]

            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                cwd=BASE_DIR,
            )

            # Map module keywords to card keys for status updates
            module_keywords = {
                "OS": "os_info",
                "Network": "os_info",
                "Processes": "process_startup",
                "Persistence": "process_startup",
                "Event Log": "event_logs",
                "File": "file_metadata",
                "Metadata": "file_metadata",
            }
            active_modules = set()

            for line in self._process.stdout:
                line_stripped = line.rstrip()
                if not line_stripped:
                    continue

                # Determine console tag
                tag = None
                if line_stripped.startswith("[+]") or "completed" in line_stripped.lower() or "OK" in line_stripped:
                    tag = "ok"
                elif "[!]" in line_stripped or "error" in line_stripped.lower():
                    tag = "error"
                elif "[>]" in line_stripped:
                    tag = "info"
                elif line_stripped.startswith("=") or line_stripped.startswith("-"):
                    tag = "dim"
                elif "[*]" in line_stripped:
                    tag = "info"

                self._log(line_stripped, tag)

                # Update module cards based on output content
                for kw, card_key in module_keywords.items():
                    if kw in line_stripped and card_key not in active_modules:
                        if "[>]" in line_stripped:
                            self._set_card_running(card_key)
                            active_modules.add(card_key)
                        elif "[v]" in line_stripped or "success" in line_stripped.lower():
                            self._set_card_done(card_key, ok=True, label="Success")
                        elif "[!]" in line_stripped or "limited" in line_stripped.lower():
                            self._set_card_done(card_key, ok=False, label="Limited Access")

                # Detect module completion lines like "[v] Status: success | Indicators: N"
                if "Status:" in line_stripped and "Indicators:" in line_stripped:
                    for kw, card_key in module_keywords.items():
                        if card_key in active_modules:
                            ok = "success" in line_stripped.lower()
                            lbl = "Success" if ok else "Limited Access"
                            self._set_card_done(card_key, ok=ok, label=lbl)

            self._process.wait()
            ret = self._process.returncode

            if ret == 0:
                # Mark any still-pending cards as done
                for key in self._module_cards:
                    cur = self._module_cards[key]["status_var"].get()
                    if "Pending" in cur or "Running" in cur:
                        self._set_card_done(key, ok=True, label="Done")

                self._on_triage_done(success=True)
            else:
                self._on_triage_done(success=False, error=f"Process exited with code {ret}")

        except FileNotFoundError:
            self._log(f"[ERROR] main.py not found at: {MAIN_PY}", "error")
            self._on_triage_done(success=False, error="main.py not found")
        except Exception as exc:
            self._log(f"[ERROR] Unexpected error: {exc}", "error")
            self._on_triage_done(success=False, error=str(exc))
        finally:
            self._process = None

    def _on_triage_done(self, success=True, error=None):
        def _do():
            self._is_running = False
            self._progress.stop()
            self._run_btn.config(state="normal", text="  ▶  RUN FORENSIC TRIAGE  ")
            self._stop_btn.config(state="disabled")
            now = datetime.datetime.now().strftime("%H:%M:%S")
            self._lastrun_lbl.config(text=f"Last run: {now}")

            if success:
                self._set_status("✅  Triage complete — reports ready", COLORS["success"])
                self._set_progress_label("✅  Collection complete. Reports generated.")
                self._log("=" * 62, "heading")
                self._log("  FORENSIC TRIAGE COMPLETE", "ok")
                self._log("  Click the report buttons above to view results.", "ok")
                self._log("=" * 62, "heading")
            else:
                self._set_status(f"❌  Triage failed: {error}", COLORS["danger"])
                self._set_progress_label(f"❌  Error: {error}")
                self._log(f"[ERROR] Triage failed: {error}", "error")
                for key in self._module_cards:
                    cur = self._module_cards[key]["status_var"].get()
                    if "Pending" in cur or "Running" in cur:
                        self._set_card_error(key, "Error")

            self._update_report_buttons()

        self.after(0, _do)

    def _stop_triage(self):
        if self._process and self._is_running:
            try:
                self._process.terminate()
                self._log("[!] Triage stopped by user.", "warn")
            except Exception as e:
                self._log(f"[!] Could not stop process: {e}", "error")
            self._on_triage_done(success=False, error="Stopped by user")

    # ----------------------------------------------------------
    # REPORT ACTIONS
    # ----------------------------------------------------------
    def _update_report_buttons(self):
        html_exists = os.path.isfile(HTML_REPORT)
        json_exists = os.path.isfile(JSON_REPORT)
        self._html_btn.config(state="normal" if html_exists else "disabled")
        self._json_btn.config(state="normal" if json_exists else "disabled")

    def _open_html(self):
        if os.path.isfile(HTML_REPORT):
            webbrowser.open(f"file:///{HTML_REPORT.replace(os.sep, '/')}")
        else:
            messagebox.showwarning("Not Found", f"HTML report not found:\n{HTML_REPORT}\n\nRun triage first.")

    def _open_json(self):
        if os.path.isfile(JSON_REPORT):
            if platform.system() == "Windows":
                os.startfile(JSON_REPORT)
            elif platform.system() == "Darwin":
                subprocess.run(["open", JSON_REPORT], shell=False)
            else:
                subprocess.run(["xdg-open", JSON_REPORT], shell=False)
        else:
            messagebox.showwarning("Not Found", f"JSON report not found:\n{JSON_REPORT}\n\nRun triage first.")

    def _open_folder(self):
        if platform.system() == "Windows":
            subprocess.run(["explorer", BASE_DIR], shell=False)
        elif platform.system() == "Darwin":
            subprocess.run(["open", BASE_DIR], shell=False)
        else:
            subprocess.run(["xdg-open", BASE_DIR], shell=False)

    # ----------------------------------------------------------
    # LIVE MONITOR TAB & WATCHERS
    # ----------------------------------------------------------
    def _build_live_tab(self, parent):
        ctrl_bar = tk.Frame(parent, bg=COLORS["card"], pady=10)
        ctrl_bar.pack(fill="x", padx=20, pady=(12, 8))

        ctrl_inner = tk.Frame(ctrl_bar, bg=COLORS["card"])
        ctrl_inner.pack(fill="x", padx=12)

        self._live_toggle_btn = tk.Button(
            ctrl_inner,
            text="  ▶  Start Live Monitor  ",
            font=("Segoe UI", 10, "bold"),
            fg="#FFFFFF",
            bg=COLORS["btn_primary"],
            activebackground=COLORS["btn_hover"],
            activeforeground="#FFFFFF",
            relief="flat",
            padx=14,
            pady=6,
            cursor="hand2",
            bd=0,
            command=self._toggle_live_monitor,
        )
        self._live_toggle_btn.pack(side="left", padx=(0, 10))

        live_clr_btn = tk.Button(
            ctrl_inner,
            text="  🗑  Clear Feed  ",
            font=FONT_BODY,
            fg=COLORS["text2"],
            bg=COLORS["card2"],
            activebackground=COLORS["border"],
            relief="flat",
            padx=10,
            pady=6,
            cursor="hand2",
            bd=0,
            command=self._clear_live_feed,
        )
        live_clr_btn.pack(side="left")

        self._live_status_lbl = tk.Label(
            ctrl_inner,
            text="⚫  Stopped — Poll interval: 2s",
            font=FONT_LABEL,
            fg=COLORS["text2"],
            bg=COLORS["card"],
        )
        self._live_status_lbl.pack(side="right")

        scope_lbl = tk.Label(
            parent,
            text="Watchers:  📁 File (~/Downloads, ~/Desktop, ~/Documents)   |   🔌 USB Drives   |   📋 System & Application Event Logs",
            font=("Segoe UI", 8),
            fg=COLORS["text2"],
            bg=COLORS["bg"],
        )
        scope_lbl.pack(anchor="w", padx=20, pady=(0, 6))

        feed_frame = tk.Frame(parent, bg=COLORS["bg"])
        feed_frame.pack(fill="both", expand=True, padx=20, pady=(0, 12))

        feed_hdr = tk.Frame(feed_frame, bg=COLORS["card2"], pady=6)
        feed_hdr.pack(fill="x")
        tk.Label(
            feed_hdr,
            text="  📡  Real-Time Forensic Event Feed",
            font=("Segoe UI", 9, "bold"),
            fg=COLORS["text2"],
            bg=COLORS["card2"],
        ).pack(side="left", padx=8)

        self._live_feed = scrolledtext.ScrolledText(
            feed_frame,
            font=FONT_MONO,
            bg="#010409",
            fg="#C9D1D9",
            insertbackground=COLORS["accent"],
            selectbackground=COLORS["accent"],
            relief="flat",
            bd=0,
            wrap="word",
            state="disabled",
            padx=10,
            pady=8,
        )
        self._live_feed.pack(fill="both", expand=True)

        self._live_feed.tag_config("green", foreground="#3FB950")
        self._live_feed.tag_config("red",   foreground="#F85149")
        self._live_feed.tag_config("yellow", foreground="#D29922")
        self._live_feed.tag_config("info",  foreground="#58A6FF")
        self._live_feed.tag_config("dim",   foreground="#484F58")

        self._live_log("Live Monitor ready. Click 'Start Live Monitor' to begin 2s polling.", "info")

    def _live_log(self, text, tag=None):
        def _do():
            try:
                self._live_feed.config(state="normal")
                ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if tag:
                    self._live_feed.insert("end", f"[{ts}] {text}\n", tag)
                else:
                    self._live_feed.insert("end", f"[{ts}] {text}\n")
                self._live_feed.see("end")
                self._live_feed.config(state="disabled")
            except tk.TclError:
                pass
        try:
            self.after(0, _do)
        except tk.TclError:
            pass

    def _clear_live_feed(self):
        self._live_feed.config(state="normal")
        self._live_feed.delete("1.0", "end")
        self._live_feed.config(state="disabled")

    def _toggle_live_monitor(self):
        if self._live_running:
            self._stop_live_monitor()
        else:
            self._start_live_monitor()

    def _start_live_monitor(self):
        if self._live_running:
            return
        self._live_running = True
        self._live_stop_event.clear()
        self._live_toggle_btn.config(
            text="  ■  Stop Live Monitor  ",
            bg=COLORS["danger"],
            activebackground="#c0392b",
        )
        self._live_status_lbl.config(text="🟢  Monitoring active (2s poll)", fg=COLORS["success"])
        self._live_log("--- Live Monitor STARTED (File, USB, Event Logs) ---", "info")

        self._live_threads = [
            threading.Thread(target=self._file_watcher_loop, daemon=True),
            threading.Thread(target=self._usb_watcher_loop, daemon=True),
            threading.Thread(target=self._event_watcher_loop, daemon=True),
        ]
        for t in self._live_threads:
            t.start()

    def _stop_live_monitor(self):
        if not self._live_running:
            return
        self._live_running = False
        self._live_stop_event.set()
        self._live_toggle_btn.config(
            text="  ▶  Start Live Monitor  ",
            bg=COLORS["btn_primary"],
            activebackground=COLORS["btn_hover"],
        )
        self._live_status_lbl.config(text="⚫  Stopped — Poll interval: 2s", fg=COLORS["text2"])
        self._live_log("--- Live Monitor STOPPED ---", "dim")

    @staticmethod
    def _snapshot_files(watch_dirs):
        snap = {}
        for base in watch_dirs:
            if not os.path.isdir(base):
                continue
            for root, _dirs, files in os.walk(base):
                for name in files:
                    path = os.path.join(root, name)
                    try:
                        snap[path] = os.stat(path).st_mtime
                    except OSError:
                        pass
        return snap

    def _file_watcher_loop(self):
        watch_dirs = [os.path.expanduser(d) for d in ("~/Downloads", "~/Desktop", "~/Documents")]
        prev = self._snapshot_files(watch_dirs)
        self._live_log(f"[FILE WATCHER] Baseline established ({len(prev)} files across 3 folders).", "dim")
        while not self._live_stop_event.wait(2.0):
            curr = self._snapshot_files(watch_dirs)
            prev_keys = set(prev.keys())
            curr_keys = set(curr.keys())
            for p in sorted(curr_keys - prev_keys):
                self._live_log(f"[FILE CREATED]  {p}", "green")
            for p in sorted(prev_keys - curr_keys):
                self._live_log(f"[FILE DELETED]  {p}", "red")
            for p in sorted(curr_keys & prev_keys):
                if curr[p] != prev[p]:
                    self._live_log(f"[FILE MODIFIED] {p}", "yellow")
            prev = curr

    @staticmethod
    def _get_removable_drives():
        drives = set()
        system = platform.system()
        if system == "Windows":
            try:
                mask = ctypes.windll.kernel32.GetLogicalDrives()
                for idx in range(26):
                    if mask & (1 << idx):
                        letter = chr(65 + idx)
                        root = f"{letter}:\\"
                        dtype = ctypes.windll.kernel32.GetDriveTypeW(root)
                        if dtype == 2:  # DRIVE_REMOVABLE
                            drives.add(root)
            except Exception:
                pass
        else:
            try:
                sys_block = "/sys/block"
                if os.path.isdir(sys_block):
                    for dev in os.listdir(sys_block):
                        rem_file = os.path.join(sys_block, dev, "removable")
                        try:
                            with open(rem_file, "r", encoding="utf-8") as f:
                                if f.read().strip() == "1":
                                    drives.add(f"/dev/{dev}")
                        except OSError:
                            pass
                if not drives:
                    res = subprocess.run(
                        ["lsblk", "-ndo", "NAME,TRAN"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        universal_newlines=True,
                        shell=False,
                        timeout=5,
                    )
                    if res.returncode == 0:
                        for line in res.stdout.splitlines():
                            parts = line.split()
                            if len(parts) >= 2 and parts[1].lower() == "usb":
                                drives.add(f"/dev/{parts[0]}")
            except Exception:
                pass
        return drives

    def _usb_watcher_loop(self):
        prev = self._get_removable_drives()
        self._live_log(f"[USB WATCHER]  Baseline: {len(prev)} removable drive(s).", "dim")
        while not self._live_stop_event.wait(2.0):
            curr = self._get_removable_drives()
            for d in sorted(curr - prev):
                self._live_log(f"[USB PLUG-IN]   Removable drive connected: {d}", "green")
            for d in sorted(prev - curr):
                self._live_log(f"[USB PLUG-OUT]  Removable drive removed: {d}", "red")
            prev = curr

    @staticmethod
    def _poll_recent_events():
        events = []
        system = platform.system()
        if system == "Windows":
            for channel in ("System", "Application"):
                try:
                    res = subprocess.run(
                        ["wevtutil", "qe", channel, "/c:10", "/rd:true", "/f:xml"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        universal_newlines=True,
                        shell=False,
                        timeout=8,
                    )
                    if res.returncode != 0 or not res.stdout.strip():
                        continue
                    xml_text = res.stdout.encode("utf-8", errors="surrogatepass").decode("utf-8", errors="replace")
                    root = ET.fromstring(f"<Events>{xml_text}</Events>")
                    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
                    for ev in root.findall(f"{ns}Event"):
                        sys_node = ev.find(f"{ns}System")
                        if sys_node is None:
                            continue
                        rec_el = sys_node.find(f"{ns}EventRecordID")
                        eid_el = sys_node.find(f"{ns}EventID")
                        prov_el = sys_node.find(f"{ns}Provider")
                        tc_el = sys_node.find(f"{ns}TimeCreated")
                        rec_id = rec_el.text if rec_el is not None and rec_el.text else ""
                        eid = eid_el.text if eid_el is not None and eid_el.text else "?"
                        prov = prov_el.attrib.get("Name", "Unknown") if prov_el is not None else "Unknown"
                        tc = tc_el.attrib.get("SystemTime", "")[:19].replace("T", " ") if tc_el is not None else ""
                        key = f"{channel}:{rec_id or (eid + tc + prov)}"
                        events.append((key, f"[EVENT LOG]    [{channel}] ID={eid} | {prov} | {tc}"))
                except Exception:
                    pass
        else:
            try:
                res = subprocess.run(
                    ["journalctl", "-n", "10", "-o", "short-iso", "--no-pager"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    shell=False,
                    timeout=8,
                )
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        line = line.strip()
                        if line and not line.startswith("--"):
                            events.append((line, f"[EVENT LOG]    {line}"))
            except Exception:
                pass
        return events

    def _event_watcher_loop(self):
        seen = collections.deque(maxlen=1000)
        seen_set = set()
        for key, _msg in self._poll_recent_events():
            if key not in seen_set:
                seen.append(key)
                seen_set.add(key)
        self._live_log(f"[EVENT WATCHER] Baseline seeded ({len(seen_set)} recent events).", "dim")
        while not self._live_stop_event.wait(2.0):
            batch = self._poll_recent_events()
            for key, msg in reversed(batch):
                if key not in seen_set:
                    if len(seen) == seen.maxlen:
                        old = seen.popleft()
                        seen_set.discard(old)
                    seen.append(key)
                    seen_set.add(key)
                    self._live_log(msg, "yellow")


# ============================================================
# ENTRY POINT
# ============================================================
def main():
    app = ForensicGUI()
    app.mainloop()


if __name__ == "__main__":
    main()

