#!/usr/bin/env python3
"""
ASM Enterprise GUI  --  asm_gui.py
Tkinter front-end for asm_enterprise.py

Usage:  python3 asm_gui.py
Keys:   saved to ~/.asm_config.json (chmod 600)
"""

import json
import os
import queue
import re
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from tkinter import (
    BooleanVar, END, HORIZONTAL, VERTICAL, LEFT, BOTH, X, Y, RIGHT,
    WORD, DISABLED, NORMAL, StringVar, Text, Scrollbar,
    messagebox, filedialog, IntVar
)
import tkinter as tk
import tkinter.ttk as ttk

CONFIG_FILE = Path.home() / ".asm_config.json"
SCRIPT_PATH = Path(__file__).parent / "asm_enterprise.py"
ANSI_RE     = re.compile(r'\x1b\[[0-9;]*[mGKHF]')

def strip_ansi(t): return ANSI_RE.sub("", t)

PHASES = {
    1:  ("Seed Data Collection",              "mixed"),
    2:  ("CT & Passive Recon",                "mixed"),
    3:  ("Active DNS Enumeration",            "mixed"),
    4:  ("IP & ASN Mapping",                  "mixed"),
    5:  ("Web Validation & TLS",              "mixed"),
    6:  ("CNAME Dangling Analysis",           "PASSIVE"),
    7:  ("Cloud Asset Enumeration",           "mixed"),
    8:  ("JS Collection, Endpoints & Secret Scanning", "mixed"),
    9:  ("Certificate Monitoring",            "mixed"),
    10: ("Reverse PTR Sweeps",                "PASSIVE"),
    11: ("DNS Permutation",                   "PASSIVE"),
    12: ("Favicon Hash Pivoting",             "PASSIVE"),
    13: ("DMARC / SPF / DKIM",               "PASSIVE"),
    14: ("Historical DNS",                    "PASSIVE"),
    15: ("Email Harvesting",                  "PASSIVE"),
    16: ("Paste Site Monitoring",             "PASSIVE"),
    17: ("Credential & Leak Monitoring",      "mixed"),
    18: ("Reverse Whois",                     "PASSIVE"),
    19: ("Digital Footprint & Shadow Assets", "PASSIVE"),
}
PASSIVE_SET = {1, 2, 4, 6, 10, 11, 12, 13, 14, 15, 16, 18, 19}

BG        = "#1e1e2e"
BG2       = "#2a2a3e"
BG3       = "#313145"
BG_SASH   = "#44445a"
ACCENT    = "#89b4fa"
ACCENT2   = "#cba6f7"
GREEN     = "#a6e3a1"
YELLOW    = "#f9e2af"
RED       = "#f38ba8"
CYAN      = "#89dceb"
WHITE     = "#cdd6f4"
MUTED     = "#6c7086"
FONT_MONO = ("Courier New", 10)
FONT_UI   = ("DejaVu Sans", 10)
FONT_HEAD = ("DejaVu Sans", 11, "bold")
FONT_SM   = ("DejaVu Sans", 9)


def load_config():
    try:
        if CONFIG_FILE.exists():
            return json.loads(CONFIG_FILE.read_text())
    except Exception:
        pass
    return {}


def save_config(data):
    try:
        CONFIG_FILE.write_text(json.dumps(data, indent=2))
        CONFIG_FILE.chmod(0o600)
    except Exception as exc:
        messagebox.showerror("Save Error", f"Could not save config:\n{exc}")


class ContextMenu:
    """Right-click Cut/Copy/Paste/Select All for any widget."""
    def __init__(self, widget):
        self.w = widget
        m = tk.Menu(widget, tearoff=0, bg=BG3, fg=WHITE,
                    activebackground=ACCENT, activeforeground=BG, relief="flat", bd=1)
        m.add_command(label="Cut",        command=lambda: widget.event_generate("<<Cut>>"))
        m.add_command(label="Copy",       command=lambda: widget.event_generate("<<Copy>>"))
        m.add_command(label="Paste",      command=lambda: widget.event_generate("<<Paste>>"))
        m.add_separator()
        m.add_command(label="Select All", command=self._sel_all)
        self.menu = m
        widget.bind("<Button-3>", self._show)

    def _show(self, e):
        try:
            self.menu.tk_popup(e.x_root, e.y_root)
        finally:
            self.menu.grab_release()

    def _sel_all(self):
        try:
            if isinstance(self.w, Text):
                self.w.tag_add("sel", "1.0", END)
            else:
                self.w.select_range(0, END)
                self.w.icursor(END)
        except Exception:
            pass


class ASMGui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ASM Enterprise v2.0")
        self.geometry("1440x880")
        self.minsize(1100, 720)
        self.configure(bg=BG)

        self._process         = None
        self._log_queue       = queue.Queue()
        self._running         = False
        self._phase_vars      = {}
        self._phases_selected = []
        self._phases_done     = set()
        self._current_phase   = 0
        self._debug_log_path  = ""
        self._output_dir      = ""
        self._config_tmp      = ""

        self._saved = load_config()
        self._build_styles()
        self._build_ui()
        self._load_saved_keys()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(60, self._poll_queue)

    def _build_styles(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".",             background=BG,  foreground=WHITE, font=FONT_UI)
        s.configure("TFrame",        background=BG)
        s.configure("P.TFrame",      background=BG2)
        s.configure("TLabel",        background=BG2, foreground=WHITE, font=FONT_UI)
        s.configure("H.TLabel",      background=BG2, foreground=ACCENT, font=FONT_HEAD)
        s.configure("M.TLabel",      background=BG2, foreground=MUTED,  font=FONT_UI)
        s.configure("S.TLabel",      background=BG2, foreground=MUTED,  font=FONT_SM)
        s.configure("TEntry",        fieldbackground=BG3, foreground=WHITE,
                    insertcolor=WHITE, relief="flat", font=FONT_MONO)
        s.configure("TNotebook",     background=BG2, bordercolor=BG3, tabmargins=[0,0,0,0])
        s.configure("TNotebook.Tab", background=BG3, foreground=MUTED, padding=[12,5], font=FONT_UI)
        s.map("TNotebook.Tab",
              background=[("selected", BG2)], foreground=[("selected", WHITE)])
        s.configure("Run.TButton",   background=GREEN, foreground="#1e1e2e",
                    font=("DejaVu Sans",11,"bold"), padding=[16,6], relief="flat")
        s.configure("Stop.TButton",  background=RED,   foreground="#1e1e2e",
                    font=("DejaVu Sans",11,"bold"), padding=[16,6], relief="flat")
        s.configure("Sec.TButton",   background=BG3,   foreground=WHITE,
                    font=FONT_UI, padding=[8,4], relief="flat")
        s.configure("TCheckbutton",  background=BG2, foreground=WHITE, font=FONT_UI)
        s.map("TCheckbutton",        background=[("active", BG2)])
        s.configure("TScrollbar",    background=BG3, troughcolor=BG2,
                    bordercolor=BG3, arrowcolor=MUTED, relief="flat")
        s.configure("Prog.Horizontal.TProgressbar",
                    background=ACCENT, troughcolor=BG3,
                    bordercolor=BG3, lightcolor=ACCENT, darkcolor=ACCENT)

    def _build_ui(self):
        tb = ttk.Frame(self, style="P.TFrame")
        tb.pack(fill=X)
        ttk.Label(tb, text="  ASM Enterprise", style="H.TLabel").pack(side=LEFT, pady=8)
        ttk.Label(tb, text="v2.0  —  Attack Surface Management  —  Financial Services",
                  style="M.TLabel").pack(side=LEFT, padx=8)
        self._status_var = StringVar(value="● Ready")
        self._status_lbl = ttk.Label(tb, textvariable=self._status_var,
                                      foreground=GREEN, background=BG2, font=FONT_UI)
        self._status_lbl.pack(side=RIGHT, padx=16)

        # Resizable paned window -- drag the sash handles to resize panels
        self._pw = tk.PanedWindow(self, orient=tk.HORIZONTAL,
                                   bg=BG_SASH, sashwidth=6, sashpad=2,
                                   showhandle=True, handlesize=10, handlepad=100,
                                   relief="flat", bd=0)
        self._pw.pack(fill=BOTH, expand=True, padx=8, pady=4)

        cfg_f   = ttk.Frame(self._pw, style="P.TFrame")
        phase_f = ttk.Frame(self._pw, style="P.TFrame")
        log_f   = ttk.Frame(self._pw, style="P.TFrame")

        self._pw.add(cfg_f,   width=370, minsize=260, stretch="always")
        self._pw.add(phase_f, width=305, minsize=255, stretch="always")
        self._pw.add(log_f,              minsize=380, stretch="always")

        self._build_config_panel(cfg_f)
        self._build_phase_panel(phase_f)
        self._build_log_panel(log_f)
        self._build_bottom_bar()

    def _entry(self, parent, row, label, password=False):
        ttk.Label(parent, text=label, style="M.TLabel").grid(
            row=row, column=0, sticky="w", padx=8, pady=(7,0))
        var = StringVar()
        e = ttk.Entry(parent, textvariable=var, show="*" if password else "",
                      font=FONT_MONO, width=30)
        e.grid(row=row+1, column=0, sticky="ew", padx=8, pady=(2,0))
        ContextMenu(e)
        return var, e

    def _build_config_panel(self, outer):
        outer.columnconfigure(0, weight=1)
        ttk.Label(outer, text="Configuration", style="H.TLabel").pack(
            anchor="w", padx=8, pady=(8,4))
        nb = ttk.Notebook(outer)
        nb.pack(fill=BOTH, expand=True, padx=4, pady=(0,4))

        # Scope tab
        st = ttk.Frame(nb, style="P.TFrame")
        st.columnconfigure(0, weight=1)
        nb.add(st, text="  Scope  ")
        r = 0
        ttk.Label(st,
                  text="Root Domain(s)  *required*  (bare domain, e.g. target.com -- no https://)",
                  style="M.TLabel",
                  wraplength=320).grid(row=r, column=0, sticky="w", padx=8, pady=(8,0)); r+=1
        self._domains_txt = Text(st, height=3, bg=BG3, fg=WHITE, font=FONT_MONO,
                                 insertbackground=WHITE, relief="flat", wrap=WORD)
        self._domains_txt.grid(row=r, column=0, sticky="ew", padx=8, pady=(2,0))
        ContextMenu(self._domains_txt); r+=1

        ttk.Label(st, text="IP / CIDR Ranges  (optional, comma-sep)",
                  style="M.TLabel").grid(row=r, column=0, sticky="w", padx=8, pady=(7,0)); r+=1
        self._ipranges_txt = Text(st, height=2, bg=BG3, fg=WHITE, font=FONT_MONO,
                                  insertbackground=WHITE, relief="flat", wrap=WORD)
        self._ipranges_txt.grid(row=r, column=0, sticky="ew", padx=8, pady=(2,0))
        ContextMenu(self._ipranges_txt); r+=1

        self._org_var,    _ = self._entry(st, r, "Organization Name  (as in WHOIS/certs)"); r+=2
        self._asn_var,    _ = self._entry(st, r, "ASN  (e.g. AS12345)"); r+=2
        self._github_var, _ = self._entry(st, r, "GitHub Org Handle"); r+=2

        ttk.Label(st, text="Output Directory  (full path, blank = auto-named under ./output/)",
                  style="M.TLabel").grid(row=r, column=0, sticky="w", padx=8, pady=(7,0)); r+=1
        of = ttk.Frame(st, style="P.TFrame")
        of.grid(row=r, column=0, sticky="ew", padx=8, pady=(2,0))
        of.columnconfigure(0, weight=1)
        self._outdir_var = StringVar()
        oe = ttk.Entry(of, textvariable=self._outdir_var, font=FONT_MONO)
        oe.grid(row=0, column=0, sticky="ew")
        ContextMenu(oe)
        ttk.Button(of, text="Browse", style="Sec.TButton",
                   command=self._browse_dir).grid(row=0, column=1, padx=(4,0))
        r += 1
        ttk.Label(st, text="Leave blank to auto-name (strongly recommended)",
                  style="S.TLabel").grid(row=r, column=0, sticky="w", padx=8, pady=(2,0))
        st.rowconfigure(r+1, weight=1)

        # API Keys tab
        kt = ttk.Frame(nb, style="P.TFrame")
        kt.columnconfigure(0, weight=1)
        nb.add(kt, text="  API Keys  ")
        r = 0
        ttk.Label(kt, text="Saved to ~/.asm_config.json (chmod 600 on save)",
                  style="S.TLabel").grid(row=r, column=0, sticky="w", padx=8, pady=(8,0)); r+=1
        self._shodan_var,        _ = self._entry(kt, r, "Shodan API Key",         password=True); r+=2
        self._censys_id_var,     _ = self._entry(kt, r, "Censys API ID",          password=True); r+=2
        self._censys_secret_var, _ = self._entry(kt, r, "Censys API Secret",      password=True); r+=2
        self._st_key_var,        _ = self._entry(kt, r, "SecurityTrails API Key", password=True); r+=2
        ttk.Separator(kt, orient=HORIZONTAL).grid(
            row=r, column=0, sticky="ew", padx=8, pady=8); r+=1
        bf = ttk.Frame(kt, style="P.TFrame")
        bf.grid(row=r, column=0, sticky="w", padx=8)
        ttk.Button(bf, text="Save Keys",  style="Sec.TButton",
                   command=self._save_keys).pack(side=LEFT, padx=(0,6))
        ttk.Button(bf, text="Clear Keys", style="Sec.TButton",
                   command=self._clear_keys).pack(side=LEFT, padx=(0,6))
        ttk.Button(bf, text="Test Keys",  style="Sec.TButton",
                   command=self._test_keys).pack(side=LEFT)
        r += 1
        ttk.Label(kt,
                  text="'Test Keys' verifies each key against its API and reports\n"
                       "your plan tier and permission level. Free Shodan dev/edu\n"
                       "plans cannot run org: or http.html: search queries (403).",
                  style="S.TLabel", wraplength=300).grid(
            row=r, column=0, sticky="w", padx=8, pady=(8,0))
        kt.rowconfigure(r+1, weight=1)

    def _build_phase_panel(self, outer):
        outer.rowconfigure(2, weight=1)
        outer.columnconfigure(0, weight=1)
        ttk.Label(outer, text="Phase Selection", style="H.TLabel").grid(
            row=0, column=0, sticky="w", padx=8, pady=(8,4))

        # Button row -- grid ensures all 3 are always visible even in narrow panel
        bf = ttk.Frame(outer, style="P.TFrame")
        bf.grid(row=1, column=0, sticky="ew", padx=8, pady=(0,6))
        bf.columnconfigure((0,1,2), weight=1)
        for col, (lbl, cmd) in enumerate([("All", self._sel_all),
                                           ("Passive", self._sel_passive),
                                           ("None",    self._sel_none)]):
            ttk.Button(bf, text=lbl, style="Sec.TButton", command=cmd).grid(
                row=0, column=col, sticky="ew",
                padx=(0 if col == 0 else 3, 0))

        # Scrollable checkbox list
        cf = ttk.Frame(outer, style="P.TFrame")
        cf.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0,8))
        cf.rowconfigure(0, weight=1)
        cf.columnconfigure(0, weight=1)

        cv = tk.Canvas(cf, bg=BG2, highlightthickness=0)
        vs = ttk.Scrollbar(cf, orient=VERTICAL, command=cv.yview)
        cv.configure(yscrollcommand=vs.set)
        cv.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")

        self._plist = ttk.Frame(cv, style="P.TFrame")
        win = cv.create_window((0,0), window=self._plist, anchor="nw")

        def _upd(e):
            cv.configure(scrollregion=cv.bbox("all"))
            cv.itemconfig(win, width=e.width)
        self._plist.bind("<Configure>", _upd)
        cv.bind("<Configure>", lambda e: cv.itemconfig(win, width=e.width))
        cv.bind("<MouseWheel>", lambda e: cv.yview_scroll(
            -1 if e.delta > 0 else 1, "units"))
        cv.bind("<Button-4>", lambda e: cv.yview_scroll(-1, "units"))
        cv.bind("<Button-5>", lambda e: cv.yview_scroll(1, "units"))

        for num, (label, mode) in PHASES.items():
            rf = ttk.Frame(self._plist, style="P.TFrame")
            rf.pack(fill=X, pady=1, padx=2)
            var = BooleanVar(value=True)
            self._phase_vars[num] = var
            ttk.Checkbutton(rf, variable=var).pack(side=LEFT)
            tk.Label(rf, text=f"{num:2d}.", bg=BG2, fg=MUTED,
                     font=FONT_MONO, width=3).pack(side=LEFT)
            tk.Label(rf, text=label, bg=BG2, fg=WHITE,
                     font=FONT_UI, anchor="w").pack(side=LEFT, fill=X, expand=True)
            mc = ACCENT if mode == "PASSIVE" else YELLOW
            tk.Label(rf, text=mode, bg=BG2, fg=mc,
                     font=("DejaVu Sans",8), width=8).pack(side=RIGHT, padx=4)

    def _build_log_panel(self, outer):
        outer.rowconfigure(1, weight=1)
        outer.columnconfigure(0, weight=1)

        hdr = ttk.Frame(outer, style="P.TFrame")
        hdr.grid(row=0, column=0, sticky="ew", padx=8, pady=(8,4))
        ttk.Label(hdr, text="Live Output", style="H.TLabel").pack(side=LEFT)
        for lbl, cmd in [("Save Log", self._save_log), ("Clear", self._clear_log)]:
            ttk.Button(hdr, text=lbl, style="Sec.TButton",
                       command=cmd).pack(side=RIGHT, padx=(6,0))
        self._debug_lbl = ttk.Label(hdr, text="", style="S.TLabel", foreground=MUTED)
        self._debug_lbl.pack(side=RIGHT, padx=(0,12))

        lf = ttk.Frame(outer, style="P.TFrame")
        lf.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0,4))
        lf.rowconfigure(0, weight=1)
        lf.columnconfigure(0, weight=1)

        self._log = Text(lf, bg=BG, fg=WHITE, font=FONT_MONO, state=DISABLED,
                         wrap=WORD, relief="flat", insertbackground=WHITE,
                         selectbackground=BG3, cursor="arrow")
        vs = ttk.Scrollbar(lf, orient=VERTICAL, command=self._log.yview)
        self._log.configure(yscrollcommand=vs.set)
        self._log.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        ContextMenu(self._log)

        for tag, fg in [
            ("crit", RED), ("err", RED), ("warn", YELLOW), ("ok", GREEN),
            ("info", CYAN), ("sec", ACCENT2), ("dim", MUTED), ("norm", WHITE),
            ("cmd", ACCENT), ("test_ok", "#a6e3a1"), ("test_fail", RED),
            ("test_warn", YELLOW), ("test_note", MUTED),
        ]:
            self._log.tag_config(tag, foreground=fg)

    def _build_bottom_bar(self):
        bar = ttk.Frame(self, style="P.TFrame")
        bar.pack(fill=X, padx=8, pady=(2,8))

        self._run_btn  = ttk.Button(bar, text="▶  RUN SCAN", style="Run.TButton",
                                     command=self._run)
        self._stop_btn = ttk.Button(bar, text="■  STOP", style="Stop.TButton",
                                     command=self._stop, state=DISABLED)
        self._run_btn.pack(side=LEFT, padx=(0,8))
        self._stop_btn.pack(side=LEFT, padx=(0,16))

        self._debug_var = BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Debug Mode",
                        variable=self._debug_var).pack(side=LEFT, padx=(0,20))

        pf = ttk.Frame(bar, style="P.TFrame")
        pf.pack(side=LEFT, fill=X, expand=True)

        self._phase_lbl = ttk.Label(pf, text="", style="M.TLabel", foreground=ACCENT)
        self._phase_lbl.pack(anchor="w")

        self._prog_var = IntVar(value=0)
        self._prog = ttk.Progressbar(pf, orient=HORIZONTAL, mode="determinate",
                                      variable=self._prog_var,
                                      style="Prog.Horizontal.TProgressbar")
        self._prog.pack(fill=X, pady=(2,0))

        self._prog_lbl = ttk.Label(pf, text="", style="S.TLabel")
        self._prog_lbl.pack(anchor="w")

    # Key management
    def _load_saved_keys(self):
        c = self._saved
        self._shodan_var.set(       c.get("shodan_key",""))
        self._censys_id_var.set(    c.get("censys_id",""))
        self._censys_secret_var.set(c.get("censys_secret",""))
        self._st_key_var.set(       c.get("securitytrails_key",""))

    def _save_keys(self):
        c = load_config()
        c.update({
            "shodan_key":         self._shodan_var.get().strip(),
            "censys_id":          self._censys_id_var.get().strip(),
            "censys_secret":      self._censys_secret_var.get().strip(),
            "securitytrails_key": self._st_key_var.get().strip(),
        })
        save_config(c)
        messagebox.showinfo("Saved", f"Keys saved to:\n{CONFIG_FILE}")

    def _clear_keys(self):
        if messagebox.askyesno("Clear Keys", "Clear all saved API keys?"):
            for v in [self._shodan_var, self._censys_id_var,
                      self._censys_secret_var, self._st_key_var]:
                v.set("")
            save_config({})

    def _test_keys(self):
        """Test each API key against its service. Runs in background thread."""
        self._log_write("\n── API Key Test ──────────────────────────────────────\n", "sec")

        shodan_key    = self._shodan_var.get().strip()
        censys_id     = self._censys_id_var.get().strip()
        censys_secret = self._censys_secret_var.get().strip()
        st_key        = self._st_key_var.get().strip()

        def _run():
            import requests as _req

            # Shodan
            self._log_queue.put(("log", "\n  Shodan\n", "sec"))
            if shodan_key:
                try:
                    import shodan as _sh
                    api  = _sh.Shodan(shodan_key)
                    info = api.info()
                    plan  = info.get("plan", "unknown")
                    qcred = info.get("query_credits", "?")
                    scred = info.get("scan_credits",  "?")
                    self._log_queue.put(("log",
                        f"  ✓  Authenticated\n"
                        f"     Plan: {plan}  |  "
                        f"Query credits: {qcred}  |  Scan credits: {scred}\n",
                        "test_ok"))
                    if plan in ("dev", "edu", ""):
                        self._log_queue.put(("log",
                            "  ⚠  Free/dev tier: org: and http.html: search queries require\n"
                            "     a paid plan -- those calls will return 403 Forbidden.\n"
                            "     SSL cert and host lookups work on free tier.\n",
                            "test_warn"))
                except ImportError:
                    self._log_queue.put(("log",
                        "  ✗  shodan library not installed\n"
                        "     Fix: pip3 install shodan --break-system-packages\n",
                        "test_fail"))
                except Exception as e:
                    self._log_queue.put(("log", f"  ✗  {e}\n", "test_fail"))
            else:
                self._log_queue.put(("log", "  –  No key provided\n", "test_note"))

            # Censys
            self._log_queue.put(("log", "\n  Censys\n", "sec"))
            if censys_id and censys_secret:
                try:
                    r = _req.get("https://search.censys.io/api/v1/account",
                                 auth=(censys_id, censys_secret),
                                 timeout=10, verify=False)
                    if r.status_code == 200:
                        d = r.json()
                        allow = d.get("allowances", {})
                        self._log_queue.put(("log",
                            f"  ✓  Authenticated\n"
                            f"     Email: {d.get('email','?')}  |  "
                            f"Queries/month: {allow.get('queryCreditsAllowed','?')}\n",
                            "test_ok"))
                    elif r.status_code == 401:
                        self._log_queue.put(("log",
                            "  ✗  Invalid ID or secret (401 Unauthorized)\n", "test_fail"))
                    else:
                        self._log_queue.put(("log",
                            f"  ✗  HTTP {r.status_code}: {r.text[:80]}\n", "test_fail"))
                except Exception as e:
                    self._log_queue.put(("log", f"  ✗  {e}\n", "test_fail"))
            elif censys_id or censys_secret:
                self._log_queue.put(("log",
                    "  ⚠  Provide both API ID and API Secret\n", "test_warn"))
            else:
                self._log_queue.put(("log", "  –  No credentials provided\n", "test_note"))

            # SecurityTrails
            self._log_queue.put(("log", "\n  SecurityTrails\n", "sec"))
            if st_key:
                try:
                    r = _req.get("https://api.securitytrails.com/v1/ping",
                                 headers={"APIKEY": st_key},
                                 timeout=10, verify=False)
                    if r.status_code == 200:
                        self._log_queue.put(("log",
                            "  ✓  Authenticated  |  Ping successful\n", "test_ok"))
                    elif r.status_code == 401:
                        self._log_queue.put(("log",
                            "  ✗  Invalid API key (401)\n", "test_fail"))
                    else:
                        self._log_queue.put(("log",
                            f"  ✗  HTTP {r.status_code}: {r.text[:80]}\n", "test_fail"))
                except Exception as e:
                    self._log_queue.put(("log", f"  ✗  {e}\n", "test_fail"))
            else:
                self._log_queue.put(("log", "  –  No key provided\n", "test_note"))

            self._log_queue.put(("log",
                "\n── End API Key Test ──────────────────────────────────\n\n", "sec"))

        threading.Thread(target=_run, daemon=True).start()

    # Phase selection
    def _sel_all(self):
        for v in self._phase_vars.values(): v.set(True)

    def _sel_none(self):
        for v in self._phase_vars.values(): v.set(False)

    def _sel_passive(self):
        for n, v in self._phase_vars.items(): v.set(n in PASSIVE_SET)

    def _browse_dir(self):
        d = filedialog.askdirectory(title="Select Output Directory")
        if d: self._outdir_var.set(d)

    # Scan execution
    def _run(self):
        if not SCRIPT_PATH.exists():
            messagebox.showerror("File Not Found",
                f"asm_enterprise.py not found:\n{SCRIPT_PATH}\n\n"
                "Both files must be in the same directory.")
            return
        if SCRIPT_PATH.resolve() == Path(__file__).resolve():
            messagebox.showerror("Wrong File",
                "SCRIPT_PATH points to this GUI file.\n"
                "Place asm_enterprise.py in the same folder as asm_gui.py.")
            return

        domains_raw = self._domains_txt.get("1.0", END).strip()
        if not domains_raw:
            messagebox.showerror("Missing Input", "Root domain(s) are required.")
            return

        # Warn if output_dir looks like a bare word, not a path
        out_dir = self._outdir_var.get().strip()
        if (out_dir and os.sep not in out_dir and "/" not in out_dir
                and not out_dir.startswith(".") and len(out_dir) < 25):
            if not messagebox.askyesno(
                "Output Directory Check",
                f"Output directory is set to:\n  '{out_dir}'\n\n"
                "This looks like a short word, not a full path.\n"
                "Did you mean to leave it blank (auto-named)?\n\n"
                "Proceed anyway?"
            ):
                return

        selected = sorted(n for n, v in self._phase_vars.items() if v.get())
        if not selected:
            messagebox.showerror("No Phases", "Select at least one phase.")
            return

        if not messagebox.askyesno(
            "Authorization Required",
            "I confirm I have WRITTEN AUTHORIZATION to assess\n"
            "all assets defined in the Scope fields.\n\nProceed?"
        ):
            return

        domains   = [d.strip().lower() for d in re.split(r"[,\n\s]+", domains_raw) if d.strip()]
        ip_raw    = self._ipranges_txt.get("1.0", END).strip()
        ip_ranges = [r.strip() for r in re.split(r"[,\n\s]+", ip_raw) if r.strip()]

        cfg = {
            "domains":            domains,
            "ip_ranges":          ip_ranges,
            "org_name":           self._org_var.get().strip(),
            "asn":                self._asn_var.get().strip(),
            "github_org":         self._github_var.get().strip(),
            "shodan_key":         self._shodan_var.get().strip(),
            "censys_id":          self._censys_id_var.get().strip(),
            "censys_secret":      self._censys_secret_var.get().strip(),
            "securitytrails_key": self._st_key_var.get().strip(),
            "output_dir":         out_dir,
        }

        tf = tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                          delete=False, prefix="asm_cfg_")
        json.dump(cfg, tf); tf.close()
        self._config_tmp = tf.name

        phases_str = ",".join(str(p) for p in selected)
        cmd = [
            sys.executable,
            "-W", "ignore::DeprecationWarning",  # suppress datetime.utcnow and others
            str(SCRIPT_PATH),
            "--config",          tf.name,
            "--phases",          phases_str,
            "--non-interactive",
            "--no-color",
        ]
        if self._debug_var.get():
            cmd.append("--debug")

        # Reset progress tracking
        self._phases_selected = selected
        self._phases_done     = set()
        self._current_phase   = 0
        self._debug_log_path  = ""
        self._output_dir      = ""
        self._prog_var.set(0)
        self._phase_lbl.config(text=f"Starting  (0 / {len(selected)} phases)")
        self._prog_lbl.config(text="")
        self._debug_lbl.config(text="")

        self._log_write(f"CMD: {' '.join(cmd)}\n", "dim")
        self._log_write(f"Domains: {', '.join(domains)}\n", "info")
        self._log_write(f"Phases:  {phases_str}\n\n", "info")

        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,   # KEY: prevents interactive prompt blocking
            text=True,
            bufsize=1,
        )
        self._running = True
        self._run_btn.config(state=DISABLED)
        self._stop_btn.config(state=NORMAL)
        self._set_status("● Running...", YELLOW)

        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        try:
            for line in self._process.stdout:
                self._log_queue.put(("line", line))
        except Exception as exc:
            self._log_queue.put(("line", f"[reader error: {exc}]\n"))
        finally:
            self._process.wait()
            self._log_queue.put(("done", self._process.returncode))

    def _poll_queue(self):
        try:
            while True:
                item = self._log_queue.get_nowait()
                kind = item[0]
                if kind == "line":
                    self._handle_line(item[1])
                elif kind == "log":
                    self._log_write(item[1], item[2] if len(item) > 2 else "")
                elif kind == "done":
                    self._on_done(item[1])
                    break
        except queue.Empty:
            pass
        self.after(60, self._poll_queue)

    def _handle_line(self, raw: str):
        clean = strip_ansi(raw)
        if clean.startswith("ASM_OUTPUT_DIR="):
            self._output_dir = clean.split("=",1)[1].strip()
            self._log_write(f"Output directory: {self._output_dir}\n", "ok")
            return
        if clean.startswith("ASM_DEBUG_LOG="):
            self._debug_log_path = clean.split("=",1)[1].strip()
            self._debug_lbl.config(text=f"Debug: {self._debug_log_path}")
            return
        if clean.startswith("ASM_COMPLETE="):
            return
        self._check_progress(clean)
        self._log_write(clean)

    def _check_progress(self, line: str):
        m = re.search(r'Phase\s+(\d+)\s*[-–—]', line, re.IGNORECASE)
        if m:
            n = int(m.group(1))
            if n in self._phase_vars and n not in self._phases_done:
                done  = len(self._phases_done)
                total = len(self._phases_selected)
                pct   = int(done / total * 100) if total else 0
                self._prog_var.set(pct)
                name  = PHASES.get(n, ("?",))[0]
                self._phase_lbl.config(
                    text=f"Running Phase {n}: {name}  ({done} / {total} done)")
                self._prog_lbl.config(text=f"{pct}%")
            return
        m2 = re.search(r'Phase\s+(\d+)\s+complete', line, re.IGNORECASE)
        if m2:
            n = int(m2.group(1))
            if n in self._phase_vars:
                self._phases_done.add(n)
                done  = len(self._phases_done)
                total = len(self._phases_selected)
                pct   = int(done / total * 100) if total else 0
                self._prog_var.set(pct)
                self._phase_lbl.config(
                    text=f"Completed Phase {n}  ({done} / {total} phases done)")
                self._prog_lbl.config(text=f"{pct}%")

    def _on_done(self, rc: int):
        self._running = False
        self._run_btn.config(state=NORMAL)
        self._stop_btn.config(state=DISABLED)
        done  = len(self._phases_done)
        total = len(self._phases_selected)
        if rc == 0:
            self._prog_var.set(100)
            self._prog_lbl.config(text="100%")
            self._phase_lbl.config(text=f"Complete  ({done} / {total} phases)")
            self._set_status("● Complete", GREEN)
            self._log_write("\n[Scan complete]\n", "ok")
            if self._output_dir:
                self._log_write(f"Outputs: {self._output_dir}\n", "ok")
        else:
            self._set_status("● Stopped / Error", RED)
            self._log_write(f"\n[Process exited with code {rc}]\n", "warn")
        try:
            if self._config_tmp:
                os.unlink(self._config_tmp)
                self._config_tmp = ""
        except Exception:
            pass

    def _stop(self):
        if self._process and self._running:
            self._process.terminate()
            self._log_write("\n[Stop requested -- SIGTERM sent]\n", "warn")
            self._set_status("● Stopping...", YELLOW)

    def _log_write(self, text: str, force_tag: str = ""):
        tag = force_tag if force_tag else self._tag_for(text)
        self._log.config(state=NORMAL)
        self._log.insert(END, text, tag)
        self._log.see(END)
        self._log.config(state=DISABLED)

    def _tag_for(self, line: str) -> str:
        l = line.lower()
        if "[critical]" in l: return "crit"
        if "[error]" in l:    return "err"
        if "[debug] cmd:" in l: return "cmd"
        if "[!]" in l or "warn" in l: return "warn"
        if "[+]" in l or "complete" in l: return "ok"
        if "[*]" in l:        return "info"
        if "====" in l or "────" in l: return "sec"
        return "norm"

    def _clear_log(self):
        self._log.config(state=NORMAL)
        self._log.delete("1.0", END)
        self._log.config(state=DISABLED)

    def _save_log(self):
        p = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text","*.txt"), ("All","*.*")],
            title="Save Log As")
        if p:
            try:
                Path(p).write_text(self._log.get("1.0", END))
                messagebox.showinfo("Saved", f"Log saved:\n{p}")
            except Exception as exc:
                messagebox.showerror("Error", f"Could not save:\n{exc}")

    def _set_status(self, text: str, colour: str = WHITE):
        self._status_var.set(text)
        self._status_lbl.config(foreground=colour)

    def _on_close(self):
        if self._running:
            if not messagebox.askyesno("Scan Running", "Stop scan and exit?"):
                return
            self._stop()
        self.destroy()


def main():
    if not SCRIPT_PATH.exists():
        print(f"[!] asm_enterprise.py not found: {SCRIPT_PATH}")
        print("    Both files must be in the same directory.")
        sys.exit(1)
    ASMGui().mainloop()


if __name__ == "__main__":
    main()
