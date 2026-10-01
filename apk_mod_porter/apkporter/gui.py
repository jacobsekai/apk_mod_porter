"""Tkinter GUI: inputs, stage checklist, results table with evidence, and a full live log."""
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from . import logutil
from .models import Config
from .pipeline import STAGES, Pipeline
from . import transplant as tp
from . import cert_spoof as cs

SYMBOL = {"pending": "○", "run": "◔", "ok": "✓", "warn": "⚠", "fail": "✗"}
LOG_COLOURS = {"DEBUG": "#8a8f98", "INFO": "#d7dae0", "OK": "#7ee787", "WARNING": "#e3b341", "ERROR": "#ff7b72"}
LEVELS = ["DEBUG", "INFO", "OK", "WARNING", "ERROR"]


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("APK Mod Porting Tool")
        self.geometry("1100x900")
        self.minsize(900, 700)
        self.q = queue.Queue()
        self.v = {k: tk.StringVar() for k in (
            "old_mod", "old_official", "new_official", "symbols_old", "symbols_new",
            "out_dir", "keystore", "apktool", "custom_signer", "custom_signer_args",
            "reference_apk", "target_apk", "ks_pass", "ks_alias",
        )}
        self.v["out_dir"].set(str(Path.cwd() / "output"))
        self.v["ks_pass"].set("android")
        self.v["ks_alias"].set("key0")
        self.apply_thr, self.review_thr = tk.DoubleVar(value=90), tk.DoubleVar(value=70)
        self.apply_review, self.allow_partial = tk.BooleanVar(), tk.BooleanVar()
        self.min_level = tk.StringVar(value="DEBUG")
        self.mode = tk.StringVar(value="patch")
        self.analysis = self.pipeline = None
        self.records = []
        self.busy = False
        self._build_ui()
        self.after(80, self._poll)

    # ---------------------------------------------------------------- layout
    def _build_ui(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(10, 4))

        self.patch_page = ttk.Frame(self.notebook)
        self.generic_transplant_page = ttk.Frame(self.notebook)
        self.sakizu_page = ttk.Frame(self.notebook)
        self.deepmods_page = ttk.Frame(self.notebook)
        self.certspoof_page = ttk.Frame(self.notebook)
        self.notebook.add(self.patch_page, text="Binary Port")
        self.notebook.add(self.generic_transplant_page, text="Generic Transplant")
        self.notebook.add(self.sakizu_page, text="Sakizu")
        self.notebook.add(self.deepmods_page, text="DeepMods")
        self.notebook.add(self.certspoof_page, text="Cert Spoof")

        self._build_patch_page()
        self._build_generic_transplant_page()
        self._build_sakizu_page()
        self._build_deepmods_page()
        self._build_certspoof_page()

    def _build_patch_page(self):
        pad = {"padx": 8, "pady": 3}
        top = ttk.Frame(self.patch_page)
        top.pack(fill="x", padx=10, pady=(10, 4))
        rows = [("Old modded APK", "old_mod", "file"), ("Old official APK (same version the mod was built on)", "old_official", "file"),
                ("New official APK", "new_official", "file"), ("Old build IL2CPP symbols (script.json, optional)", "symbols_old", "json"),
                ("New build IL2CPP symbols (script.json, optional)", "symbols_new", "json"), ("apktool.jar (transplant mode only)", "apktool", "file"), ("Output folder", "out_dir", "dir")]
        top.columnconfigure(1, weight=1)
        for r, (label, key, kind) in enumerate(rows):
            ttk.Label(top, text=label).grid(row=r, column=0, sticky="w", **pad)
            ttk.Entry(top, textvariable=self.v[key]).grid(row=r, column=1, sticky="ew", **pad)
            ttk.Button(top, text="Browse", command=lambda k=key, t=kind: self._browse(k, t)).grid(row=r, column=2, **pad)

        modebar = ttk.Frame(self.patch_page)
        modebar.pack(fill="x", padx=10, pady=(2, 0))
        ttk.Label(modebar, text="Mode").pack(side="left", padx=8)
        for text, val in (("Binary patch port", "patch"), ("Transplant runtime-hook mod", "transplant")):
            ttk.Radiobutton(modebar, text=text, value=val, variable=self.mode, command=self._mode_changed).pack(side="left", padx=6)

        opt = ttk.LabelFrame(self.patch_page, text="Safety and options")
        opt.pack(fill="x", padx=10, pady=4)
        ttk.Label(opt, text="Auto-apply at or above (%)").grid(row=0, column=0, **pad)
        ttk.Spinbox(opt, from_=50, to=100, width=5, textvariable=self.apply_thr).grid(row=0, column=1, **pad)
        ttk.Label(opt, text="Review at or above (%)").grid(row=0, column=2, **pad)
        ttk.Spinbox(opt, from_=30, to=100, width=5, textvariable=self.review_thr).grid(row=0, column=3, **pad)
        ttk.Checkbutton(opt, text="Also apply review-level matches", variable=self.apply_review).grid(row=0, column=4, **pad)
        ttk.Checkbutton(opt, text="Allow partial port (skip unresolved targets)", variable=self.allow_partial).grid(row=0, column=5, **pad)
        ttk.Label(opt, text="Keystore (optional)").grid(row=1, column=0, sticky="w", **pad)
        ttk.Entry(opt, textvariable=self.v["keystore"], width=60).grid(row=1, column=1, columnspan=4, sticky="ew", **pad)
        ttk.Button(opt, text="Browse", command=lambda: self._browse("keystore", "file")).grid(row=1, column=5, sticky="w", **pad)
        ttk.Label(opt, text="Custom APK signer").grid(row=2, column=0, sticky="w", **pad)
        ttk.Entry(opt, textvariable=self.v["custom_signer"], width=60).grid(row=2, column=1, columnspan=4, sticky="ew", **pad)
        ttk.Button(opt, text="Browse", command=lambda: self._browse("custom_signer", "file")).grid(row=2, column=5, sticky="w", **pad)
        ttk.Button(opt, text="Use Uber APK Signer", command=self._preset_uber_apk_signer).grid(row=2, column=6, sticky="w", **pad)
        ttk.Label(opt, text="Signer args").grid(row=3, column=0, sticky="w", **pad)
        ttk.Entry(opt, textvariable=self.v["custom_signer_args"], width=60).grid(row=3, column=1, columnspan=5, sticky="ew", **pad)

        btns = ttk.Frame(self.patch_page)
        btns.pack(fill="x", padx=10, pady=4)
        self.b_analyse = ttk.Button(btns, text="Analyse & Port", command=self.start_analyse)
        self.b_build = ttk.Button(btns, text="Build APK", command=self.start_build, state="disabled")
        self.b_open = ttk.Button(btns, text="Open output folder", command=self.open_out)
        for b in (self.b_analyse, self.b_build, self.b_open):
            b.pack(side="left", padx=4)
        self.progress = ttk.Progressbar(btns, mode="determinate", maximum=1.0)
        self.progress.pack(side="left", fill="x", expand=True, padx=10)

        mid = ttk.Panedwindow(self.patch_page, orient="horizontal")
        mid.pack(fill="both", expand=False, padx=10, pady=4)
        self.stage_frame = ttk.LabelFrame(mid, text="Analysis")
        self.stage_labels = {}
        self._make_stages(STAGES)
        mid.add(self.stage_frame, weight=1)
        rf = ttk.LabelFrame(mid, text="Patch results (double-click for evidence)")
        cols = ("id", "kind", "target", "confidence", "status")
        self.tree = ttk.Treeview(rf, columns=cols, show="headings", height=9)
        for c, w in zip(cols, (50, 60, 330, 90, 160)):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=4, pady=4)
        self.tree.tag_configure("matched", foreground="#1a7f37")
        self.tree.tag_configure("applied", foreground="#1a7f37")
        self.tree.tag_configure("review", foreground="#9a6700")
        self.tree.tag_configure("unmatched", foreground="#cf222e")
        self.tree.bind("<Double-1>", self._show_evidence)
        mid.add(rf, weight=3)

        lf = ttk.LabelFrame(self.patch_page, text="Log")
        lf.pack(fill="both", expand=True, padx=10, pady=(4, 10))
        bar = ttk.Frame(lf)
        bar.pack(fill="x")
        ttk.Label(bar, text="Show from level").pack(side="left", padx=6)
        cb = ttk.Combobox(bar, values=LEVELS, textvariable=self.min_level, width=9, state="readonly")
        cb.pack(side="left")
        cb.bind("<<ComboboxSelected>>", lambda e: self._refilter())
        ttk.Button(bar, text="Clear", command=self._clear_log).pack(side="right", padx=4)
        ttk.Button(bar, text="Save log", command=self.save_log).pack(side="right", padx=4)
        self.log_box = scrolledtext.ScrolledText(lf, height=16, bg="#0d1117", fg="#d7dae0", font=("Consolas", 10), state="disabled", wrap="word")
        self.log_box.pack(fill="both", expand=True, padx=4, pady=4)
        for lv, col in LOG_COLOURS.items():
            self.log_box.tag_configure(lv, foreground=col)

    def _build_generic_transplant_page(self):
        self._build_transplant_page(self.generic_transplant_page, "Generic Transplant", "Run Generic transplant", "generic")

    def _build_sakizu_page(self):
        self._build_transplant_page(self.sakizu_page, "Sakizu", "Run Sakizu transplant", "sakizu")

    def _build_deepmods_page(self):
        self._build_transplant_page(self.deepmods_page, "DeepMods", "Run DeepMods transplant", "deepmods")

    def _build_transplant_page(self, parent, title, action_text, page_key):
        pad = {"padx": 8, "pady": 3}
        outer = ttk.Frame(parent)
        outer.pack(fill="both", expand=True, padx=10, pady=10)

        rows = [("Old official APK (clean baseline)", "old_official", "file"), ("Old modded APK", "old_mod", "file"),
            ("New official APK", "new_official", "file"),
                ("apktool.jar", "apktool", "file"), ("Output folder", "out_dir", "dir"),
                ("Custom APK signer (optional)", "custom_signer", "file"), ("Signer args", "custom_signer_args", "text")]
        for r, (label, key, kind) in enumerate(rows):
            ttk.Label(outer, text=label).grid(row=r, column=0, sticky="w", **pad)
            if key == "custom_signer_args":
                ttk.Entry(outer, textvariable=self.v[key], width=80).grid(row=r, column=1, sticky="ew", **pad)
            else:
                ttk.Entry(outer, textvariable=self.v[key]).grid(row=r, column=1, sticky="ew", **pad)
            if key != "custom_signer_args":
                ttk.Button(outer, text="Browse", command=lambda k=key, t=kind: self._browse(k, t)).grid(row=r, column=2, **pad)

        analysis = ttk.LabelFrame(outer, text="Analysis")
        analysis.grid(row=len(rows), column=0, columnspan=3, sticky="ew", padx=8, pady=(8, 4))
        stage_labels = {}
        for stage in tp.TP_STAGES:
            label_widget = ttk.Label(analysis, text=f"{SYMBOL['pending']} {stage}")
            label_widget.pack(anchor="w", padx=8, pady=1)
            stage_labels[stage] = label_widget
        progress = ttk.Progressbar(analysis, mode="determinate", maximum=1.0)
        progress.pack(fill="x", padx=8, pady=(5, 6))
        setattr(self, f"{page_key}_stage_labels", stage_labels)
        setattr(self, f"{page_key}_progress", progress)

        btns = ttk.Frame(outer)
        btns.grid(row=len(rows) + 1, column=0, columnspan=3, sticky="ew", padx=8, pady=(8, 4))
        ttk.Button(btns, text=action_text, command=lambda p=page_key: self.start_transplant(p)).pack(side="left", padx=4)
        ttk.Button(btns, text="Use Uber APK Signer", command=self._preset_uber_apk_signer).pack(side="left", padx=4)
        ttk.Button(btns, text="Open output folder", command=self.open_out).pack(side="left", padx=4)

        info = ttk.LabelFrame(outer, text=f"{title} behaviour")
        info.grid(row=len(rows) + 2, column=0, columnspan=3, sticky="ew", padx=8, pady=(6, 0))
        ttk.Label(info, text=f"This tab performs the {title.lower()} flow: it checks the modded APK against the target app, rebuilds the patched APK, and can auto-sign it using your custom signer.", wraplength=800, justify="left").pack(fill="x", padx=8, pady=8)

        log_frame = ttk.LabelFrame(outer, text=f"{title} log")
        log_frame.grid(row=len(rows) + 3, column=0, columnspan=3, sticky="nsew", padx=8, pady=(6, 0))
        outer.grid_columnconfigure(1, weight=1)
        outer.grid_rowconfigure(len(rows) + 3, weight=1)
        setattr(self, f"{page_key}_log_box", scrolledtext.ScrolledText(log_frame, height=12, bg="#0d1117", fg="#d7dae0", font=("Consolas", 10), state="disabled", wrap="word"))
        getattr(self, f"{page_key}_log_box").pack(fill="both", expand=True, padx=4, pady=4)
        for lv, col in LOG_COLOURS.items():
            getattr(self, f"{page_key}_log_box").tag_configure(lv, foreground=col)

        setattr(self, f"{page_key}_log_records", [])
        setattr(self, f"{page_key}_log_min", tk.StringVar(value="DEBUG"))
        bar = ttk.Frame(log_frame)
        bar.pack(fill="x")
        ttk.Label(bar, text="Show from level").pack(side="left", padx=6)
        cb = ttk.Combobox(bar, values=LEVELS, textvariable=getattr(self, f"{page_key}_log_min"), width=9, state="readonly")
        cb.pack(side="left")
        cb.bind("<<ComboboxSelected>>", lambda e, k=page_key: self._refilter_transplant_log(k))
        ttk.Button(bar, text="Clear", command=lambda k=page_key: self._clear_transplant_log(k)).pack(side="right", padx=4)
        getattr(self, f"{page_key}_log_box").bind("<Configure>", lambda e, b=getattr(self, f"{page_key}_log_box"): b.see("end"))

    # ---------------------------------------------------------------- cert spoof page
    def _build_certspoof_page(self):
        pad = {"padx": 8, "pady": 3}
        outer = ttk.Frame(self.certspoof_page)
        outer.pack(fill="both", expand=True, padx=10, pady=10)
        outer.columnconfigure(1, weight=1)

        rows = [
            ("Reference APK (fingerprint source)", "reference_apk", "file"),
            ("Target APK (to patch)", "target_apk", "file"),
            ("apktool.jar", "apktool", "file"),
            ("Keystore (optional, debug auto-generated)", "keystore", "file"),
            ("Keystore password", "ks_pass", "text"),
            ("Key alias", "ks_alias", "text"),
            ("Output folder", "out_dir", "dir"),
        ]
        for r, (label, key, kind) in enumerate(rows):
            ttk.Label(outer, text=label).grid(row=r, column=0, sticky="w", **pad)
            ttk.Entry(outer, textvariable=self.v[key]).grid(row=r, column=1, sticky="ew", **pad)
            if kind == "file":
                ttk.Button(outer, text="Browse", command=lambda k=key: self._browse(k, "file")).grid(row=r, column=2, **pad)
            elif kind == "dir":
                ttk.Button(outer, text="Browse", command=lambda k=key: self._browse(k, "dir")).grid(row=r, column=2, **pad)

        info = ttk.LabelFrame(outer, text="What this does")
        info.grid(row=len(rows), column=0, columnspan=3, sticky="ew", padx=8, pady=(10, 4))
        ttk.Label(info, text=(
            "Extracts the SHA-256 certificate fingerprint from the reference APK, decodes the target APK, "
            "locates its MAIN/LAUNCHER activity (scanning all smali_classes* folders), injects a runtime hook "
            "that installs the reference fingerprint, rebuilds with apktool, runs zipalign -f 4, signs with "
            "V2+V3 enabled, and then automatically re-extracts the fingerprint from the output to confirm it "
            "matches the reference. The build fails if the fingerprint does not match."
        ), wraplength=820, justify="left").pack(fill="x", padx=8, pady=8)

        analysis = ttk.LabelFrame(outer, text="Progress")
        analysis.grid(row=len(rows) + 1, column=0, columnspan=3, sticky="ew", padx=8, pady=(8, 4))
        labels = {}
        for stage in cs.SPOOF_STAGES:
            lbl = ttk.Label(analysis, text=f"{SYMBOL['pending']} {stage}")
            lbl.pack(anchor="w", padx=8, pady=1)
            labels[stage] = lbl
        self.certspoof_stage_labels = labels
        self.certspoof_progress = ttk.Progressbar(analysis, mode="determinate", maximum=1.0)
        self.certspoof_progress.pack(fill="x", padx=8, pady=(5, 6))

        btns = ttk.Frame(outer)
        btns.grid(row=len(rows) + 2, column=0, columnspan=3, sticky="ew", padx=8, pady=(8, 4))
        self.b_certspoof = ttk.Button(btns, text="Run cert spoof", command=self.start_certspoof)
        self.b_certspoof.pack(side="left", padx=4)
        ttk.Button(btns, text="Open output folder", command=self.open_out).pack(side="left", padx=4)

        log_frame = ttk.LabelFrame(outer, text="Cert spoof log")
        log_frame.grid(row=len(rows) + 3, column=0, columnspan=3, sticky="nsew", padx=8, pady=(6, 0))
        outer.grid_rowconfigure(len(rows) + 3, weight=1)

        bar = ttk.Frame(log_frame)
        bar.pack(fill="x")
        ttk.Label(bar, text="Show from level").pack(side="left", padx=6)
        self.certspoof_log_min = tk.StringVar(value="DEBUG")
        cb = ttk.Combobox(bar, values=LEVELS, textvariable=self.certspoof_log_min, width=9, state="readonly")
        cb.pack(side="left")
        cb.bind("<<ComboboxSelected>>", lambda e: self._refilter_certspoof_log())
        ttk.Button(bar, text="Clear", command=self._clear_certspoof_log).pack(side="right", padx=4)

        self.certspoof_log_box = scrolledtext.ScrolledText(
            log_frame, height=14, bg="#0d1117", fg="#d7dae0",
            font=("Consolas", 10), state="disabled", wrap="word",
        )
        self.certspoof_log_box.pack(fill="both", expand=True, padx=4, pady=4)
        for lv, col in LOG_COLOURS.items():
            self.certspoof_log_box.tag_configure(lv, foreground=col)
        self.certspoof_log_records = []

    # ---------------------------------------------------------------- mode handling
    def _make_stages(self, names):
        for w in self.stage_frame.winfo_children():
            w.destroy()
        self.stage_labels = {}
        for n in names:
            l = ttk.Label(self.stage_frame, text=f"{SYMBOL['pending']} {n}")
            l.pack(anchor="w", padx=8)
            self.stage_labels[n] = l

    def _mode_changed(self):
        t = self.mode.get() == "transplant"
        self._make_stages(tp.TP_STAGES if t else STAGES)
        self.b_analyse.config(text="Transplant mod" if t else "Analyse & Port")
        self.b_build.config(state="disabled")
        self.progress["value"] = 0

    # ---------------------------------------------------------------- helpers
    def _browse(self, key, kind):
        if kind == "text":
            return
        if kind == "dir":
            p = filedialog.askdirectory()
        elif kind == "json":
            p = filedialog.askopenfilename(filetypes=[("JSON", "*.json"), ("All", "*.*")])
        else:
            p = filedialog.askopenfilename(filetypes=[("APK / bundle", "*.apk *.apks *.xapk *.zip"), ("All", "*.*")]) if key not in ("keystore", "custom_signer") else filedialog.askopenfilename()
        if p:
            self.v[key].set(p)

    def _preset_uber_apk_signer(self):
        jar = filedialog.askopenfilename(
            title="Select uber-apk-signer.jar",
            filetypes=[("Uber APK Signer", "*.jar"), ("All files", "*.*")],
        )
        if not jar:
            return
        self.v["custom_signer"].set(jar)
        self.v["custom_signer_args"].set("")

    def _config(self):
        g = lambda k: self.v[k].get().strip()
        return Config(g("old_mod"), g("old_official"), g("new_official"), g("out_dir") or "output", g("symbols_old"), g("symbols_new"),
                      self.apply_thr.get(), self.review_thr.get(), self.apply_review.get(), self.allow_partial.get(), g("keystore"))

    def _set_busy(self, busy):
        self.busy = busy
        self.b_analyse.config(state="disabled" if busy else "normal")
        self.b_build.config(state="disabled" if busy or not self.analysis else "normal")
        if hasattr(self, "b_certspoof"):
            self.b_certspoof.config(state="disabled" if busy else "normal")

    def _put_log(self, level, msg):
        self.records.append((level, msg))
        self._append(level, msg)

    def _append(self, level, msg):
        if LEVELS.index(level if level in LEVELS else "INFO") < LEVELS.index(self.min_level.get()):
            return
        self.log_box.config(state="normal")
        self.log_box.insert("end", msg + "\n", level)
        self.log_box.see("end")
        self.log_box.config(state="disabled")

    def _refilter(self):
        self.log_box.config(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.config(state="disabled")
        for lv, m in self.records:
            self._append(lv, m)

    def _clear_log(self):
        self.records.clear()
        self._refilter()

    def _append_transplant_log(self, page_key, level, msg):
        records = getattr(self, f"{page_key}_log_records")
        records.append((level, msg))
        box = getattr(self, f"{page_key}_log_box")
        min_level = getattr(self, f"{page_key}_log_min").get()
        if LEVELS.index(level if level in LEVELS else "INFO") < LEVELS.index(min_level):
            return
        box.config(state="normal")
        box.insert("end", msg + "\n", level)
        box.see("end")
        box.config(state="disabled")

    def _refilter_transplant_log(self, page_key):
        box = getattr(self, f"{page_key}_log_box")
        records = getattr(self, f"{page_key}_log_records")
        min_level = getattr(self, f"{page_key}_log_min").get()
        box.config(state="normal")
        box.delete("1.0", "end")
        box.config(state="disabled")
        for lv, m in records:
            if LEVELS.index(lv if lv in LEVELS else "INFO") >= LEVELS.index(min_level):
                box.config(state="normal")
                box.insert("end", m + "\n", lv)
                box.config(state="disabled")

    def _clear_transplant_log(self, page_key):
        setattr(self, f"{page_key}_log_records", [])
        box = getattr(self, f"{page_key}_log_box")
        box.config(state="normal")
        box.delete("1.0", "end")
        box.config(state="disabled")

    # ---------------------------------------------------------------- cert spoof log
    def _append_certspoof_log(self, level, msg):
        self.certspoof_log_records.append((level, msg))
        min_level = self.certspoof_log_min.get()
        if LEVELS.index(level if level in LEVELS else "INFO") < LEVELS.index(min_level):
            return
        box = self.certspoof_log_box
        box.config(state="normal")
        box.insert("end", msg + "\n", level)
        box.see("end")
        box.config(state="disabled")

    def _refilter_certspoof_log(self):
        box = self.certspoof_log_box
        min_level = self.certspoof_log_min.get()
        box.config(state="normal")
        box.delete("1.0", "end")
        box.config(state="disabled")
        for lv, m in self.certspoof_log_records:
            if LEVELS.index(lv if lv in LEVELS else "INFO") >= LEVELS.index(min_level):
                box.config(state="normal")
                box.insert("end", m + "\n", lv)
                box.config(state="disabled")

    def _clear_certspoof_log(self):
        self.certspoof_log_records = []
        box = self.certspoof_log_box
        box.config(state="normal")
        box.delete("1.0", "end")
        box.config(state="disabled")

    def save_log(self):
        p = filedialog.asksaveasfilename(defaultextension=".log", initialfile="apkporter.log")
        if p:
            Path(p).write_text("\n".join(m for _, m in self.records), encoding="utf-8")

    def open_out(self):
        p = Path(self.v["out_dir"].get())
        p.mkdir(parents=True, exist_ok=True)
        if sys.platform.startswith("win"):
            os.startfile(p)
        else:
            subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", str(p)])

    def _show_evidence(self, _):
        sel = self.tree.selection()
        if not sel or not self.analysis:
            return
        tid = self.tree.item(sel[0])["values"][0]
        item = next((x for x in self.analysis.native + self.analysis.files if x.id == tid), None)
        if not item:
            return
        w = tk.Toplevel(self)
        w.title(f"Evidence for {tid}")
        t = scrolledtext.ScrolledText(w, width=100, height=22, wrap="word")
        t.pack(fill="both", expand=True)
        lines = [f"{tid}: {item.status} ({item.confidence:.1f}%)", item.message, ""]
        if item.kind == "native":
            lines += [f"Library: {item.path}", f"Old: {item.old_name} @ {item.old_vaddr:#x}", f"New: {item.new_name} @ {item.new_vaddr:#x}",
                      "Changed words: " + ", ".join(f"#{x.index} {x.old_word:#010x} -> {x.new_word:#010x}" for x in item.words), ""]
        lines += ["Evidence:"] + [f" - {e}" for e in item.evidence]
        t.insert("end", "\n".join(lines))
        t.config(state="disabled")

    def _fill_results(self):
        self.tree.delete(*self.tree.get_children())
        for t in self.analysis.native:
            self.tree.insert("", "end", values=(t.id, "native", f"{t.old_name} -> {t.new_name or '?'}", f"{t.confidence:.1f}%" if t.confidence else "n/a", t.status), tags=(t.status,))
        for f in self.analysis.files:
            self.tree.insert("", "end", values=(f.id, "file", f"{f.action}: {f.path}", f"{f.confidence:.0f}%" if f.confidence else "n/a", f.status), tags=(f.status,))
        for i, msg in enumerate(self.analysis.issues, 1):
            self.tree.insert("", "end", values=(f"M{i}", "manual", msg, "n/a", "unmatched"), tags=("unmatched",))

    # ---------------------------------------------------------------- workers
    def _setup_logging(self):
        return logutil.setup(callback=lambda lv, m: self.q.put(("log", lv, m)))

    def _run(self, fn):
        self._set_busy(True)
        threading.Thread(target=fn, daemon=True).start()

    def start_transplant(self, page_key="generic"):
        g = lambda k: self.v[k].get().strip()
        self.tree.delete(*self.tree.get_children())
        for n, l in self.stage_labels.items():
            l.config(text=f"{SYMBOL['pending']} {n}")
        self.progress["value"] = 0
        log = self._setup_logging()
        emit = lambda *a: self.q.put(("transplant_event", page_key, *a))
        self.active_transplant_page = page_key

        stage_labels = getattr(self, f"{page_key}_stage_labels")
        for stage, label in stage_labels.items():
            label.config(text=f"{SYMBOL['pending']} {stage}")
        getattr(self, f"{page_key}_progress")["value"] = 0

        box = getattr(self, f"{page_key}_log_box", None)
        if box is not None:
            records = getattr(self, f"{page_key}_log_records")
            records.clear()
            box.config(state="normal")
            box.delete("1.0", "end")
            box.config(state="disabled")

        args = (g("new_official"), g("old_mod"), g("out_dir") or "output", g("apktool"))
        old_official = g("old_official")
        keystore = g("keystore")
        custom_signer = g("custom_signer")
        custom_signer_args = g("custom_signer_args")

        def work():
            try:
                native_lib = "lib/arm64-v8a/libDeep-Mods.so" if page_key == "deepmods" else tp.LIB_PATH
                out = tp.run(*args, log, keystore, emit=emit, custom_signer=custom_signer,
                             custom_signer_args=custom_signer_args, native_lib=native_lib, old_official=old_official)
                self.q.put(("transplanted", str(out)))
            except Exception as e:
                log.error(f"STOPPED: {e}")
                self.q.put(("idle",))
        self._run(work)

    def start_certspoof(self):
        g = lambda k: self.v[k].get().strip()
        for stage, lbl in self.certspoof_stage_labels.items():
            lbl.config(text=f"{SYMBOL['pending']} {stage}")
        self.certspoof_progress["value"] = 0
        self.certspoof_log_records.clear()
        self.certspoof_log_box.config(state="normal")
        self.certspoof_log_box.delete("1.0", "end")
        self.certspoof_log_box.config(state="disabled")

        log = self._setup_logging()
        emit = lambda *a: self.q.put(("certspoof_event", *a))
        self.active_certspoof = True

        reference = g("reference_apk")
        target = g("target_apk")
        out_dir = g("out_dir") or "output"
        apktool = g("apktool")
        keystore = g("keystore")
        ks_pass = g("ks_pass") or "android"
        ks_alias = g("ks_alias") or "key0"

        if not (reference and target and apktool):
            log.error("reference APK, target APK and apktool.jar are all required")
            self._set_busy(False)
            return

        def work():
            try:
                out = cs.run(reference, target, out_dir, apktool, log, keystore,
                             ks_pass=ks_pass, ks_alias=ks_alias, emit=emit)
                self.q.put(("certspoof_done", str(out)))
            except Exception as e:
                log.error(f"STOPPED: {e}")
                self.q.put(("certspoof_failed", str(e)))
        self._run(work)

    def start_analyse(self):
        if self.mode.get() == "transplant":
            return self.start_transplant()
        cfg = self._config()
        self.analysis = None
        self.tree.delete(*self.tree.get_children())
        for s, l in self.stage_labels.items():
            l.config(text=f"{SYMBOL['pending']} {s}")
        self.progress["value"] = 0
        log = self._setup_logging()
        emit = lambda *a: self.q.put(a)
        self.pipeline = Pipeline(cfg, log, emit)

        def work():
            try:
                res = self.pipeline.analyse()
                self.q.put(("analysed", res))
            except Exception as e:
                log.error(f"Analysis failed: {e}")
                self.q.put(("idle",))
        self._run(work)

    def start_build(self):
        if not self.analysis:
            return
        cfg = self._config()
        self.pipeline.cfg = cfg
        log = logutil.get()

        def work():
            try:
                self.q.put(("built", self.pipeline.build(self.analysis)))
            except Exception as e:
                log.error(f"Build failed: {e}")
                self.q.put(("idle",))
        self._run(work)

    def _poll(self):
        try:
            while True:
                m = self.q.get_nowait()
                k = m[0]
                if k == "log":
                    self._put_log(m[1], m[2])
                    if hasattr(self, "active_transplant_page"):
                        self._append_transplant_log(self.active_transplant_page, m[1], m[2])
                    if getattr(self, "active_certspoof", False):
                        self._append_certspoof_log(m[1], m[2])
                elif k == "transplant_event":
                    page_key, event = m[1], m[2]
                    if event == "stage":
                        getattr(self, f"{page_key}_stage_labels")[m[3]].config(text=f"{SYMBOL[m[4]]} {m[3]}")
                    elif event == "progress":
                        getattr(self, f"{page_key}_progress")["value"] = m[3]
                elif k == "certspoof_event":
                    event = m[1]
                    if event == "stage":
                        self.certspoof_stage_labels[m[2]].config(text=f"{SYMBOL[m[3]]} {m[2]}")
                    elif event == "progress":
                        self.certspoof_progress["value"] = m[2]
                elif k == "stage":
                    self.stage_labels[m[1]].config(text=f"{SYMBOL[m[2]]} {m[1]}")
                elif k == "progress":
                    self.progress["value"] = m[1]
                elif k == "analysed":
                    self.analysis = m[1]
                    self._fill_results()
                    self._set_busy(False)
                elif k == "built":
                    self._fill_results()
                    self._set_busy(False)
                    if not m[1].ok:
                        messagebox.showwarning("Build", m[1].message)
                elif k == "transplanted":
                    self.tree.delete(*self.tree.get_children())
                    for i, (what, detail) in enumerate((("native library", "lib/arm64-v8a/libsakizu.so"), ("menu dex", "added as next free classesN.dex"),
                                                        ("startup call", "UnityPlayerActivity.onCreate"), ("manifest", "overlay permission + Launcher service"),
                                                        ("output", m[1])), 1):
                        self.tree.insert("", "end", values=(f"T{i}", "mod", f"{what}: {detail}", "verified", "applied"), tags=("applied",))
                    self._set_busy(False)
                    self.b_build.config(state="disabled")
                elif k == "certspoof_done":
                    self.active_certspoof = False
                    self._set_busy(False)
                    self.certspoof_progress["value"] = 1.0
                    messagebox.showinfo("Cert spoof", f"VERIFICATION SUCCESS\n\nOutput: {m[1]}")
                elif k == "certspoof_failed":
                    self.active_certspoof = False
                    self._set_busy(False)
                    messagebox.showerror(
                        "Cert spoof failed",
                        f"{m[1]}\n\nSee the Cert Spoof tab log for details.",
                    )
                elif k == "idle":
                    self._set_busy(False)
        except queue.Empty:
            pass
        self.after(80, self._poll)


def main():
    App().mainloop()