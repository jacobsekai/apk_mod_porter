"""Orchestrates the workflow: analyse (read-only) then build (apply, rebuild, sign, verify, report)."""
import shutil
import tempfile
from pathlib import Path

from . import apk_manager as am
from .diff_engine import diff_sets, fmt
from .il2cpp import METADATA_SUFFIX, load_symbols, parse_metadata
from .matching import NativeIndex, build_anchors, match_function
from .models import BuildResult, Config, FileTarget
from .patch_engine import apply_native, export_patch, extract_native_targets, plan_target
from .report import write_reports
from .verification import verify_output

ANALYSE_STAGES = ["Open APKs", "Compare modded vs old official", "Compare old vs new official",
                  "Identify native libraries", "Analyse IL2CPP metadata", "Extract modifications",
                  "Match in new version"]
BUILD_STAGES = ["Apply patches", "Rebuild and align", "Sign", "Verify", "Write report"]
STAGES = ANALYSE_STAGES + BUILD_STAGES


class Analysis:
    def __init__(self):
        self.native, self.files, self.issues, self.summary = [], [], [], {}
        self.sets = {}

    def unresolved(self, cfg):
        ok = {"matched"} | ({"review"} if cfg.apply_review else set())
        return [t for t in self.native + self.files if t.status not in ok] + self.issues


class Pipeline:
    def __init__(self, cfg: Config, log, emit=lambda *a: None):
        self.cfg, self.log, self.emit = cfg, log, emit
        self.work = Path(tempfile.mkdtemp(prefix="apkporter_"))

    def stage(self, name, state):
        self.emit("stage", name, state)

    # ------------------------------------------------------------------ analyse
    def analyse(self) -> Analysis:
        cfg, log, res = self.cfg, self.log, Analysis()
        log.info("=== Analysis started ===")
        self.stage(STAGES[0], "run")
        for label, p in (("old modded", cfg.old_mod), ("old official", cfg.old_official), ("new official", cfg.new_official)):
            if not p or not Path(p).is_file():
                self.stage(STAGES[0], "fail")
                raise ValueError(f"Missing or unreadable {label} APK: {p!r}")
        mod = am.ApkSet(cfg.old_mod, self.work, log)
        off = am.ApkSet(cfg.old_official, self.work, log)
        new = am.ApkSet(cfg.new_official, self.work, log)
        res.sets = {"mod": mod, "off": off, "new": new}
        for n, s in res.sets.items():
            log.info(f"  {n}: {len(s.index())} files in {len(s.members)} APK(s)")
        self.stage(STAGES[0], "ok")

        self.stage(STAGES[1], "run")
        d_mod = diff_sets(off, mod)
        log.info(f"  modded vs old official: {len(d_mod.changed)} changed, {len(d_mod.added)} added, "
                 f"{len(d_mod.removed)} removed, {d_mod.same} identical")
        for k in d_mod.changed[:50]:
            log.debug(f"    changed by mod: {fmt(k)}")
        for k in d_mod.added[:50]:
            log.debug(f"    added by mod:   {fmt(k)}")
        if not (d_mod.changed or d_mod.added or d_mod.removed):
            log.warning("  the modded APK is identical to the old official APK: there is nothing to port")
        self.stage(STAGES[1], "ok")

        self.stage(STAGES[2], "run")
        d_ver = diff_sets(off, new)
        log.info(f"  old vs new official: {len(d_ver.changed)} changed, {len(d_ver.added)} added, "
                 f"{len(d_ver.removed)} removed, {d_ver.same} identical")
        res.summary = {"mod_changed": len(d_mod.changed), "mod_added": len(d_mod.added), "mod_removed": len(d_mod.removed),
                       "version_changed": len(d_ver.changed), "version_added": len(d_ver.added), "version_removed": len(d_ver.removed)}
        self.stage(STAGES[2], "ok")

        self.stage(STAGES[3], "run")
        new_idx_keys = new.index()
        for name, s in (("old official", off), ("new official", new)):
            for k in sorted(s.index()):
                if k[1].endswith(".so") and k[1].startswith("lib/"):
                    log.info(f"  [{name}] {fmt(k)}")
        so_changed = [k for k in d_mod.changed if k[1].endswith(".so")]
        log.info(f"  {len(so_changed)} native librar{'y' if len(so_changed) == 1 else 'ies'} modified by the mod")
        self.stage(STAGES[3], "ok")

        self.stage(STAGES[4], "run")
        self._metadata(mod, off, new)
        self.stage(STAGES[4], "ok")

        self.stage(STAGES[5], "run")
        sym_old = self._symbols(cfg.symbols_old, "old")
        sym_new = self._symbols(cfg.symbols_new, "new")
        indices = {}
        for k in so_changed:
            if k not in new_idx_keys:
                res.issues.append(f"{fmt(k)}: modified by the mod but missing in the new official APK")
                continue
            try:
                log.info(f"  fingerprinting {fmt(k)} (old official)")
                oi = NativeIndex(off.read(k), sym_old)
                log.info(f"    {len(oi)} functions, boundaries from {oi.boundary_source}, arch {oi.elf.arch}")
                ts, iss = extract_native_targets(k, oi, off.read(k), mod.read(k), log)
                res.issues += iss
                if ts:
                    indices[k] = (oi, ts)
            except ValueError as e:
                res.issues.append(f"{fmt(k)}: cannot analyse ({e})")
        n = 0
        for k, (oi, ts) in indices.items():
            for t in ts:
                n += 1
                t.id = f"N{n}"
                res.native.append(t)
        for k in d_mod.changed:
            if not k[1].endswith(".so"):
                res.files.append(self._file_target(k, "carry-over", new_idx_keys, off.index()))
        for k in d_mod.added:
            res.files.append(self._file_target(k, "add", new_idx_keys, off.index()))
        for k in d_mod.removed:
            res.issues.append(f"{fmt(k)}: removed by the mod; removal is not ported automatically")
        for i, f in enumerate(res.files, 1):
            f.id = f"F{i}"
            log.info(f"  {f.id}: {f.action} {fmt((f.member, f.path))} -> {f.status}: {f.message}")
        self.stage(STAGES[5], "ok")

        self.stage(STAGES[6], "run")
        for k, (oi, ts) in indices.items():
            log.info(f"  fingerprinting {fmt(k)} (new official)")
            ni = NativeIndex(new.read(k), sym_new)
            log.info(f"    {len(ni)} functions, boundaries from {ni.boundary_source}")
            anchors = build_anchors(oi, ni)
            log.info(f"    {len(anchors)} anchor functions (unique identical bodies in both builds)")
            for t in ts:
                i = oi.func_at(t.old_vaddr)
                m = match_function(oi, i, ni, anchors)
                plan_target(t, i, oi, m, ni, self.cfg, log)
                lvl = {"matched": 25, "review": 30}.get(t.status, 40)
                log.log(lvl, f"  {t.id} {t.old_name}: {t.status.upper()} {t.confidence:.1f}% "
                             f"-> {t.new_name} @ {t.new_vaddr:#x}" + (f"  [{t.message}]" if t.message else ""))
                for e in t.evidence:
                    log.info(f"      evidence: {e}")
        for msg in res.issues:
            log.warning(f"  UNHANDLED: {msg}")
        self.stage(STAGES[6], "ok" if not res.unresolved(self.cfg) else "warn")
        u = res.unresolved(self.cfg)
        log.info(f"=== Analysis finished: {len(res.native) + len(res.files) - len([x for x in u if not isinstance(x, str)])} "
                 f"ready, {len(u)} need attention ===")
        self.emit("progress", 0.55)
        return res

    def _symbols(self, path, label):
        if not path:
            return None
        try:
            s = load_symbols(path)
            self.log.info(f"  loaded {len(s)} IL2CPP symbols for {label} build from {Path(path).name}")
            return s
        except (OSError, ValueError, KeyError) as e:
            self.log.warning(f"  could not read {label} symbol map: {e}")
            return None

    def _metadata(self, mod, off, new):
        meta = {}
        for n, s in (("modded", mod), ("old official", off), ("new official", new)):
            keys = [k for k in s.index() if k[1].endswith(METADATA_SUFFIX)]
            if not keys:
                self.log.warning(f"  [{n}] no {METADATA_SUFFIX} found (split APK or different layout?)")
                continue
            m = parse_metadata(s.read(keys[0]))
            meta[n] = (keys[0], m)
            self.log.info(f"  [{n}] {fmt(keys[0])}: " + (f"valid, v{m.version}, {len(m.strings)} identifier strings"
                                                         if m.valid else f"NOT parsed: {m.note}"))
        if "old official" in meta and "new official" in meta:
            a, b = meta["old official"][1], meta["new official"][1]
            if a.valid and b.valid:
                self.log.info(f"  identifiers: +{len(b.strings - a.strings)} / -{len(a.strings - b.strings)} between official versions")
        if "modded" in meta and "old official" in meta:
            if meta["modded"][0] in mod.index() and mod.index()[meta["modded"][0]] != off.index().get(meta["modded"][0]):
                self.log.warning("  metadata was modified by the mod: not portable automatically")

    def _file_target(self, k, action, new_index, off_index):
        t = FileTarget("", k[0], k[1], action)
        if action == "add":
            if k in new_index:
                t.status, t.message = "unmatched", "path exists in the new official APK but not the old one; conflict"
            else:
                t.status, t.confidence = "matched", 95.0
                t.message = "file added by the mod; absent from both official builds"
                t.evidence = ["not present in old or new official APK"]
        else:
            if k not in new_index:
                t.status, t.message = "unmatched", "file no longer exists in the new official APK"
            elif new_index[k] == off_index.get(k):
                t.status, t.confidence = "matched", 100.0
                t.message = "official file unchanged between versions; modded copy carried over"
                t.evidence = ["CRC32 and size identical in old and new official APK"]
            else:
                t.status, t.message = "unmatched", "file changed in the new version as well; needs a manual merge"
        return t

    # ------------------------------------------------------------------ build
    def build(self, res: Analysis) -> BuildResult:
        cfg, log = self.cfg, self.log
        out = BuildResult()
        log.info("=== Build started ===")
        bad = res.unresolved(cfg)
        if bad and not cfg.allow_partial:
            out.message = ("Patch target could not be reliably identified. Manual analysis required. "
                           f"{len(bad)} item(s) unresolved; nothing was built (enable partial port to override).")
            log.error(out.message)
            self.emit("progress", 1.0)
            return out
        ok_status = {"matched"} | ({"review"} if cfg.apply_review else set())
        native = [t for t in res.native if t.status in ok_status]
        files = [f for f in res.files if f.status == "matched"]
        for t in res.native:
            if t not in native:
                t.status = "skipped" if t.status in ("review", "unmatched") else t.status
        mod, new = res.sets["mod"], res.sets["new"]
        outdir = Path(cfg.out_dir)
        outdir.mkdir(parents=True, exist_ok=True)

        self.stage("Apply patches", "run")
        repl, add = {m: {} for m in new.members}, {m: {} for m in new.members}
        bufs = {}
        try:
            for t in native:
                key = (t.member, t.path)
                bufs.setdefault(key, bytearray(new.read(key)))
                apply_native(bufs[key], t)
                log.info(f"  {t.id}: patched {t.new_name} @ {t.new_vaddr:#x} ({len(t.mapped)} words, confidence {t.confidence:.1f}%)")
            for (m, p), b in bufs.items():
                repl[m][p] = bytes(b)
            for f in files:
                data = mod.read((f.member, f.path))
                (repl if f.action == "carry-over" else add)[f.member][f.path] = data
                f.status = "applied"
                log.info(f"  {f.id}: {f.action} {f.path}")
        except (ValueError, KeyError) as e:
            self.stage("Apply patches", "fail")
            out.message = f"Patch application failed: {e}"
            log.error(out.message)
            return out
        self.stage("Apply patches", "ok")
        self.emit("progress", 0.7)

        self.stage("Rebuild and align", "run")
        unsigned = {}
        stem = Path(cfg.new_official).stem
        for m, src in new.members.items():
            dest = self.work / (f"{stem}_{m}" if m else f"{stem}_unsigned.apk")
            am.rebuild(src, dest, repl[m], add[m], log)
            unsigned[m] = dest
        self.stage("Rebuild and align", "ok")

        self.stage("Sign", "run")
        signed_all = True
        finals = {}
        odir = outdir / (f"{stem}_ported" if new.bundle else "")
        odir.mkdir(parents=True, exist_ok=True)
        for m, u in unsigned.items():
            name = m or f"{stem}_ported.apk"
            dest = odir / name
            if am.sign(u, dest, cfg.keystore, cfg.ks_alias, cfg.ks_pass, log):
                finals[m] = dest
            else:
                signed_all = False
                dest = odir / name.replace(".apk", "_UNSIGNED.apk")
                shutil.copy(u, dest)
                finals[m] = dest
                log.warning(f"  left unsigned: {dest}")
        self.stage("Sign", "ok" if signed_all else "warn")
        self.emit("progress", 0.85)

        self.stage("Verify", "run")
        checks = []
        for m, p in finals.items():
            log.info(f"  verifying {p.name}")
            checks += verify_output(p, m, new, native, signed_all, log)
        out.checks = checks
        out.outputs = [str(p) for p in finals.values()]
        out.ok = all(c.ok for c in checks) and signed_all
        self.stage("Verify", "ok" if all(c.ok for c in checks) else "fail")

        self.stage("Write report", "run")
        paths = write_reports(res, out, cfg, outdir)
        export_patch(res.native, res.files, outdir / "patch.json")
        log.info(f"  report: {paths[1]}")
        self.stage("Write report", "ok")
        out.message = ("Build complete." if out.ok else "Build finished with warnings (unsigned output or failed checks).")
        (log.log(25, out.message) if out.ok else log.warning(out.message))
        if signed_all:
            log.info("  note: the output is signed with a different key than the official app; uninstall the official app first")
        self.emit("progress", 1.0)
        return out
