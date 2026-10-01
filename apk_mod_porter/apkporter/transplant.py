"""Transplant mode: carry a runtime-hook mod (menu dex + native lib + startup call + manifest entries)
onto a new official APK. Nothing is guessed: every step is verified, and the run aborts on any surprise."""
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path

from . import apk_manager as am
from .il2cpp import METADATA_SUFFIX, parse_metadata
from .manifest_patch import add_manifest_entries, verify_additions_only

HOST_CLASS = b"Lcom/unity3d/player/UnityPlayerActivity;"
MENU_CLASS = b"Lcom/android/support/Main;"
HOOK = "invoke-static {p0}, Lcom/android/support/Main;->Start(Landroid/content/Context;)V"
LIB_PATH = "lib/arm64-v8a/libsakizu.so"
PERMISSION = "android.permission.SYSTEM_ALERT_WINDOW"
SERVICE = "com.android.support.Launcher"
# names libsakizu.so resolves through the IL2CPP API (found in its read-only data)
DEFAULT_TARGET_NAMES = ["Sekai", "Sekai.Live", "Sekai.Core.Live", "Sekai.CheerfulCarnival", "NoteBase", "LiveLogic",
                        "PutUserLiveResultResponce", "get_ClearType", "get_Result",
                        "get_CheerfulCarnivalLiveMatchResultType", "OnFinishFirstBgLoaded", "Assembly-CSharp.dll"]


TP_STAGES = ["Check target names", "Locate UnityPlayerActivity", "Insert startup call",
             "Patch manifest", "Rebuild and sign", "Verify"]


class TransplantError(RuntimeError):
    pass


class _Stages:
    """Reports stage/progress events (used by the GUI); harmless when emit is None."""

    def __init__(self, emit):
        self.emit, self.cur, self.warn = emit or (lambda *a: None), -1, False

    def go(self, i):
        if self.cur >= 0:
            self.emit("stage", TP_STAGES[self.cur], "warn" if self.warn else "ok")
            self.warn = False
        self.cur = i
        self.emit("stage", TP_STAGES[i], "run")
        self.emit("progress", i / len(TP_STAGES))

    def done(self):
        self.emit("stage", TP_STAGES[self.cur], "ok")
        self.emit("progress", 1.0)

    def fail(self):
        if self.cur >= 0:
            self.emit("stage", TP_STAGES[self.cur], "fail")


def _dex_index(name):
    m = re.fullmatch(r"classes(\d*)\.dex", name)
    return None if not m else (int(m.group(1)) if m.group(1) else 1)


def _dex_defines_class(data: bytes, descriptor: bytes) -> bool:
    """True when *data* is a DEX that has a class_def for *descriptor* (e.g. b'Lcom/example/Foo;').

    A type descriptor string can appear in many DEX files (any that reference the class), but only
    the DEX that actually defines the class will have an entry in its class_defs table.
    """
    if len(data) < 0x70 or data[:3] != b"dex":
        return False
    try:
        string_ids_size, string_ids_off = struct.unpack_from("<II", data, 0x38)
        type_ids_size, type_ids_off = struct.unpack_from("<II", data, 0x40)
        class_defs_size, class_defs_off = struct.unpack_from("<II", data, 0x60)
    except struct.error:
        return False
    # Collect type indices that have class definitions
    defined = set()
    for i in range(class_defs_size):
        off = class_defs_off + i * 32
        if off + 4 > len(data):
            break
        defined.add(struct.unpack_from("<I", data, off)[0])
    # Check each defined type's descriptor string
    for type_idx in defined:
        if type_idx >= type_ids_size:
            continue
        desc_idx = struct.unpack_from("<I", data, type_ids_off + type_idx * 4)[0]
        if desc_idx >= string_ids_size:
            continue
        s_off = struct.unpack_from("<I", data, string_ids_off + desc_idx * 4)[0]
        # Skip ULEB128 utf16_size prefix
        p = s_off
        while p < len(data) and data[p] & 0x80:
            p += 1
        p += 1
        if p >= len(data):
            continue
        end = data.find(b"\0", p)
        if end >= 0 and data[p:end] == descriptor:
            return True
    return False


def _apktool(jar, args, log, timeout=900):
    log.info("  apktool " + " ".join(args[:3]) + " ...")
    r = subprocess.run(["java", "-Xmx1g", "-jar", str(jar), *args], capture_output=True, text=True, timeout=timeout)
    if r.returncode:
        raise TransplantError(f"apktool failed: {(r.stderr or r.stdout).strip()[-400:]}")


def patch_dex(dex: bytes, manifest: bytes, apktool_jar, work: Path, log) -> bytes:
    """Insert the startup call at the top of UnityPlayerActivity.onCreate via a smali round trip."""
    mini, out, built = work / "mini.apk", work / "dec", work / "built.apk"
    with zipfile.ZipFile(mini, "w") as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", dex)
    _apktool(apktool_jar, ["d", "-f", "--no-res", "-o", str(out), str(mini)], log)
    smali = next(out.glob("smali*/com/unity3d/player/UnityPlayerActivity.smali"), None)
    if not smali:
        raise TransplantError("UnityPlayerActivity.smali not produced")
    s = smali.read_text(encoding="utf-8")
    if "Lcom/android/support/Main;->Start" in s:
        raise TransplantError("hook already present in this dex")
    pat = re.compile(r"(\.method [^\n]*onCreate\(Landroid/os/Bundle;\)V\n\s*\.(?:locals|registers) \d+\n\n)")
    if len(pat.findall(s)) != 1:
        raise TransplantError("onCreate(Bundle) not found exactly once; the Unity activity has changed. Manual work required.")
    smali.write_text(pat.sub(lambda m: m.group(1) + "    " + HOOK + "\n\n", s, count=1), encoding="utf-8")
    _apktool(apktool_jar, ["b", "-f", "-o", str(built), str(out)], log)
    with zipfile.ZipFile(built) as z:
        return z.read("classes.dex")


def check_names(new_zip, names, log):
    keys = [n for n in new_zip.namelist() if n.endswith(METADATA_SUFFIX)]
    if not keys:
        log.warning("  no global-metadata.dat in the new APK; name check skipped")
        return []
    meta = parse_metadata(new_zip.read(keys[0]))
    if not meta.valid:
        log.warning(f"  metadata not parseable ({meta.note}); name check skipped")
        return []
    missing = [n for n in names if n not in meta.strings]
    log.info(f"  {len(names) - len(missing)}/{len(names)} mod target names present in the new metadata (v{meta.version})")
    for n in missing:
        log.error(f"  MISSING in new metadata: {n}")
    return missing


def validate_source_payload(old_zip, mod_zip, native_lib, menu_dex, log):
    """Confirm that the selected transplant payload is present and mod-specific."""
    if native_lib not in mod_zip.namelist():
        raise TransplantError(f"{native_lib} not found in the modded APK")
    if native_lib in old_zip.namelist() and old_zip.read(native_lib) == mod_zip.read(native_lib):
        raise TransplantError(f"{native_lib} is unchanged from the old official APK; select the correct modded APK")

    if menu_dex not in mod_zip.namelist():
        raise TransplantError(f"{menu_dex} not found in the modded APK")
    if not _dex_defines_class(mod_zip.read(menu_dex), MENU_CLASS):
        raise TransplantError(f"{menu_dex} does not define the expected mod entry class Lcom/android/support/Main;")
    if menu_dex in old_zip.namelist() and _dex_defines_class(old_zip.read(menu_dex), MENU_CLASS):
        raise TransplantError(f"{menu_dex} already contains the mod entry class in the old official APK")
    log.info(f"  source payload validated: {native_lib} + {menu_dex}")


def run(new_apk, mod_apk, out_dir, apktool_jar, log, keystore="", ks_pass="android", ks_alias="key0",
        menu_dex="classes6.dex", names=None, allow_missing_names=False, emit=None, custom_signer="",
    custom_signer_args="", native_lib=LIB_PATH, old_official=""):
    st = _Stages(emit)
    try:
        return _run(new_apk, mod_apk, out_dir, apktool_jar, log, keystore, ks_pass, ks_alias, menu_dex, names,
                    allow_missing_names, st, custom_signer, custom_signer_args, native_lib, old_official)
    except (TransplantError, OSError, zipfile.BadZipFile, subprocess.TimeoutExpired) as e:
        st.fail()
        raise TransplantError(str(e)) if not isinstance(e, TransplantError) else e


def _run(new_apk, mod_apk, out_dir, apktool_jar, log, keystore, ks_pass, ks_alias, menu_dex, names,
        allow_missing_names, st, custom_signer, custom_signer_args, native_lib, old_official):
    for label, f in (("new APK", new_apk), ("old official APK", old_official), ("modded APK", mod_apk),
                 ("apktool.jar", apktool_jar)):
        if not f or not Path(f).is_file():
            raise TransplantError(f"{label} not found: {f!r}")
    new_apk, old_official, mod_apk, out_dir = Path(new_apk), Path(old_official), Path(mod_apk), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="apkporter_tp_"))
    log.info("=== Transplant started ===")
    with zipfile.ZipFile(new_apk) as zn, zipfile.ZipFile(old_official) as zo, zipfile.ZipFile(mod_apk) as zm:
        if "AndroidManifest.xml" not in zn.namelist():
            raise TransplantError("new APK has no AndroidManifest.xml (is it a split bundle? merge it first)")
        validate_source_payload(zo, zm, native_lib, menu_dex, log)
        st.go(0)
        log.info("[1/6] checking mod target names against the new build")
        missing = check_names(zn, names or DEFAULT_TARGET_NAMES, log)
        if missing and not allow_missing_names:
            raise TransplantError(f"{len(missing)} name(s) the mod relies on are gone from the new build. Manual analysis required.")

        st.go(1)

        log.info("[2/6] locating UnityPlayerActivity")
        dexes = sorted((n for n in zn.namelist() if _dex_index(n)), key=_dex_index)
        hosts = [n for n in dexes if _dex_defines_class(zn.read(n), HOST_CLASS)]
        if not hosts:
            # fallback: class_def parsing found nothing; use raw byte search
            hosts = [n for n in dexes if HOST_CLASS in zn.read(n)]
        if len(hosts) != 1:
            raise TransplantError(f"UnityPlayerActivity found in {len(hosts)} dex files {hosts}; expected exactly one")
        log.info(f"  host dex: {hosts[0]} ({len(dexes)} dex files in the new APK)")
        manifest = zn.read("AndroidManifest.xml")

        st.go(2)

        log.info("[3/6] inserting the startup call (smali round trip, may take a few minutes)")
        patched_dex = patch_dex(zn.read(hosts[0]), manifest, apktool_jar, work, log)

        st.go(3)

        log.info("[4/6] patching the manifest (append-only)")
        new_manifest = add_manifest_entries(manifest, PERMISSION, SERVICE)
        ok, extra = verify_additions_only(manifest, new_manifest, PERMISSION, SERVICE)
        if not ok:
            raise TransplantError(f"manifest check failed, unexpected changes: {extra[:4]}")
        log.info("  manifest differs from the original by exactly the permission and the service")

        menu_name = f"classes{max(_dex_index(n) for n in dexes) + 1}.dex"
        replace = {hosts[0]: patched_dex, "AndroidManifest.xml": new_manifest}
        add = {menu_name: zm.read(menu_dex), native_lib: zm.read(native_lib)}
        if native_lib in zn.namelist() or menu_name in zn.namelist():
            raise TransplantError("target names already exist in the new APK")

    st.go(4)

    log.info("[5/6] rebuilding, aligning, signing")
    unsigned = work / "unsigned.apk"
    am.rebuild(new_apk, unsigned, replace, add, log)
    if custom_signer:
        signed = am.run_custom_signer(str(unsigned), str(out_dir), custom_signer, log, custom_signer_args)
        if signed is not None:
            final = signed
        else:
            final = out_dir / f"{new_apk.stem}_ported_UNSIGNED.apk"
            shutil.copy(unsigned, final)
            st.warn = True
            log.warning(f"  left unsigned: {final}")
    else:
        final = out_dir / f"{new_apk.stem}_ported.apk"
        if not am.sign(unsigned, final, keystore, ks_alias, ks_pass, log):
            final = out_dir / f"{new_apk.stem}_ported_UNSIGNED.apk"
            shutil.copy(unsigned, final)
            st.warn = True
            log.warning(f"  left unsigned: {final}")

    st.go(5)

    log.info("[6/6] verifying")
    problems = verify(new_apk, final, set(replace), set(add), log)
    if problems:
        raise TransplantError("verification failed: " + "; ".join(problems))
    st.done()
    log.log(25, f"=== Transplant complete: {final} ===")
    return final


def verify(new_apk, out_apk, replaced, added, log):
    problems = []
    with zipfile.ZipFile(new_apk) as a, zipfile.ZipFile(out_apk) as b:
        if b.testzip():
            problems.append("zip integrity")
        ia = {i.filename: (i.CRC, i.file_size) for i in a.infolist() if not i.is_dir() and not am.is_signature(i.filename)}
        ib = {i.filename: (i.CRC, i.file_size) for i in b.infolist() if not i.is_dir() and not am.is_signature(i.filename)}
        changed = {k for k in ia if k in ib and ia[k] != ib[k]}
        gone, new = set(ia) - set(ib), set(ib) - set(ia)
        if changed != replaced or new != added or gone:
            problems.append(f"unexpected file changes: changed={sorted(changed ^ replaced)} new={sorted(new ^ added)} removed={sorted(gone)}")
        else:
            log.log(25, f"  PASS only the planned files differ: {len(replaced)} replaced, {len(added)} added, {len(ia) - len(replaced)} untouched")
    bad = am.check_alignment(out_apk)
    if bad:
        problems.append(f"misaligned entries {bad[:3]}")
    else:
        log.log(25, "  PASS stored entries aligned")
    if "UNSIGNED" not in Path(out_apk).name:
        ok, msg = am.verify_signature(out_apk)
        if ok is False:
            problems.append(f"signature: {msg}")
        elif ok:
            log.log(25, "  PASS apksigner verify")
    return problems
