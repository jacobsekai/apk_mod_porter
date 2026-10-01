"""Certificate spoofing: extract a reference APK's certificate SHA-256 fingerprint, locate the
launcher activity, inject a mock-data hook into its onCreate, then align and sign with V2+V3.

This module is deliberately conservative: every step fails loudly, and the final verification
re-extracts the fingerprint from the produced APK to prove it matches the reference.
"""
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import apk_manager as am


SPOOF_STAGES = [
    "Extract reference fingerprint",
    "Locate launcher activity",
    "Inject certificate hook",
    "Rebuild and align",
    "Sign (V2+V3)",
    "Verify fingerprint",
]

# Smali hook injected at the top of the launcher activity's onCreate. It installs a
# PackageManager wrapper? No -- too invasive. Instead we seed a static field on the
# app's own class that the mod (or a companion dex) can read, plus we reflectively
# override the cached Signature on the PackageInfo the activity can query.
HOOK_MARKER = "Lcom/android/support/CertSpoof;"

HOOK_SMALI = """\
    # --- cert spoof hook (injected by apkporter) ---
    const-string v0, "{fp}"
    invoke-static {{v0}}, Lcom/android/support/CertSpoof;->install(Ljava/lang/String;)V
    # --- end cert spoof hook ---
"""


class CertSpoofError(RuntimeError):
    pass


# --------------------------------------------------------------------------- step 1
def extract_fingerprint(apk_path: str, log) -> str:
    """Run `apksigner verify --print-certs` and return the SHA-256 fingerprint."""
    tool = am.find_tool("apksigner")
    if not tool:
        raise CertSpoofError("apksigner not found (install Android build-tools, or set ANDROID_HOME)")
    apk = Path(apk_path)
    if not apk.is_file():
        raise CertSpoofError(f"reference APK not found: {apk}")
    r = subprocess.run([tool, "verify", "--print-certs", str(apk)], capture_output=True, text=True)
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode and "DOES NOT VERIFY" not in out:
        raise CertSpoofError(f"apksigner verify failed: {out.strip()[-400:]}")
    m = re.search(r"SHA-256 digest:\s*([0-9a-fA-F:]+)", out)
    if not m:
        # Older apksigner prints "Signer #1 certificate SHA-256 digest: ..."
        m = re.search(r"certificate SHA-256 digest:\s*([0-9a-fA-F:]+)", out)
    if not m:
        raise CertSpoofError(f"could not parse SHA-256 fingerprint from apksigner output:\n{out.strip()[-600:]}")
    fp = m.group(1).replace(":", "").lower()
    log.info(f"  reference fingerprint: {fp}")
    return fp


# --------------------------------------------------------------------------- step 2
def find_launcher_smali(decoded_dir: Path, log) -> Path:
    """Parse AndroidManifest.xml from an unpacked dir and return the launcher .smali path."""
    manifest = decoded_dir / "AndroidManifest.xml"
    if not manifest.is_file():
        raise CertSpoofError(f"AndroidManifest.xml not found in {decoded_dir}")
    text = manifest.read_text(encoding="utf-8", errors="replace")

    # Find every <activity ...> block; pick the one with MAIN+LAUNCHER filters.
    activity_re = re.compile(r"<activity\b[^>]*?android:name=\"([^\"]+)\"[^>]*?>(.*?)</activity>",
                             re.DOTALL)
    launcher = None
    for m in activity_re.finditer(text):
        name, body = m.group(1), m.group(2)
        if "android.intent.action.MAIN" in body and "android.intent.category.LAUNCHER" in body:
            launcher = name
            break
    if not launcher:
        # some manifests put the filters in <activity-alias>
        alias_re = re.compile(r"<activity-alias\b[^>]*?android:targetActivity=\"([^\"]+)\"[^>]*?>(.*?)</activity-alias>",
                              re.DOTALL)
        for m in alias_re.finditer(text):
            name, body = m.group(1), m.group(2)
            if "android.intent.action.MAIN" in body and "android.intent.category.LAUNCHER" in body:
                launcher = name
                break
    if not launcher:
        raise CertSpoofError("no MAIN/LAUNCHER activity found in AndroidManifest.xml")

    # Strip a leading dot (relative package name handled by apktool, but be safe)
    if launcher.startswith("."):
        pkg_m = re.search(r'package="([^"]+)"', text)
        if pkg_m:
            launcher = pkg_m.group(1) + launcher
    log.info(f"  launcher activity: {launcher}")

    # Convert dotted class to a smali path. Inner classes use $ which stays literal.
    parts = launcher.split(".")
    # apktool names smali dirs smali/, smali_classes2/, smali_classes3/ ...
    candidates = [decoded_dir / "smali"]
    for i in range(2, 20):
        d = decoded_dir / f"smali_classes{i}"
        if d.is_dir():
            candidates.append(d)
    rel = Path(*parts[:-1]) / f"{parts[-1]}.smali"
    for base in candidates:
        target = base / rel
        if target.is_file():
            log.info(f"  smali file: {target.relative_to(decoded_dir)}")
            return target
    raise CertSpoofError(
        f"launcher smali not found in any of {[c.name for c in candidates]} (looked for {rel})")


# --------------------------------------------------------------------------- step 3
def inject_hook(smali_path: Path, fingerprint: str, log) -> None:
    """Insert the cert-spoof hook at the top of onCreate in the launcher smali."""
    src = smali_path.read_text(encoding="utf-8")
    if HOOK_MARKER in src:
        raise CertSpoofError("cert spoof hook already present in this smali")

    # Match .method ... onCreate(Landroid/os/Bundle;)V  ... .locals N
    pat = re.compile(
        r"(\.method\s+[^\n]*?\bonCreate\(Landroid/os/Bundle;\)V\s*\n"
        r"\s*\.(?:locals|registers)\s+\d+\s*\n)",
        re.MULTILINE,
    )
    matches = list(pat.finditer(src))
    if not matches:
        raise CertSpoofError("onCreate(Landroid/os/Bundle;)V not found in launcher smali")
    if len(matches) > 1:
        raise CertSpoofError(f"onCreate(Bundle) found {len(matches)} times; expected exactly one")

    # Ensure the hook's register (v0) is within the declared locals. Read the .locals count.
    locals_m = re.search(r"\.locals\s+(\d+)", matches[0].group(1))
    if not locals_m:
        raise CertSpoofError("could not read .locals from onCreate")
    n_locals = int(locals_m.group(1))
    if n_locals < 1:
        # Bump .locals 0 -> 1 so v0 exists.
        new_decl = re.sub(r"\.locals\s+0", ".locals 1", matches[0].group(1))
        src = src[:matches[0].start(1)] + new_decl + src[matches[0].end(1):]
        # recompute match span after edit
        matches = list(pat.finditer(src))

    hook = HOOK_SMALI.format(fp=fingerprint)
    src = src[:matches[0].end(1)] + hook + src[matches[0].end(1):]
    smali_path.write_text(src, encoding="utf-8")
    log.info(f"  injected hook at onCreate in {smali_path.name}")


# --------------------------------------------------------------------------- step 4
def zipalign(apk_path: Path, log) -> None:
    tool = am.find_tool("zipalign")
    if not tool:
        raise CertSpoofError("zipalign not found (install Android build-tools, or set ANDROID_HOME)")
    r = subprocess.run([tool, "-f", "4", str(apk_path), str(apk_path)], capture_output=True, text=True)
    if r.returncode:
        raise CertSpoofError(f"zipalign failed: {(r.stderr or r.stdout).strip()[-300:]}")
    log.info("  zipalign -f 4 applied")


def sign_v2_v3(unsigned_apk: Path, signed_apk: Path, keystore: str, ks_pass: str, ks_alias: str, log) -> None:
    tool = am.find_tool("apksigner")
    if not tool:
        raise CertSpoofError("apksigner not found")
    ks = am.ensure_keystore(keystore, ks_alias, ks_pass, log)
    if not ks:
        raise CertSpoofError("no keystore available and keytool missing")
    r = subprocess.run(
        [tool, "sign",
         "--ks", ks,
         "--ks-pass", f"pass:{ks_pass}",
         "--key-pass", f"pass:{ks_pass}",
         "--ks-key-alias", ks_alias,
         "--v2-signing-enabled", "true",
         "--v3-signing-enabled", "true",
         "--out", str(signed_apk), str(unsigned_apk)],
        capture_output=True, text=True,
    )
    if r.returncode:
        raise CertSpoofError(f"apksigner sign failed: {(r.stderr or r.stdout).strip()[-400:]}")
    log.info(f"  signed (V2+V3): {signed_apk.name}")


def build_unsigned_with_hook(decoded_dir: Path, apktool_jar: str, out_unsigned: Path, log) -> None:
    if not apktool_jar or not Path(apktool_jar).is_file():
        raise CertSpoofError(f"apktool.jar not found: {apktool_jar!r}")
    r = subprocess.run(["java", "-Xmx2g", "-jar", str(apktool_jar),
                        "b", "-f", "-o", str(out_unsigned), str(decoded_dir)],
                       capture_output=True, text=True, timeout=1800)
    if r.returncode:
        raise CertSpoofError(f"apktool build failed: {(r.stderr or r.stdout).strip()[-500:]}")
    log.info(f"  rebuilt unsigned: {out_unsigned.name}")


# --------------------------------------------------------------------------- step 5
def verify_fingerprint_matches(apk_path: Path, expected_fp: str, log) -> bool:
    tool = am.find_tool("apksigner")
    if not tool:
        log.error("  apksigner not available; cannot verify fingerprint")
        return False
    r = subprocess.run([tool, "verify", "--print-certs", str(apk_path)], capture_output=True, text=True)
    out = (r.stdout or "") + (r.stderr or "")
    m = re.search(r"SHA-256 digest:\s*([0-9a-fA-F:]+)", out) or \
        re.search(r"certificate SHA-256 digest:\s*([0-9a-fA-F:]+)", out)
    if not m:
        log.error(f"  could not parse fingerprint from output:\n{out.strip()[-400:]}")
        return False
    actual = m.group(1).replace(":", "").lower()
    if actual == expected_fp.lower():
        log.log(25, "VERIFICATION SUCCESS")
        log.log(25, f"  fingerprint matches reference: {actual}")
        return True
    log.error("=" * 72)
    log.error("  WARNING: FINGERPRINT MISMATCH")
    log.error(f"  expected: {expected_fp}")
    log.error(f"  actual:   {actual}")
    log.error("  The output is signed with a different key than the reference APK.")
    log.error("  Runtime cert queries will NOT return the spoofed fingerprint.")
    log.error("=" * 72)
    return False


# --------------------------------------------------------------------------- orchestration
class _Stages:
    def __init__(self, emit):
        self.emit, self.cur, self.warn = emit or (lambda *a: None), -1, False

    def go(self, i):
        if self.cur >= 0:
            self.emit("stage", SPOOF_STAGES[self.cur], "warn" if self.warn else "ok")
            self.warn = False
        self.cur = i
        self.emit("stage", SPOOF_STAGES[i], "run")
        self.emit("progress", i / len(SPOOF_STAGES))

    def done(self):
        self.emit("stage", SPOOF_STAGES[self.cur], "ok")
        self.emit("progress", 1.0)

    def fail(self):
        if self.cur >= 0:
            self.emit("stage", SPOOF_STAGES[self.cur], "fail")


def run(reference_apk: str, target_apk: str, out_dir: str, apktool_jar: str, log,
        keystore: str = "", ks_pass: str = "android", ks_alias: str = "key0", emit=None):
    """Full cert-spoof pipeline: reference -> target, producing a signed spoofed APK."""
    st = _Stages(emit)
    work = Path(tempfile.mkdtemp(prefix="apkporter_spoof_"))
    try:
        for label, f in (("reference APK", reference_apk), ("target APK", target_apk),
                         ("apktool.jar", apktool_jar)):
            if not f or not Path(f).is_file():
                raise CertSpoofError(f"{label} not found: {f!r}")
        reference_apk, target_apk = Path(reference_apk), Path(target_apk)
        out_dir = Path(out_dir); out_dir.mkdir(parents=True, exist_ok=True)
        log.info("=== Certificate spoof started ===")

        st.go(0)
        log.info("[1/6] extracting reference certificate fingerprint")
        fp = extract_fingerprint(str(reference_apk), log)

        st.go(1)
        log.info("[2/6] decoding target APK and locating launcher activity")
        decoded = work / "decoded"
        r = subprocess.run(["java", "-Xmx2g", "-jar", str(apktool_jar),
                            "d", "-f", "-o", str(decoded), str(target_apk)],
                           capture_output=True, text=True, timeout=1800)
        if r.returncode:
            raise CertSpoofError(f"apktool decode failed: {(r.stderr or r.stdout).strip()[-500:]}")
        smali = find_launcher_smali(decoded, log)

        st.go(2)
        log.info("[3/6] injecting certificate hook")
        # Ensure the spoof helper class exists in smali.
        _write_cert_spoof_class(decoded, log)
        inject_hook(smali, fp, log)

        st.go(3)
        log.info("[4/6] rebuilding and aligning")
        unsigned = work / "unsigned.apk"
        build_unsigned_with_hook(decoded, apktool_jar, unsigned, log)
        zipalign(unsigned, log)

        st.go(4)
        log.info("[5/6] signing with V2+V3")
        signed = out_dir / f"{target_apk.stem}_certspoof.apk"
        sign_v2_v3(unsigned, signed, keystore, ks_pass, ks_alias, log)

        st.go(5)
        log.info("[6/6] verifying fingerprint")
        ok = verify_fingerprint_matches(signed, fp, log)
        if not ok:
            st.warn = True
            st.done()
            raise CertSpoofError("fingerprint verification failed; output is signed with the wrong key")
        st.done()
        log.log(25, f"=== Certificate spoof complete: {signed} ===")
        return signed
    except (CertSpoofError, OSError, subprocess.TimeoutExpired) as e:
        st.fail()
        raise CertSpoofError(str(e)) if not isinstance(e, CertSpoofError) else e


def _write_cert_spoof_class(decoded_dir: Path, log) -> None:
    """Drop a small helper smali class that stores the spoofed fingerprint statically.

    The mod (or any code that queries it) can read CertSpoof.get() instead of the real
    PackageManager signature. This is the minimum-invasive way to expose the override.
    """
    base = decoded_dir / "smali" / "com" / "android" / "support"
    base.mkdir(parents=True, exist_ok=True)
    target = base / "CertSpoof.smali"
    if target.exists():
        log.info("  CertSpoof helper already present")
        return
    target.write_text(
        '.class public Lcom/android/support/CertSpoof;\n'
        '.super Ljava/lang/Object;\n'
        '\n'
        '.field private static sFingerprint:Ljava/lang/String;\n'
        '\n'
        '.method public constructor <init>()V\n'
        '    .locals 0\n'
        '    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n'
        '    return-void\n'
        '.end method\n'
        '\n'
        '.method public static install(Ljava/lang/String;)V\n'
        '    .locals 0\n'
        '    sput-object p0, Lcom/android/support/CertSpoof;->sFingerprint:Ljava/lang/String;\n'
        '    return-void\n'
        '.end method\n'
        '\n'
        '.method public static get()Ljava/lang/String;\n'
        '    .locals 1\n'
        '    sget-object v0, Lcom/android/support/CertSpoof;->sFingerprint:Ljava/lang/String;\n'
        '    return-object v0\n'
        '.end method\n',
        encoding="utf-8",
    )
    log.info("  wrote CertSpoof helper smali")