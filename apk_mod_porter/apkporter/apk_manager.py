"""APK Manager: open (incl. split bundles), rebuild with alignment, sign, and tool discovery."""
import glob
import os
import re
import shutil
import struct
import subprocess
import zipfile
from pathlib import Path

SO_ALIGN = 16384   # 16 KB satisfies both 4 KB and 16 KB page-size requirements
DEF_ALIGN = 4


def is_signature(path: str) -> bool:
    p = path.upper()
    return (p == "STAMP-CERT-SHA256" or
            p.startswith("META-INF/") and p.endswith((".RSA", ".DSA", ".EC", ".SF", ".MF")))


def _is_config(name):
    return name.lower().startswith(("config.", "split_config.", "split_"))


class ApkSet:
    """One APK, or a bundle (.apks/.xapk/.zip) of splits, presented as ONE flat file namespace.

    Keys are always ("", inner_path), so a bundle can be compared with a single merged APK.
    If a path exists in several splits (for example AndroidManifest.xml) the base split wins.
    `member_of(path)` says which split really holds the file, for writing patches back.
    """

    def __init__(self, path, workdir, log):
        self.path, self.log = Path(path), log
        self.members = {}
        self._zips = {}
        self._idx = None
        self._where = {}
        self.duplicates = 0
        with zipfile.ZipFile(self.path) as z:
            names = z.namelist()
            nested = [n for n in names if n.lower().endswith(".apk")]
            self.bundle = bool(nested) and "AndroidManifest.xml" not in names
            if self.bundle:
                dest = Path(workdir) / self.path.stem
                dest.mkdir(parents=True, exist_ok=True)
                for n in nested:
                    t = dest / Path(n).name
                    t.write_bytes(z.read(n))
                    self.members[Path(n).name] = t
                log.info(f"  {self.path.name}: split bundle with {len(nested)} APKs: "
                         + ", ".join(sorted(self.members)))
            else:
                self.members[""] = self.path

    def _zip(self, member):
        if member not in self._zips:
            self._zips[member] = zipfile.ZipFile(self.members[member])
        return self._zips[member]

    def _build(self):
        if self._idx is not None:
            return
        best = {}
        for m in self.members:
            for i in self._zip(m).infolist():
                if i.is_dir():
                    continue
                rank = (0 if _is_config(m) else 1, i.file_size)
                cur = best.get(i.filename)
                if cur is None:
                    best[i.filename] = (rank, m, i.CRC, i.file_size)
                else:
                    self.duplicates += 1
                    if rank > cur[0]:
                        best[i.filename] = (rank, m, i.CRC, i.file_size)
        self._idx = {("", p): (v[2], v[3]) for p, v in best.items()}
        self._where = {p: v[1] for p, v in best.items()}

    def index(self):
        self._build()
        return self._idx

    def read(self, key):
        self._build()
        return self._zip(self._where[key[1]]).read(key[1])

    def member_of(self, path):
        self._build()
        return self._where.get(path)

    def member_for_new(self, path):
        """Split that should hold `path`: its current split, else the split holding its siblings."""
        m = self.member_of(path)
        if m is not None:
            return m
        prefix = "/".join(path.split("/")[:2]) + "/"
        counts = {}
        for p, mm in self._where.items():
            if p.startswith(prefix):
                counts[mm] = counts.get(mm, 0) + 1
        if counts:
            return max(counts, key=counts.get)
        return next((m for m in self.members if not _is_config(m)), next(iter(self.members)))

    def close(self):
        for z in self._zips.values():
            z.close()


def _write_entry(zout, name, data, ctype, date_time, ext_attr):
    """Write one entry; stored entries get padded so their data starts on an aligned offset."""
    zi = zipfile.ZipInfo(name, date_time)
    zi.compress_type = ctype
    zi.external_attr = ext_attr
    if ctype == zipfile.ZIP_STORED:
        align = SO_ALIGN if name.endswith(".so") else DEF_ALIGN
        base = zout.fp.tell() + 30 + len(name.encode("utf-8"))
        pad = (-base) % align
        if 0 < pad < 4:
            pad += align
        if pad:
            zi.extra = struct.pack("<HH", 0xD935, pad - 4) + b"\0" * (pad - 4)
    zout.writestr(zi, data)


def rebuild(src, dest, replace, add, log):
    """Copy src to dest without old signatures, swapping `replace` entries and appending `add`."""
    names = set()
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dest, "w") as zout:
        for info in zin.infolist():
            if info.is_dir() or is_signature(info.filename):
                continue
            data = replace.get(info.filename)
            if data is None:
                data = zin.read(info)
            _write_entry(zout, info.filename, data, info.compress_type, info.date_time, info.external_attr)
            names.add(info.filename)
        for name, data in add.items():
            if name not in names:
                ctype = zipfile.ZIP_STORED if name.endswith(".so") else zipfile.ZIP_DEFLATED
                _write_entry(zout, name, data, ctype, (2026, 1, 1, 0, 0, 0), 0o600 << 16)
    log.info(f"  rebuilt {Path(dest).name}: {len(replace)} replaced, {len(add)} added, old signatures dropped, aligned in-process")


def check_alignment(apk):
    bad = []
    with zipfile.ZipFile(apk) as z:
        for i in z.infolist():
            if i.compress_type == zipfile.ZIP_STORED and not i.is_dir():
                off = i.header_offset + 30 + len(i.filename.encode("utf-8")) + _local_extra_len(apk, i.header_offset)
                need = SO_ALIGN if i.filename.endswith(".so") else DEF_ALIGN
                if off % need:
                    bad.append(i.filename)
    return bad


def _local_extra_len(apk, header_offset):
    with open(apk, "rb") as f:
        f.seek(header_offset + 28)
        return struct.unpack("<H", f.read(2))[0]


# ---- external tools ----------------------------------------------------------
def find_tool(name):
    p = shutil.which(name)
    if p:
        return p
    for root in (os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
                 str(Path.home() / "Android" / "Sdk"), str(Path.home() / "AppData/Local/Android/Sdk")):
        if root:
            hits = sorted(glob.glob(os.path.join(root, "build-tools", "*", name + "*")))
            if hits:
                return hits[-1]
    return None


def ensure_keystore(path, alias, password, log):
    if path and Path(path).exists():
        return path
    keytool = shutil.which("keytool")
    if not keytool:
        return None
    path = path or str(Path.home() / ".apkporter" / "debug.keystore")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    log.info(f"  generating a debug keystore at {path}")
    r = subprocess.run([keytool, "-genkeypair", "-keystore", path, "-storepass", password, "-keypass", password,
                        "-alias", alias, "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
                        "-dname", "CN=APK Porter Debug"], capture_output=True, text=True)
    if r.returncode:
        log.error(f"  keytool failed: {r.stderr.strip()}")
        return None
    return path


def sign(unsigned, signed, keystore, alias, password, log):
    tool = find_tool("apksigner")
    if not tool:
        log.warning("  apksigner not found (install Android build-tools, or set ANDROID_HOME)")
        return False
    ks = ensure_keystore(keystore, alias, password, log)
    if not ks:
        log.warning("  no keystore available and keytool missing")
        return False
    r = subprocess.run([tool, "sign", "--ks", ks, "--ks-pass", f"pass:{password}", "--key-pass", f"pass:{password}",
                        "--ks-key-alias", alias, "--out", str(signed), str(unsigned)], capture_output=True, text=True)
    if r.returncode:
        log.error(f"  apksigner failed: {(r.stderr or r.stdout).strip()}")
        return False
    log.info(f"  signed {Path(signed).name}")
    return True


def verify_signature(apk):
    tool = find_tool("apksigner")
    if not tool:
        return None, "apksigner not available"
    r = subprocess.run([tool, "verify", str(apk)], capture_output=True, text=True)
    return r.returncode == 0, (r.stderr or r.stdout).strip() or "verified"


def _expand_signer_template(template: str, apk_path: str, out_dir: str):
    ap = Path(apk_path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    return template.format(apk=str(ap), apk_path=str(ap), out=str(out), out_dir=str(out), file=str(ap), output_dir=str(out))


def run_custom_signer(apk_path, out_dir, signer_cmd, log, signer_args=""):
    if not signer_cmd or not str(signer_cmd).strip():
        log.warning("  no custom signer configured")
        return None
    apk = Path(apk_path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    before = {p: p.stat().st_mtime_ns for p in out.iterdir() if p.is_file() and p.suffix.lower() == ".apk"}
    cmd = str(signer_cmd).strip()
    has_signer_flags = re.search(r"(?:^|\s)(?:-a|--apks|-o|--out|-out)(?:$|\s)", cmd, re.IGNORECASE)
    if Path(cmd).suffix.lower() == ".jar" and not has_signer_flags:
        cmd = f'java -jar "{cmd}" -a "{apk}" -o "{out}"'
    else:
        cmd = f"{cmd} {signer_args}".strip()
        cmd = _expand_signer_template(cmd, str(apk), str(out))
    if not cmd.strip():
        log.error("  custom signer command is empty")
        return None
    log.info(f"  running custom signer: {cmd[:120]} ...")
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if r.returncode:
        log.error(f"  custom signer failed: {(r.stderr or r.stdout).strip()}")
        return None
    candidates = sorted(
        [p for p in out.iterdir() if p.is_file() and p.suffix.lower() == ".apk"
         and (p not in before or p.stat().st_mtime_ns > before[p])],
        key=lambda p: p.stat().st_mtime_ns,
        reverse=True,
    )
    if candidates:
        log.info(f"  custom signer produced {candidates[0].name}")
        return candidates[0]
    fallback = out / apk.name
    if fallback.exists():
        return fallback
    log.warning(f"  custom signer returned successfully but no APK was produced in {out}")
    return None
