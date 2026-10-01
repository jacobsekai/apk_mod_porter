"""Verification Engine: integrity, alignment, and 'nothing else changed' checks on the output."""
import zipfile

import numpy as np

from .apk_manager import check_alignment, verify_signature
from .elf import Elf
from .models import Check


def verify_output(apk_path, member, new_set, natives, expect_signed, log):
    checks = []

    def add(name, ok, detail=""):
        checks.append(Check(name, bool(ok), detail))
        (log.log(25, f"    PASS {name} {detail}") if ok else log.error(f"    FAIL {name} {detail}"))

    with zipfile.ZipFile(apk_path) as z:
        bad = z.testzip()
        names = set(z.namelist())
        add("zip integrity", bad is None, f"first bad entry: {bad}" if bad else "")
        add("AndroidManifest.xml present", "AndroidManifest.xml" in names)
        for t in natives:
            if new_set.member_of(t.path) != member or t.status != "applied":
                continue
            out = z.read(t.path)
            ref = new_set.read(("", t.path))
            try:
                Elf(out)
                add(f"ELF parses ({t.path})", True)
            except ValueError as e:
                add(f"ELF parses ({t.path})", False, str(e))
                continue
            add(f"size unchanged ({t.path})", len(out) == len(ref))
    mine = [t for t in natives if new_set.member_of(t.path) == member and t.status == "applied"]
    for path in sorted({t.path for t in mine}):
        with zipfile.ZipFile(apk_path) as z:
            out = np.frombuffer(z.read(path), dtype=np.uint8)
        ref = np.frombuffer(new_set.read(("", path)), dtype=np.uint8)
        if len(out) != len(ref):
            continue
        allowed = np.zeros(len(out), dtype=bool)
        for t in mine:
            if t.path == path:
                for e in t.mapped:
                    allowed[e["offset"]:e["offset"] + 4] = True
        stray = np.nonzero((out != ref) & ~allowed)[0]
        add(f"only planned bytes differ from official ({path})", not len(stray),
            f"{len(stray)} unexpected byte differences" if len(stray) else f"{int((out != ref).sum())} bytes changed, all planned")
    bad = check_alignment(apk_path)
    add("stored entries aligned", not bad, f"misaligned: {bad[:3]}" if bad else "")
    if expect_signed:
        ok, msg = verify_signature(apk_path)
        if ok is None:
            log.warning(f"    SKIP signature verification: {msg}")
        else:
            add("apksigner verify", ok, msg)
    return checks
