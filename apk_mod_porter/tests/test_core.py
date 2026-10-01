"""End-to-end test on synthetic ELF/APK fixtures (no game files needed). Run: python -m unittest -v"""
import logging
import random
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from apkporter import logutil
from apkporter.aarch64 import RET, is_pc_relative, normalise
from apkporter.apk_manager import check_alignment
from apkporter.models import Config
from apkporter.pipeline import Pipeline

MOV_W0_1 = 0x52800020


def make_funcs(seed, n=80):
    rnd = random.Random(seed)
    funcs = []
    for _ in range(n):
        body = []
        while len(body) < rnd.randint(24, 60):
            w = rnd.getrandbits(32)
            if not is_pc_relative(w) and w != RET:
                body.append(w)
        funcs.append(body + [RET])
    return funcs


def make_elf(funcs, text_addr=0x100000):
    text = b"".join(struct.pack("<I", w) for f in funcs for w in f)
    starts, a = [], text_addr
    for f in funcs:
        starts.append(a)
        a += 4 * len(f)
    off_text = 0x1000
    hdr_off = off_text + len(text)
    hdr_addr = text_addr + len(text)
    eh = struct.pack("<BBBB", 1, 0x03, 0x03, 0x3B) + struct.pack("<II", 0, len(starts))
    eh += b"".join(struct.pack("<ii", s - hdr_addr, 0) for s in starts)
    names = b"\0.text\0.eh_frame_hdr\0.shstrtab\0"
    str_off = hdr_off + len(eh)
    sh_off = (str_off + len(names) + 7) // 8 * 8

    def sh(n, t, fl, ad, of, sz):
        return struct.pack("<IIQQQQIIQQ", n, t, fl, ad, of, sz, 0, 0, 1, 0)
    shdrs = b"\0" * 64 + sh(1, 1, 6, text_addr, off_text, len(text)) + sh(7, 1, 2, hdr_addr, hdr_off, len(eh)) \
        + sh(21, 3, 0, 0, str_off, len(names))
    head = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8 + struct.pack("<HHIQQQIHHHHHH", 3, 0xB7, 1, 0, 0, sh_off, 0, 64, 0, 0, 64, 4, 3)
    blob = bytearray(head.ljust(off_text, b"\0")) + text + eh + names
    blob = blob.ljust(sh_off, b"\0") + shdrs
    return bytes(blob)


def make_apk(path, lib, extra=None):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", b"manifest")
        z.writestr("classes.dex", b"dex")
        z.writestr("lib/arm64-v8a/libil2cpp.so", lib)
        for k, v in (extra or {}).items():
            z.writestr(k, v)


class Core(unittest.TestCase):
    def test_normalise_moves(self):
        bl_a, bl_b = 0x94000010, 0x94000200
        self.assertEqual(int(normalise([bl_a])[0]), int(normalise([bl_b])[0]))

    def run_case(self, mod_words, new_mutate, extra_mod=None):
        logs = []
        log = logutil.setup(callback=lambda lv, m: logs.append((lv, m)))
        tmp = Path(tempfile.mkdtemp())
        old = make_funcs(1)
        mod = [f[:] for f in old]
        for idx, (k, v) in mod_words.items():
            mod[idx][k] = v
        new = [f[:] for f in old]
        new_mutate(new)
        make_apk(tmp / "off.apk", make_elf(old), {"assets/a.bin": b"same"})
        make_apk(tmp / "mod.apk", make_elf(mod), {"assets/a.bin": b"modded!", "assets/extra.txt": b"x", **(extra_mod or {})})
        make_apk(tmp / "new.apk", make_elf(new), {"assets/a.bin": b"same"})
        cfg = Config(str(tmp / "mod.apk"), str(tmp / "off.apk"), str(tmp / "new.apk"), str(tmp / "out"))
        p = Pipeline(cfg, log)
        res = p.analyse()
        return tmp, cfg, p, res, logs

    def test_port_moved_and_edited_function(self):
        def mutate(new):
            new.insert(0, make_funcs(99, 3)[0])          # everything shifts
            new[41][10] ^= 0x00100000                     # small unrelated change inside the target function
        tmp, cfg, p, res, _ = self.run_case({40: (5, MOV_W0_1)}, mutate)
        self.assertEqual(len(res.native), 1)
        t = res.native[0]
        self.assertIn(t.status, ("matched", "review"), (t.status, t.message, t.evidence))
        self.assertEqual(t.new_vaddr - t.old_vaddr, 4 * (len(make_funcs(99, 3)[0])))
        cfg.apply_review = True
        out = p.build(res)
        self.assertTrue(all(c.ok for c in out.checks), [c for c in out.checks if not c.ok])
        apk = [o for o in out.outputs][0]
        self.assertEqual(check_alignment(apk), [])
        with zipfile.ZipFile(apk) as z:
            data = z.read("lib/arm64-v8a/libil2cpp.so")
            self.assertEqual(z.read("assets/a.bin"), b"modded!")
        off = 0x1000 + (t.new_vaddr - 0x100000) + 4 * 5
        self.assertEqual(struct.unpack_from("<I", data, off)[0], MOV_W0_1)

    def test_refuses_when_function_rewritten(self):
        def mutate(new):
            new[40] = make_funcs(1234, 1)[0]              # function replaced wholesale
        tmp, cfg, p, res, _ = self.run_case({40: (5, MOV_W0_1)}, mutate)
        self.assertNotEqual(res.native[0].status, "matched")
        out = p.build(res)
        self.assertFalse(out.ok)
        self.assertIn("Manual analysis required", out.message)
        self.assertEqual(out.outputs, [])

    def test_custom_signer_helper_invokes_commands(self):
        from apkporter import apk_manager as am
        tmp = Path(tempfile.mkdtemp())
        apk = tmp / "demo.apk"
        apk.write_bytes(b"apk")
        script = tmp / "fake_signer.py"
        script.write_text(
            "import os, sys\n"
            "src = sys.argv[sys.argv.index('--apk') + 1]\n"
            "dst = sys.argv[sys.argv.index('--out') + 1]\n"
            "dst_path = dst if os.path.isfile(dst) else os.path.join(dst, os.path.basename(src))\n"
            "os.makedirs(os.path.dirname(dst_path) or '.', exist_ok=True)\n"
            "with open(dst_path, 'wb') as f: f.write(open(src, 'rb').read())\n",
            encoding="utf-8",
        )
        out_dir = tmp / "signed"
        out_dir.mkdir()
        cmd = f'python "{script.as_posix()}" --apk "{{apk}}" --out "{{out}}"'
        ok = am.run_custom_signer(str(apk), str(out_dir), cmd, logging.getLogger("test"))
        self.assertTrue(ok)
        self.assertTrue((out_dir / "demo.apk").exists())

    def test_custom_signer_ignores_stale_apks(self):
        from apkporter import apk_manager as am
        tmp = Path(tempfile.mkdtemp())
        apk = tmp / "demo.apk"
        apk.write_bytes(b"apk")
        out_dir = tmp / "signed"
        out_dir.mkdir()
        (out_dir / "old_sakizu.apk").write_bytes(b"stale")
        script = tmp / "fake_signer.py"
        script.write_text(
            "import os, sys\n"
            "src = sys.argv[sys.argv.index('--apk') + 1]\n"
            "dst = os.path.join(sys.argv[sys.argv.index('--out') + 1], 'new_deepmods.apk')\n"
            "with open(dst, 'wb') as f: f.write(open(src, 'rb').read())\n",
            encoding="utf-8",
        )
        cmd = f'python "{script.as_posix()}" --apk "{{apk}}" --out "{{out}}"'
        result = am.run_custom_signer(str(apk), str(out_dir), cmd, logging.getLogger("test"))
        self.assertEqual(result, out_dir / "new_deepmods.apk")


if __name__ == "__main__":
    unittest.main()
