"""Minimal ELF64 (little endian) reader: sections and function boundaries."""
import struct
from dataclasses import dataclass

import numpy as np

from .aarch64 import RET, NOP, is_prologue

SHF_ALLOC, SHF_EXEC = 2, 4
SHT_NOBITS = 8
MACHINES = {0xB7: "AArch64", 0x28: "ARM", 0x3E: "x86-64", 0x03: "x86"}


@dataclass
class Section:
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int

    @property
    def is_exec(self):
        return bool(self.flags & SHF_EXEC)


class Elf:
    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 0x40 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("not an ELF64 little-endian file")
        self.machine = struct.unpack_from("<H", data, 0x12)[0]
        self.arch = MACHINES.get(self.machine, hex(self.machine))
        shoff = struct.unpack_from("<Q", data, 0x28)[0]
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
        if not shoff or shentsize < 64 or shoff + shnum * shentsize > len(data):
            raise ValueError("section header table missing or truncated")
        raw = [struct.unpack_from("<IIQQQQ", data, shoff + i * shentsize) for i in range(shnum)]
        so, ss = raw[shstrndx][4], raw[shstrndx][5]
        strtab = data[so:so + ss]
        self.sections = []
        for name_i, typ, flags, addr, off, size in raw:
            end = strtab.find(b"\0", name_i)
            self.sections.append(Section(strtab[name_i:end].decode("ascii", "replace"), typ, flags, addr, off, size))

    def section(self, name):
        return next((s for s in self.sections if s.name == name), None)

    def layout(self):
        return [(s.name, s.type, s.flags, s.addr, s.offset, s.size) for s in self.sections]

    def text_section(self):
        t = self.section(".text")
        if t and t.is_exec:
            return t
        ex = [s for s in self.sections if s.is_exec and s.size]
        if not ex:
            raise ValueError("no executable section")
        return max(ex, key=lambda s: s.size)

    # ---- function boundaries -------------------------------------------------
    def function_starts(self, sec: Section):
        """Prefer .eh_frame_hdr (exact); fall back to a prologue scan."""
        starts = self._from_eh_frame_hdr(sec)
        if starts:
            self.boundary_source = ".eh_frame_hdr"
            return starts
        self.boundary_source = "prologue scan (heuristic)"
        return self._prologue_scan(sec)

    def _read_enc(self, pos, enc, vaddr_of_pos, hdr_vaddr):
        fmt, app = enc & 0x0F, enc & 0x70
        d = self.data
        if fmt == 0x03:
            v, n = struct.unpack_from("<I", d, pos)[0], 4
        elif fmt == 0x0B:
            v, n = struct.unpack_from("<i", d, pos)[0], 4
        elif fmt == 0x04:
            v, n = struct.unpack_from("<Q", d, pos)[0], 8
        elif fmt == 0x0C:
            v, n = struct.unpack_from("<q", d, pos)[0], 8
        else:
            raise ValueError("unsupported eh_frame_hdr encoding")
        if app == 0x10:
            v += vaddr_of_pos
        elif app == 0x30:
            v += hdr_vaddr
        return v, pos + n

    def _from_eh_frame_hdr(self, sec):
        hdr = self.section(".eh_frame_hdr")
        if not hdr or hdr.size < 12:
            return []
        try:
            b = hdr.offset
            ver, ptr_enc, cnt_enc, tab_enc = self.data[b:b + 4]
            if ver != 1 or cnt_enc == 0xFF or tab_enc == 0xFF:
                return []
            pos = b + 4
            _, pos = self._read_enc(pos, ptr_enc, hdr.addr + (pos - b), hdr.addr)
            count, pos = self._read_enc(pos, cnt_enc, hdr.addr + (pos - b), hdr.addr)
            out = set()
            for _ in range(count):
                start, pos = self._read_enc(pos, tab_enc, hdr.addr + (pos - b), hdr.addr)
                _, pos = self._read_enc(pos, tab_enc, hdr.addr + (pos - b), hdr.addr)
                if sec.addr <= start < sec.addr + sec.size and start % 4 == 0:
                    out.add(start)
            return sorted(out)
        except (ValueError, struct.error):
            return []

    def _prologue_scan(self, sec):
        w = np.frombuffer(self.data, dtype="<u4", count=sec.size // 4, offset=sec.offset)
        out = [sec.addr]
        for i in range(1, len(w)):
            if is_prologue(int(w[i])) and int(w[i - 1]) in (RET, NOP, 0) or \
                    (is_prologue(int(w[i])) and (int(w[i - 1]) & 0xFC000000) == 0x14000000):
                out.append(sec.addr + 4 * i)
        return sorted(set(out))
