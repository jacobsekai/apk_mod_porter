"""Small AArch64 helpers: normalise position-dependent instructions, find BL targets.

Normalisation masks the PC-relative immediate of branches, ADR/ADRP, literal loads and
compare/test-and-branch instructions, so the same code hashes identically after it moves.
"""
import numpy as np

RET = 0xD65F03C0
NOP = 0xD503201F
# (mask, value, bits kept)
_RULES = [
    (0x7C000000, 0x14000000, 0xFC000000),  # B / BL
    (0x1F000000, 0x10000000, 0x9F00001F),  # ADR / ADRP
    (0x3B000000, 0x18000000, 0xFF00001F),  # LDR (literal)
    (0xFF000010, 0x54000000, 0xFF00001F),  # B.cond
    (0x7E000000, 0x34000000, 0xFF00001F),  # CBZ / CBNZ
    (0x7E000000, 0x36000000, 0xFFF8001F),  # TBZ / TBNZ
]


def normalise(words):
    w = np.asarray(words, dtype=np.uint32)
    out = w.copy()
    for mask, val, keep in _RULES:
        m = (w & np.uint32(mask)) == np.uint32(val)
        out[m] = w[m] & np.uint32(keep)
    return out


def pc_relative(words):
    w = np.asarray(words, dtype=np.uint32)
    r = np.zeros(w.shape, dtype=bool)
    for mask, val, _ in _RULES:
        r |= (w & np.uint32(mask)) == np.uint32(val)
    return r


def is_pc_relative(word):
    return bool(pc_relative(np.array([word], dtype=np.uint32))[0])


def bl_targets(words, base_vaddr):
    """Return [(instruction_index, target_vaddr)] for every BL in `words`."""
    w = np.asarray(words, dtype=np.uint32)
    idx = np.nonzero((w & np.uint32(0xFC000000)) == np.uint32(0x94000000))[0]
    imm = (w[idx] & np.uint32(0x03FFFFFF)).astype(np.int64)
    imm = np.where(imm & 0x02000000, imm - 0x04000000, imm)
    return [(int(i), base_vaddr + 4 * int(i) + 4 * int(d)) for i, d in zip(idx, imm)]


def is_prologue(w):
    """stp x29, x30, [sp, #imm]!  or  sub sp, sp, #imm"""
    return (w & 0xFFC07FFF) == 0xA9807BFD or (w & 0xFF0003FF) == 0xD10003FF
