"""Binary Matching Engine: function fingerprints, candidate generation, scoring with evidence."""
import bisect
import hashlib
from dataclasses import dataclass, field

import numpy as np

from .aarch64 import bl_targets, normalise
from .elf import Elf


def _h(arr):
    return hashlib.blake2b(np.ascontiguousarray(arr).tobytes(), digest_size=10).digest()


class NativeIndex:
    """All functions of a library's main executable section, with fingerprints."""

    def __init__(self, data: bytes, symbols=None):
        self.elf = Elf(data)
        self.sec = self.elf.text_section()
        n = self.sec.size // 4
        self.words = np.frombuffer(data, dtype="<u4", count=n, offset=self.sec.offset)
        self.norm = normalise(self.words)
        self.cls = self.norm >> np.uint32(21)
        starts = self.elf.function_starts(self.sec)
        self.boundary_source = self.elf.boundary_source
        self.starts = np.array(starts, dtype=np.int64)
        ends = np.append(self.starts[1:], self.sec.addr + self.sec.size)
        self.first = (self.starts - self.sec.addr) // 4
        self.count = (ends - self.starts) // 4
        self.sym = symbols or {}
        self.l2, self.by_l2, self.by_prefix, self.by_name = [], {}, {}, {}
        for i in range(len(self.starts)):
            a, c = int(self.first[i]), int(self.count[i])
            h = _h(self.norm[a:a + c])
            self.l2.append(h)
            self.by_l2.setdefault(h, []).append(i)
            self.by_prefix.setdefault(_h(self.norm[a:a + min(8, c)]), []).append(i)
            k = self.sym.get(int(self.starts[i]))
            if k:
                self.by_name.setdefault(k, []).append(i)
        self._callee = {}

    def __len__(self):
        return len(self.starts)

    def func_at(self, vaddr):
        k = int(np.searchsorted(self.starts, vaddr))
        return k if k < len(self.starts) and int(self.starts[k]) == vaddr else None

    def sl(self, arr, i):
        a = int(self.first[i])
        return arr[a:a + int(self.count[i])]

    def name(self, i):
        return self.sym.get(int(self.starts[i]))

    def callee_sig(self, i):
        if i not in self._callee:
            s = set()
            for _, t in bl_targets(self.sl(self.words, i), int(self.starts[i])):
                j = self.func_at(t)
                if j is not None and j != i:
                    s.add(self.l2[j])
            self._callee[i] = frozenset(s)
        return self._callee[i]


def _shingles(x, n=3):
    return set(zip(*[x[k:] for k in range(n)])) if len(x) >= n else {tuple(x)}


def _jac(a, b):
    return len(a & b) / len(a | b) if (a or b) else 1.0


def similarity(old, i, new, j):
    a, b = old.sl(old.norm, i).tolist(), new.sl(new.norm, j).tolist()
    if a == b:
        return 1.0, "normalised instruction stream identical"
    jn = _jac(_shingles(a), _shingles(b))
    jc = _jac(_shingles(old.sl(old.cls, i).tolist()), _shingles(new.sl(new.cls, j).tolist()))
    sr = min(len(a), len(b)) / max(len(a), len(b))
    s = 0.55 * jn + 0.30 * jc + 0.15 * sr
    return s, f"instruction 3-gram overlap {jn:.2f}, opcode-class overlap {jc:.2f}, size ratio {sr:.2f}"


def build_anchors(old, new):
    """Functions whose normalised body is unique and identical in both builds."""
    pairs = []
    for h, ol in old.by_l2.items():
        nl = new.by_l2.get(h)
        if len(ol) == 1 and nl and len(nl) == 1 and old.count[ol[0]] >= 12:
            pairs.append((ol[0], nl[0]))
    pairs.sort()
    return pairs


@dataclass
class Match:
    j: int = -1
    confidence: float = 0.0
    evidence: list = field(default_factory=list)


def match_function(old, i, new, anchors):
    ev = []
    cands = {}

    def add(j, tag):
        cands.setdefault(j, []).append(tag)

    for j in new.by_l2.get(old.l2[i], []):
        add(j, "exact")
    key = old.name(i)
    if key:
        for j in new.by_name.get(key, []):
            add(j, "name")
    for j in new.by_prefix.get(_h(old.sl(old.norm, i)[:8]), [])[:20]:
        add(j, "prefix")
    predicted = set()
    if anchors:
        keys = [a for a, _ in anchors]
        p = bisect.bisect_left(keys, i)
        for q in (p - 1, p):
            if 0 <= q < len(anchors):
                oi, nj = anchors[q]
                pj = nj + (i - oi)
                for d in range(-2, 3):
                    if 0 <= pj + d < len(new):
                        add(pj + d, "neighbour")
                if 0 <= pj < len(new):
                    predicted.add(pj)
    if not cands:
        return Match(evidence=["no candidate found by hash, name, prefix or neighbourhood"])

    n_exact = len(new.by_l2.get(old.l2[i], []))
    n_old_same = len(old.by_l2[old.l2[i]])
    scored = []
    for j, tags in cands.items():
        s, why = similarity(old, i, new, j)
        exact = s == 1.0
        raw = 97.0 if exact else 100 * s ** 1.5
        e = [why]
        if exact and (n_exact > 1 or n_old_same > 1):
            raw = 80.0
            e.append(f"body is not unique ({n_old_same} in old, {n_exact} in new)")
        nk = new.name(j)
        if key and nk:
            if key == nk:
                raw += 10
                e.append(f"IL2CPP symbol matches: {key[0]}")
            else:
                raw -= 15
                e.append(f"symbol names differ: {key[0]} vs {nk[0]}")
        cs_o, cs_n = old.callee_sig(i), new.callee_sig(j)
        if cs_o and cs_o == cs_n:
            raw += 3
            e.append(f"identical callee set ({len(cs_o)} calls)")
        if j in predicted:
            raw += 4
            e.append("position consistent with neighbouring matched functions")
        if min(old.count[i], new.count[j]) / max(old.count[i], new.count[j]) < 0.5:
            raw = min(raw, 60)
            e.append("size differs by more than 2x")
        scored.append((raw, j, e))
    scored.sort(key=lambda t: (-t[0], t[1]))
    raw, j, e = scored[0]
    if len(scored) > 1 and raw - scored[1][0] < 6:
        raw = min(raw, 65)
        e.append(f"ambiguous: runner-up at {scored[1][0]:.1f} vs best {scored[0][0]:.1f}")
    return Match(j, min(raw, 99.5), e)


def map_words(old_norm, new_norm, idxs, ctx=2):
    """Map old instruction indices to new ones. Returns (mapping|None, explanation)."""
    if old_norm == new_norm:
        return {i: i for i in idxs}, "function bodies identical after normalisation"
    from difflib import SequenceMatcher
    m = {}
    for a, b, n in SequenceMatcher(None, old_norm, new_norm, autojunk=False).get_matching_blocks():
        for k in range(n):
            m[a + k] = b + k
    out = {}
    for i in idxs:
        if i not in m:
            return None, f"patched instruction {i} has no counterpart in the new function"
        for d in range(-ctx, ctx + 1):
            j = i + d
            if 0 <= j < len(old_norm) and (j not in m or m[j] - m[i] != d):
                return None, f"code around patched instruction {i} changed in the new version"
        out[i] = m[i]
    return out, "aligned by sequence matching with intact context"
