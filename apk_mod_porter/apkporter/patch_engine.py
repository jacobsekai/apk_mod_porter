"""Patch Engine: derive patches (modded vs old official), plan them for the new build, apply them."""
import json
import struct
from dataclasses import asdict

import numpy as np

from .aarch64 import is_pc_relative
from .matching import NativeIndex, map_words
from .models import NativeTarget, WordPatch


def sym_name(idx, i):
    k = idx.name(i)
    return k[0] if k else f"sub_{int(idx.starts[i]):X}"


def extract_native_targets(key, off_idx: NativeIndex, off_data, mod_data, log):
    """Word-level diff of the executable section, grouped per function. Returns (targets, issues)."""
    from .elf import Elf, SHT_NOBITS, SHF_ALLOC
    issues, targets = [], []
    label = f"{key[0]}::{key[1]}" if key[0] else key[1]
    try:
        mod_elf = Elf(mod_data)
    except ValueError as e:
        return [], [f"{label}: modded library is not a valid ELF ({e})"]
    if mod_elf.layout() != off_idx.elf.layout():
        return [], [f"{label}: section layout differs between official and modded library; "
                    f"in-place patching assumption broken. Manual analysis required."]
    sec = off_idx.sec
    for s in off_idx.elf.sections:
        if s is sec or s.type == SHT_NOBITS or not (s.flags & SHF_ALLOC):
            continue
        if off_data[s.offset:s.offset + s.size] != mod_data[s.offset:s.offset + s.size]:
            issues.append(f"{label}: section {s.name} ({'code' if s.is_exec else 'data'}) modified; "
                          f"only {sec.name} is patchable automatically")
    mod_words = np.frombuffer(mod_data, dtype="<u4", count=sec.size // 4, offset=sec.offset)
    diff = np.nonzero(off_idx.words != mod_words)[0]
    log.info(f"  {label}: {len(diff)} modified instruction words in {sec.name}")
    if not len(diff):
        return [], issues
    fi = np.searchsorted(off_idx.first, diff, side="right") - 1
    groups = {}
    for w, f in zip(diff.tolist(), fi.tolist()):
        if f < 0 or w >= off_idx.first[f] + off_idx.count[f]:
            issues.append(f"{label}: modified word at {sec.addr + 4 * w:#x} lies outside any known function")
            continue
        groups.setdefault(f, []).append(w - int(off_idx.first[f]))
    for f, idxs in sorted(groups.items()):
        base = int(off_idx.first[f])
        t = NativeTarget(id=f"N{len(targets) + 1}", member=key[0], path=key[1],
                         old_vaddr=int(off_idx.starts[f]), old_size=int(off_idx.count[f]) * 4,
                         old_name=sym_name(off_idx, f),
                         words=[WordPatch(k, int(off_idx.words[base + k]), int(mod_words[base + k])) for k in idxs])
        targets.append(t)
        log.info(f"    {t.id}: {t.old_name} @ {t.old_vaddr:#x} ({len(idxs)} words changed)")
    return targets, issues


def plan_target(t: NativeTarget, i, old: NativeIndex, m, new: NativeIndex, cfg, log):
    """Fill in new location, byte-level edits, status. Never leaves a half-planned target."""
    t.evidence = list(m.evidence)
    if m.j < 0:
        t.status, t.message = "unmatched", "Patch target could not be reliably identified. Manual analysis required."
        return
    j = m.j
    t.new_vaddr, t.new_size, t.new_name = int(new.starts[j]), int(new.count[j]) * 4, sym_name(new, j)
    conf = m.confidence
    mapping, why = map_words(old.sl(old.norm, i).tolist(), new.sl(new.norm, j).tolist(), [w.index for w in t.words])
    t.evidence.append(why)
    if mapping is None:
        t.confidence, t.status = min(conf, 50.0), "unmatched"
        t.message = f"Function found ({t.new_name}) but patch site cannot be mapped: {why}. Manual analysis required."
        return
    if "sequence matching" in why:
        conf = min(conf, 92.0)
    edits = []
    for w in t.words:
        pos = mapping[w.index]
        if is_pc_relative(w.new_word):
            t.confidence, t.status = min(conf, 50.0), "unmatched"
            t.message = f"Replacement instruction {w.new_word:#010x} is PC-relative and cannot be relocated safely."
            return
        nw = int(new.words[int(new.first[j]) + pos])
        if int(new.norm[int(new.first[j]) + pos]) != int(old.norm[int(old.first[i]) + w.index]):
            t.confidence, t.status = min(conf, 50.0), "unmatched"
            t.message = "Instruction at the mapped patch site differs from the original one being replaced."
            return
        edits.append({"offset": new.sec.offset + (int(new.first[j]) + pos) * 4, "expected": nw,
                      "replacement": w.new_word})
    t.mapped, t.confidence = edits, round(conf, 1)
    if conf >= cfg.apply_threshold:
        t.status = "matched"
    elif conf >= cfg.review_threshold:
        t.status, t.message = "review", "Review required before applying."
    else:
        t.status, t.message = "unmatched", "Patch target could not be reliably identified. Manual analysis required."


def apply_native(buf: bytearray, t: NativeTarget):
    for e in t.mapped:
        cur = struct.unpack_from("<I", buf, e["offset"])[0]
        if cur != e["expected"]:
            raise ValueError(f"{t.id}: bytes at {e['offset']:#x} changed since analysis ({cur:#010x})")
        struct.pack_into("<I", buf, e["offset"], e["replacement"])
    t.status = "applied"


def export_patch(natives, files, path):
    """Generic, tool-independent patch representation."""
    doc = {"format": "apkporter-patch/1",
           "native": [asdict(t) for t in natives], "files": [asdict(f) for f in files]}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
