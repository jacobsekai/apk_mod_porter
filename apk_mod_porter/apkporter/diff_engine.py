"""APK Diff Engine: file-level comparison using central-directory CRC + size (no full reads)."""
from dataclasses import dataclass, field

from .apk_manager import is_signature


@dataclass
class ApkDiff:
    added: list = field(default_factory=list)
    removed: list = field(default_factory=list)
    changed: list = field(default_factory=list)
    same: int = 0


def diff_sets(a, b) -> ApkDiff:
    ia, ib = a.index(), b.index()
    d = ApkDiff()
    for k in sorted(ia.keys() | ib.keys()):
        if is_signature(k[1]):
            continue
        if k not in ia:
            d.added.append(k)
        elif k not in ib:
            d.removed.append(k)
        elif ia[k] != ib[k]:
            d.changed.append(k)
        else:
            d.same += 1
    return d


def fmt(key):
    return f"{key[0]}::{key[1]}" if key[0] else key[1]
