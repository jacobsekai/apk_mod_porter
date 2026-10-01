"""IL2CPP analyser: global-metadata.dat header/strings and optional Il2CppDumper symbol maps.

Recovering method-pointer tables from libil2cpp.so is version specific. Instead of guessing, this tool
accepts the `script.json` that Il2CppDumper writes for each build and uses it as a strong naming signal.
"""
import json
import struct
from dataclasses import dataclass, field

MAGIC = 0xFAB11BAF
METADATA_SUFFIX = "global-metadata.dat"


@dataclass
class Metadata:
    valid: bool = False
    version: int = -1
    strings: set = field(default_factory=set)
    note: str = ""


def parse_metadata(data: bytes) -> Metadata:
    if len(data) < 32:
        return Metadata(note="file too small")
    magic, ver = struct.unpack_from("<Ii", data, 0)
    if magic != MAGIC:
        return Metadata(version=ver, note="magic mismatch (file may be encrypted or customised)")
    _, _, _, _, s_off, s_size = struct.unpack_from("<6i", data, 8)
    if s_off <= 0 or s_size <= 0 or s_off + s_size > len(data):
        return Metadata(True, ver, note="string table bounds invalid for this header layout")
    raw = data[s_off:s_off + s_size].split(b"\0")
    return Metadata(True, ver, {x.decode("utf-8", "replace") for x in raw if x})


def load_symbols(path: str) -> dict:
    """Il2CppDumper script.json -> {vaddr: (name, signature)}."""
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    out = {}
    for m in doc.get("ScriptMethod", []):
        out[int(m["Address"])] = (m.get("Name", ""), m.get("Signature", ""))
    return out
