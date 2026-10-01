"""Shared data structures. Everything reportable is a dataclass so it serialises to JSON."""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Config:
    old_mod: str = ""
    old_official: str = ""
    new_official: str = ""
    out_dir: str = "output"
    symbols_old: str = ""        # optional Il2CppDumper script.json for the OLD official build
    symbols_new: str = ""        # optional Il2CppDumper script.json for the NEW official build
    apply_threshold: float = 90.0
    review_threshold: float = 70.0
    apply_review: bool = False   # also apply review-level matches
    allow_partial: bool = False  # build even if some modifications could not be ported
    keystore: str = ""
    ks_pass: str = "android"
    ks_alias: str = "key0"


@dataclass
class WordPatch:
    index: int       # instruction index inside the old function
    old_word: int    # word in the old OFFICIAL build
    new_word: int    # word in the old MODDED build


@dataclass
class NativeTarget:
    id: str
    member: str
    path: str
    old_vaddr: int
    old_size: int
    old_name: str
    words: list = field(default_factory=list)      # list[WordPatch]
    status: str = "pending"   # matched | review | unmatched | applied | skipped
    confidence: float = 0.0
    new_vaddr: int = 0
    new_size: int = 0
    new_name: str = ""
    mapped: list = field(default_factory=list)     # {offset, expected, replacement}
    evidence: list = field(default_factory=list)
    message: str = ""
    kind: str = "native"


@dataclass
class FileTarget:
    id: str
    member: str
    path: str
    action: str               # carry-over | add
    status: str = "pending"
    confidence: float = 0.0
    evidence: list = field(default_factory=list)
    message: str = ""
    kind: str = "file"


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class BuildResult:
    ok: bool = False
    outputs: list = field(default_factory=list)
    checks: list = field(default_factory=list)
    message: str = ""
