"""Append-only editor for binary AndroidManifest.xml (AXML).

Existing strings, indices and typed values are never rewritten, so nothing already in the manifest
can change type or value. New strings go on the end of the string pool and new elements are inserted
as raw chunks. Result is checked by decoding it again (see verify_additions_only).
"""
import struct

ANDROID_NS = "http://schemas.android.com/apk/res/android"
RES_STRING_POOL, RES_START_NS, RES_START_EL, RES_END_EL = 0x0001, 0x0100, 0x0102, 0x0103
UTF8_FLAG = 0x100
ATTR_ORDER = ["name", "enabled", "exported"]   # ascending resource id, as aapt emits them


class AxmlError(ValueError):
    pass


def _read_len8(d, p):
    n = d[p]; p += 1
    if n & 0x80:
        n = ((n & 0x7F) << 8) | d[p]; p += 1
    return n, p


def _read_pool(d):
    typ, hdr, size, count, styles, flags, s_start, st_start = struct.unpack_from("<HHIIIIII", d, 8)
    if typ != RES_STRING_POOL:
        raise AxmlError("string pool not where expected")
    offs = struct.unpack_from(f"<{count}I", d, 8 + hdr)
    base = 8 + s_start
    out = []
    for o in offs:
        p = base + o
        if flags & UTF8_FLAG:
            _, p = _read_len8(d, p)
            n, p = _read_len8(d, p)
            out.append(d[p:p + n].decode("utf-8", "replace"))
        else:
            n = struct.unpack_from("<H", d, p)[0]
            out.append(d[p + 2:p + 2 + 2 * n].decode("utf-16-le", "replace"))
    return dict(size=size, count=count, styles=styles, flags=flags, s_start=s_start, hdr=hdr, strings=out)


def _enc(s, utf8):
    if utf8:
        b = s.encode("utf-8")
        assert len(b) < 128 and len(s) < 128
        return bytes([len(s), len(b)]) + b + b"\0"
    return struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\0\0"


def add_strings(d, new):
    """Append strings to the pool; returns (new_bytes, {string: index})."""
    pool = _read_pool(d)
    if pool["styles"]:
        raise AxmlError("style spans in manifest string pool are not supported")
    utf8 = bool(pool["flags"] & UTF8_FLAG)
    strings = pool["strings"]
    idx, add = {}, []
    for s in new:
        if s in strings:
            idx[s] = strings.index(s)
        else:
            idx[s] = len(strings) + len(add)
            add.append(s)
    if not add:
        return d, idx
    start = 8
    hdr = pool["hdr"]
    off_tbl_end = start + hdr + 4 * pool["count"]
    chunk_end = start + pool["size"]
    data = d[start + pool["s_start"]:chunk_end]
    offs = list(struct.unpack_from(f"<{pool['count']}I", d, start + hdr))
    blob = b""
    for s in add:
        offs.append(len(data) + len(blob))
        blob += _enc(s, utf8)
    data += blob
    data += b"\0" * (-len(data) % 4)
    new_count = pool["count"] + len(add)
    s_start = hdr + 4 * new_count
    size = s_start + len(data)
    head = bytearray(d[start:start + hdr])
    struct.pack_into("<I", head, 4, size)
    struct.pack_into("<I", head, 8, new_count)
    struct.pack_into("<I", head, 20, s_start)
    new_pool = bytes(head) + struct.pack(f"<{new_count}I", *offs) + data
    out = bytearray(d[:start]) + new_pool + d[chunk_end:]
    struct.pack_into("<I", out, 4, len(out))
    return bytes(out), idx


def _el_start(tag, attrs, line=1):
    body = struct.pack("<iiHHHHHH", -1, tag, 0x14, 0x14, len(attrs), 0, 0, 0)
    for ns, name, raw, dtype, data in attrs:
        body += struct.pack("<iiiHBBI", ns, name, raw, 8, 0, dtype, data & 0xFFFFFFFF)
    return struct.pack("<HHIii", RES_START_EL, 16, 16 + len(body), line, -1) + body


def _el_end(tag, line=1):
    return struct.pack("<HHIiiii", RES_END_EL, 16, 24, line, -1, -1, tag)


def _chunks(d):
    p = 8 + _read_pool(d)["size"]
    while p < len(d):
        typ, _, size = struct.unpack_from("<HHI", d, p)
        yield p, typ, size
        p += size


def add_manifest_entries(data: bytes, permission: str, service: str) -> bytes:
    d, idx = add_strings(data, ["uses-permission", "service", "name", "enabled", "exported", ANDROID_NS, permission, service])
    pool = _read_pool(d)["strings"]
    ns, tag_perm, tag_srv = idx[ANDROID_NS], idx["uses-permission"], idx["service"]
    if pool.index(ANDROID_NS) != ns or "application" not in pool:
        raise AxmlError("unexpected manifest string layout")
    at = {n: idx[n] for n in ATTR_ORDER}
    perm = _el_start(tag_perm, [(ns, at["name"], idx[permission], 3, idx[permission])]) + _el_end(tag_perm)
    srv = _el_start(tag_srv, [(ns, at["name"], idx[service], 3, idx[service]),
                              (ns, at["enabled"], -1, 0x12, 0xFFFFFFFF),
                              (ns, at["exported"], -1, 0x12, 0)]) + _el_end(tag_srv)
    app = pool.index("application")
    first_perm_pos = app_end_pos = None
    for p, typ, size in _chunks(d):
        name = struct.unpack_from("<i", d, p + 20)[0] if typ in (RES_START_EL, RES_END_EL) else None
        if typ == RES_START_EL and name == tag_perm and first_perm_pos is None:
            first_perm_pos = p
        if typ == RES_END_EL and name == app:
            app_end_pos = p
    if first_perm_pos is None or app_end_pos is None:
        raise AxmlError("could not find insertion points")
    out = d[:first_perm_pos] + perm + d[first_perm_pos:app_end_pos] + srv + d[app_end_pos:]
    out = bytearray(out)
    struct.pack_into("<I", out, 4, len(out))
    return bytes(out)


def decode_lines(data: bytes):
    import logging, re
    prev = logging.root.manager.disable
    logging.disable(logging.CRITICAL)      # androguard is chatty; restored below
    try:
        try:
            from loguru import logger
            logger.remove()
        except ImportError:
            pass
        from androguard.core.axml import AXMLPrinter
        x = AXMLPrinter(data)
        if not x.is_valid():
            raise AxmlError("patched manifest does not decode")
        return re.sub(r">\s*<", ">\n<", x.get_xml().decode("utf-8")).splitlines()
    finally:
        logging.disable(prev)


def verify_additions_only(before: bytes, after: bytes, permission: str, service: str):
    """Decoded manifest must equal the original plus exactly the two new elements."""
    import difflib
    a, b = decode_lines(before), decode_lines(after)
    extra = [l for l in difflib.unified_diff(a, b, lineterm="", n=0) if l[:1] in "+-" and l[:3] not in ("+++", "---")]
    ok = (len(extra) == 2 and all(l.startswith("+") for l in extra)
          and any(permission in l for l in extra) and any(service in l for l in extra))
    return ok, extra
