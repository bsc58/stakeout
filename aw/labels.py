"""App names as the phone shows them (docs/CONTRACT_PHONE.md, "aw/labels.py").

The name is the <application> element's android:label in the APK's binary AndroidManifest.xml.
It is usually a reference into resources.arsc, which holds one value per configuration; the
value of the first wanted locale that has one is the name. Both formats are Android's
resource chunks (frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h).

On the phone, `unzip` (Android's ziptool) copies the two files out of each APK into
/data/local/tmp/appwatch/labels/, the device layer's pull_tar brings them home, and the
directory is removed again. What was found is kept in a JSON cache keyed by package and APK
path: {package: {apk path: label | None}}, so that an app is read once per installed version.
"""
import json
import os
import re
import struct
import tempfile
import threading
from pathlib import Path

REMOTE_PARENT = "/data/local/tmp/appwatch"
REMOTE_DIR = REMOTE_PARENT + "/labels"
APK_FILES = ("AndroidManifest.xml", "resources.arsc")
BATCH = 20                 # apps extracted and pulled at a time: bounds the space used on both sides
MAX_HOPS = 8               # references followed from the label to a string

# Paths and package names go into a root shell command as they are (device.Device.sh takes plain
# words). Installed APK paths use these characters (`~~<base64>==` directories, `@<version>` in
# APEX paths); one that does not fit is not read.
_PLAIN_APK = re.compile(r"/[A-Za-z0-9_.@~=/-]+")
_PLAIN_PACKAGE = re.compile(r"[A-Za-z0-9_.]+")

_ANDROID_LABEL = 0x01010001        # android:label
_STRING_POOL, _TABLE, _XML = 0x0001, 0x0002, 0x0003
_XML_START, _XML_END, _XML_RESOURCE_MAP = 0x0102, 0x0103, 0x0180
_PACKAGE, _TYPE = 0x0200, 0x0201
_TYPE_REFERENCE, _TYPE_STRING = 0x01, 0x03
_SPARSE, _OFFSET16 = 0x01, 0x02                  # ResTable_type flags
_ENTRY_COMPLEX, _ENTRY_COMPACT = 0x0001, 0x0008  # ResTable_entry flags
_NO_ENTRY = 0xFFFFFFFF

_HEADER = struct.Struct("<HHI")     # ResChunk_header: type, headerSize, size
_U16 = struct.Struct("<H")
_U32 = struct.Struct("<I")
_U16X2 = struct.Struct("<HH")
_ATTR_EXT = struct.Struct("<IIHHH")       # ns, name, attributeStart, attributeSize, attributeCount
_ATTR = struct.Struct("<IIIHBBI")         # ns, name, rawValue, Res_value (size, res0, dataType, data)
_TYPE_HEAD = struct.Struct("<BBHII")      # id, flags, reserved, entryCount, entriesStart

_lock = threading.Lock()   # one phone-side read at a time: they share REMOTE_DIR and the cache


def _chunks(b, off, end):
    """(offset, type, header size, size) of the chunks laid end to end in b[off:end]."""
    end = min(end, len(b))
    while off + 8 <= end:
        t, hs, size = _HEADER.unpack_from(b, off)
        if hs < 8 or size < hs or off + size > end:
            return
        yield off, t, hs, size
        off += size


class _Pool:
    """A ResStringPool chunk; strings are decoded when asked for."""

    def __init__(self, b, off):
        hs = _U16.unpack_from(b, off + 2)[0]
        self.count, _, flags, start = struct.unpack_from("<IIII", b, off + 8)
        self.b, self.offsets, self.start, self.utf8 = b, off + hs, off + start, bool(flags & 0x100)

    def get(self, i):
        if not 0 <= i < self.count:
            return None
        b = self.b
        p = self.start + _U32.unpack_from(b, self.offsets + 4 * i)[0]
        if self.utf8:
            p += 2 if b[p] & 0x80 else 1          # length in UTF-16 units: not needed
            n = b[p]
            if n & 0x80:
                n, p = (n & 0x7F) << 8 | b[p + 1], p + 2
            else:
                p += 1
            return b[p:p + n].decode("utf-8", "replace")
        n = _U16.unpack_from(b, p)[0]
        p += 2
        if n & 0x8000:
            n, p = (n & 0x7FFF) << 16 | _U16.unpack_from(b, p)[0], p + 2
        return b[p:p + 2 * n].decode("utf-16-le", "replace")


def _manifest_label(m):
    """The <application> element's android:label as (dataType, value): value is the string
    itself for a literal, the resource id for a reference. None when there is none."""
    t, hs, size = _HEADER.unpack_from(m, 0)
    if t != _XML:
        return None
    pool, resmap, depth = None, (), 0
    for off, t, hs, size in _chunks(m, hs, size):
        if t == _STRING_POOL and pool is None:
            pool = _Pool(m, off)
        elif t == _XML_RESOURCE_MAP:
            resmap = struct.unpack_from(f"<{(size - hs) // 4}I", m, off + hs)
        elif t == _XML_START:
            depth += 1
            if depth != 2:
                continue
            ext = off + hs
            _, name, start, step, count = _ATTR_EXT.unpack_from(m, ext)
            if pool is None or pool.get(name) != "application":
                continue
            for k in range(count):
                _, aname, _, _, _, vtype, data = _ATTR.unpack_from(m, ext + start + k * step)
                # By resource id, as Android reads it: the attribute's name string may be anything.
                if aname < len(resmap) and resmap[aname] == _ANDROID_LABEL:
                    if vtype == _TYPE_STRING:
                        return vtype, pool.get(data)
                    return vtype, data
            return None
        elif t == _XML_END:
            depth -= 1
    return None


class _Table:
    """resources.arsc: the value pool and, per (package id, type id), its ResTable_type chunks."""

    def __init__(self, b):
        t, hs, size = _HEADER.unpack_from(b, 0)
        if t != _TABLE:
            raise ValueError("not a resource table")
        self.b, self.pool, self.types = b, None, {}
        for off, t, phs, psize in _chunks(b, hs, size):
            if t == _STRING_POOL and self.pool is None:
                self.pool = _Pool(b, off)
            elif t == _PACKAGE:
                pid = _U32.unpack_from(b, off + 8)[0]
                for c, ct, _, _ in _chunks(b, off + phs, off + psize):
                    if ct == _TYPE:
                        self.types.setdefault((pid, b[c + 8]), []).append(c)

    def locale(self, c):
        """(language, country, script) bytes of a type chunk's ResTable_config."""
        cfg = c + 20
        b = self.b
        script = b[cfg + 36:cfg + 40] if _U32.unpack_from(b, cfg)[0] >= 40 else b"\0" * 4
        return b[cfg + 8:cfg + 10], b[cfg + 10:cfg + 12], script

    def value(self, c, idx):
        """(dataType, data) of entry idx in type chunk c; None when it has none or it is a bag."""
        b = self.b
        hs = _U16.unpack_from(b, c + 2)[0]
        _, flags, _, count, start = _TYPE_HEAD.unpack_from(b, c + 8)
        offsets = c + hs
        if flags & _SPARSE:                     # sorted (index, offset / 4) pairs
            lo, hi = 0, count
            while lo < hi:
                mid = (lo + hi) // 2
                i, o = _U16X2.unpack_from(b, offsets + 4 * mid)
                if i == idx:
                    break
                lo, hi = (mid + 1, hi) if i < idx else (lo, mid)
            else:
                return None
            o *= 4
        elif idx >= count:
            return None
        elif flags & _OFFSET16:
            o = _U16.unpack_from(b, offsets + 2 * idx)[0]
            if o == 0xFFFF:
                return None
            o *= 4
        else:
            o = _U32.unpack_from(b, offsets + 4 * idx)[0]
            if o == _NO_ENTRY:
                return None
        e = c + start + o
        esize, eflags = _U16X2.unpack_from(b, e)
        if eflags & _ENTRY_COMPACT:             # key, flags (dataType in the high byte), data
            return eflags >> 8, _U32.unpack_from(b, e + 4)[0]
        if eflags & _ENTRY_COMPLEX:
            return None
        return b[e + esize + 3], _U32.unpack_from(b, e + esize + 4)[0]

    def lookup(self, rid, wanted):
        """(dataType, data) of resource rid in the first wanted locale that has it."""
        chunks = self.types.get((rid >> 24, (rid >> 16) & 0xFF), ())
        keyed = [(self.locale(c), c) for c in chunks]
        for want in wanted:
            for key, c in keyed:
                if key == want:
                    v = self.value(c, rid & 0xFFFF)
                    if v is not None:
                        return v
        return None


def _locale_key(locale):
    """"zh-CN" -> (b"zh", b"CN", no script); "" -> the default configuration."""
    lang, _, country = locale.partition("-")
    return lang.encode().ljust(2, b"\0"), country.encode().ljust(2, b"\0"), b"\0" * 4


def label_from_files(manifest: bytes, arsc: bytes, locales=("zh-CN", "zh", "")) -> str | None:
    """The application label in the first of `locales` that has it ("" is the default
    configuration); None when there is none or the files cannot be read."""
    try:
        found = _manifest_label(manifest)
        if found is None:
            return None
        vtype, value = found
        if vtype == _TYPE_REFERENCE:
            table = _Table(arsc)
            wanted = [_locale_key(x) for x in locales]
            for _ in range(MAX_HOPS):
                found = table.lookup(value, wanted)
                if found is None:
                    return None
                vtype, value = found
                if vtype != _TYPE_REFERENCE:
                    break
            if vtype == _TYPE_STRING:
                value = table.pool.get(value) if table.pool else None
        return value if vtype == _TYPE_STRING and value else None
    except (struct.error, IndexError, ValueError):
        return None


def _load(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):       # no cache yet, or not readable: read the apps again
        return {}


def _save(path, cache):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _read_on_phone(dev, todo):
    """Yield (package, apk, label) for each (package, apk) whose manifest came back."""
    # As the shell user: collect pushes its scripts into this directory as that user.
    dev.sh(f"mkdir -p {REMOTE_PARENT}")
    try:
        for i in range(0, len(todo), BATCH):
            batch = todo[i:i + BATCH]
            # `; true`: an APK that cannot be read leaves its directory empty, the others go on.
            steps = [f"mkdir -p {REMOTE_DIR}/{pkg} && unzip -o -q -d {REMOTE_DIR}/{pkg} {apk} {' '.join(APK_FILES)}"
                     for pkg, apk in batch]
            dev.sh(f"rm -rf {REMOTE_DIR}; " + "; ".join(steps) + "; true", root=True)
            with tempfile.TemporaryDirectory(prefix="aw_labels_") as tmp:
                dev.pull_tar(REMOTE_DIR, tmp, root=True)
                for pkg, apk in batch:
                    d = Path(tmp) / pkg
                    if not (d / APK_FILES[0]).is_file():
                        continue                # not read: not cached either, tried again next time
                    arsc = d / APK_FILES[1]
                    yield pkg, apk, label_from_files((d / APK_FILES[0]).read_bytes(),
                                                     arsc.read_bytes() if arsc.is_file() else b"")
    finally:
        # rmdir: the parent only when nothing else is in it (it may hold a running capture).
        dev.sh(f"rm -rf {REMOTE_DIR}; rmdir {REMOTE_PARENT}; true", root=True)


def labels(dev, packages, cache_path) -> dict:
    """{package: label | None} for collect.list_packages entries ({"package", "apk", ...}).

    Apps not in the cache under their current APK path are read from the phone, then cached.
    dev=None answers from the cache alone: an app cached only under another APK path (an older
    version) gets that label. A DeviceError from the phone is passed on; what was read before it
    stays in the cache."""
    cache_path = Path(cache_path)
    with _lock:
        cache = _load(cache_path)
        result, todo = {}, []
        for p in packages:
            pkg, apk = p["package"], p.get("apk")
            known = cache.get(pkg, {})
            if apk in known:
                result[pkg] = known[apk]
                continue
            result[pkg] = next(reversed(known.values()), None) if dev is None else None
            if dev is not None and apk and _PLAIN_APK.fullmatch(apk) and _PLAIN_PACKAGE.fullmatch(pkg):
                todo.append((pkg, apk))
        if todo:
            try:
                for pkg, apk, label in _read_on_phone(dev, todo):
                    cache.setdefault(pkg, {})[apk] = label
                    result[pkg] = label
            finally:
                _save(cache_path, cache)
        return result
