# rtti_names.py: recover MSVC RTTI class names, vtables, base classes and vfunc slots.
# Output: recomp/data/rtti_names.tsv and recomp/data/rtti.json.
import csv
import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cfg
from pe_image import Image

im = Image(cfg.game_exe())
if im.arch != "x86":
    sys.exit("RTTI tooling currently decodes 32-bit MSVC images; the x64 RTTI layout is WIP")
secs = {s[0]: s for s in im.secs}
text = secs.get(".text")
if not text:
    sys.exit("no .text section")
lo, hi = text[2], text[2] + text[1]
buffers = []
for s in im.secs:
    if s[0] == ".text" or not s[3]:
        continue
    buffers.append((s[2], im.read(s[2], s[3])))
if not buffers:
    sys.exit("no data sections")


def in_image(v):
    if v is None:
        return False
    for name, vs, va, rs, rp in im.secs:
        if va <= v < va + max(vs, rs):
            return True
    return False


def read(v, n):
    b = im.read(v, n)
    return b if len(b) == n else None


def u32(v):
    b = read(v, 4)
    return struct.unpack("<I", b)[0] if b else None


def find(value):
    pat = struct.pack("<I", value)
    hits = []
    for va, data in buffers:
        pos = data.find(pat)
        while pos >= 0:
            hits.append(va + pos)
            pos = data.find(pat, pos + 1)
    return hits


def is_code(v):
    return v is not None and lo <= v < hi


# ---- type descriptors -------------------------------------------------------
descriptors = []
descriptor_by_addr = {}
for va, data in buffers:
    for prefix in (b".?AV", b".?AU"):
        pos = data.find(prefix)
        while pos >= 0:
            end = data.find(b"\0", pos)
            if end > pos:
                td = va + pos - 8
                name = data[pos:end].decode("latin-1", "replace")
                vt_info = u32(td)
                if in_image(vt_info):
                    descriptors.append((td, name))
                    descriptor_by_addr[td] = name
            pos = data.find(prefix, pos + 1)


def class_name(mangled):
    base = mangled
    for p in (".?AV", ".?AU"):
        if base.startswith(p):
            base = base[len(p):]
            break
    return base.split("@@")[0]


# ---- complete object locators, vtables and methods --------------------------
rows = []
classes = []
vtables = {}
vt_methods = {}
methods = {}
orphans = 0
for td, mangled in descriptors:
    base = class_name(mangled)
    if not base:
        continue
    rows.append((td, "rtti_" + base, "class"))
    cols = []
    for ref in find(td):
        col = ref - 12
        if u32(col) != 0 or u32(col + 12) != td:
            continue
        cd = u32(col + 16)
        if not in_image(cd):
            continue
        cols.append((col, cd))
    if not cols:
        orphans += 1
    for col, cd in cols:
        bases = []
        sig, attrs, count, arr = u32(cd), u32(cd + 4), u32(cd + 8), u32(cd + 12)
        if sig == 0 and count and count < 64 and in_image(arr):
            for i in range(count):
                bcd = u32(arr + i * 4)
                if not in_image(bcd):
                    continue
                btd = u32(bcd)
                bname = descriptor_by_addr.get(btd)
                if bname:
                    bn = class_name(bname)
                    if bn and bn != base and bn not in bases:
                        bases.append(bn)
        class_vtables = []
        for ref in find(col):
            vt = ref + 4
            if u32(vt - 4) != col or vt in vtables:
                continue
            slots = []
            slot = vt
            index = 0
            while True:
                fn = u32(slot)
                if not is_code(fn):
                    break
                name = "%s::vfunc%d" % (base, index)
                slots.append({"slot": index, "address": "0x%08x" % fn, "name": name})
                rows.append((fn, name, "vfunc"))
                methods.setdefault("0x%08x" % fn, []).append(name)
                slot += 4
                index += 1
            if slots:
                vtables[vt] = base
                vt_methods[vt] = slots
                class_vtables.append("0x%08x" % vt)
                rows.append((vt, "vftable_" + base, "vftable"))
                classes.append({
                    "name": base,
                    "descriptor": "0x%08x" % td,
                    "col": "0x%08x" % col,
                    "vtable": "0x%08x" % vt,
                    "vtables": class_vtables,
                    "bases": bases,
                    "method_count": len(slots),
                })

# ---- write -----------------------------------------------------------------
os.makedirs(cfg.DATA, exist_ok=True)
tsv = os.path.join(cfg.DATA, "rtti_names.tsv")
seen = set()
with open(tsv, "w", encoding="utf-8", newline="") as f:
    w = csv.writer(f, delimiter="\t")
    w.writerow(["ea", "name", "kind"])
    for ea, name, kind in rows:
        key = (ea, name)
        if key in seen:
            continue
        seen.add(key)
        w.writerow(["%08x" % ea, name, kind])

digest = None
manifest = os.path.join(cfg.DATA, "target.json")
if os.path.exists(manifest):
    try:
        digest = json.load(open(manifest, encoding="utf-8")).get("target", {}).get("sha256")
    except Exception:
        pass
if not digest:
    h = hashlib.sha256()
    with open(cfg.game_exe(), "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    digest = h.hexdigest()

record = {
    "schema": 1,
    "target_sha256": digest,
    "classes": sorted(classes, key=lambda c: c["name"].lower()),
    "vtables": [{"address": "0x%08x" % vt, "class": cls,
                 "methods": vt_methods.get(vt, [])}
                for vt, cls in sorted(vtables.items())],
    "methods": {k: sorted(set(v)) for k, v in sorted(methods.items())},
    "counts": {
        "type_descriptors": len(descriptors),
        "classes": len(classes),
        "vtables": len(vtables),
        "methods": len(methods),
        "descriptors_without_vtable": orphans,
    },
    "limitations": [
        "MSVC RTTI only (type descriptor names .?AV/.?AU); Itanium/GCC RTTI is not decoded.",
        "vfuncN names are positional, not semantic method names.",
        "Multiple inheritance, thunks and secondary vtables can produce duplicate entries.",
        "A descriptor without a valid CompleteObjectLocator is counted as an orphan, not guessed.",
    ],
}
json_path = os.path.join(cfg.DATA, "rtti.json")
with open(json_path, "w", encoding="utf-8", newline="\n") as f:
    json.dump(record, f, indent=1, sort_keys=True)
    f.write("\n")
print("descriptors %d, classes %d, vtables %d, methods %d, orphans %d -> %s, %s"
      % (len(descriptors), len(classes), len(vtables), len(methods), orphans, tsv, json_path))
