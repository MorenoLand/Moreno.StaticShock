# gen.py: lift every function of the image to C, write the dispatch table and stubs for unlifted call targets.
# usage: gen.py [--only hex,hex,...] [--chunk N] [--regenerate]
import bisect
import csv
import os
import re
import struct
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cfg
from pe_image import Image
from lift import Lifter

OUT = str(cfg.SRC)
if cfg.ARCH != "x86":
    sys.exit("arch = %r: PE32+ parsing and configuration are available, but the x64 lifter and "
             "runtime are WIP. The shipped backend is x86-32." % cfg.ARCH)
if os.path.isdir(OUT) and any(f.endswith(".c") for _, _, fs in os.walk(OUT) for f in fs) and "--regenerate" not in sys.argv:
    sys.exit("src/ already holds the source: it is edited by hand now and gen.py would overwrite it.\n"
             "  pass --regenerate only to rebuild the lifted code from the exe from scratch (it deletes the lifted files in src/)")
if "--regenerate" in sys.argv:
    sys.argv.remove("--regenerate")
os.makedirs(OUT, exist_ok=True)

only = None
chunk = cfg.chunk_size()
a = sys.argv[1:]
if "--only" in a:
    only = {int(x, 16) for x in a[a.index("--only") + 1].split(",")}
if "--chunk" in a:
    chunk = int(a[a.index("--chunk") + 1])

im = Image(cfg.game_exe())
rows = list(csv.DictReader(open(os.path.join(cfg.DATA, "functions.tsv"), encoding="utf-8"), delimiter="\t"))
skip_cats = cfg.skip_categories()
rows = [r for r in rows if r.get("category", "app") not in skip_cats]
starts = sorted(int(r["ea"], 16) for r in rows)
names = {int(r["ea"], 16): r["name"] for r in rows}
SKIP = cfg.skip_functions()
WRAP = cfg.wrap_functions()
code_map = None
code_heads = None
code_path = os.path.join(cfg.ida_dump(), "code.txt")
if os.path.exists(code_path):
    code_map = bytearray(cfg.CODE_HI - cfg.CODE_LO)
    code_heads = set()
    for line in open(code_path, encoding="utf-8"):
        lo, hi = (int(x, 16) for x in line.split())
        code_heads.add(lo)
        for ea in range(lo, hi):
            if cfg.CODE_LO <= ea < cfg.CODE_HI:
                code_map[ea - cfg.CODE_LO] = 1
lf = Lifter(im, starts, names, code_lo=cfg.CODE_LO, code_hi=cfg.CODE_HI, code_heads=code_heads)
todo = [e for e in starts if (only is None or e in only) and e not in SKIP]

t0 = time.time()
texts = {}
unsup_by_fn = {}
mn = Counter()
for e in todo:
    n0 = len(lf.unsup)
    try:
        texts[e] = lf.lift(e, "_lifted" if e in WRAP else "")
    except Exception as ex:
        texts[e] = "void f_%08x(void) { UNSUP(0x%08x, \"lifter failed: %s\"); }" % (e, e, str(ex).replace('"', "'"))
        unsup_by_fn[e] = [(e, "lifter failed: %s" % ex)]
        continue
    if len(lf.unsup) > n0:
        unsup_by_fn[e] = lf.unsup[n0:]
        for _, t in lf.unsup[n0:]:
            mn[t.split()[0]] += 1

# Code addresses stored in data (vtables, initialiser tables, callbacks) that lie outside every known function are
# functions the analysis missed. Lift them as well, but do not record their bytes as code: they may be jump tables.
text_lo, text_hi = cfg.CODE_LO, cfg.CODE_HI
guessed = set()
sizes = {int(r["ea"], 16): int(r["size"]) for r in rows}


def known_code(v):
    return code_map is None or (cfg.CODE_LO <= v < cfg.CODE_HI and code_map[v - cfg.CODE_LO])


for nm, vs, va, rs, rp in im.secs:
    if nm == ".text" or not rs:
        continue
    data = im.read(va, rs)
    for off in range(0, len(data) - 3, 4):
        v = struct.unpack_from("<I", data, off)[0]
        if not (text_lo <= v < text_hi):
            continue
        k = bisect.bisect_right(starts, v) - 1
        outside = k < 0 or (v != starts[k] and v >= starts[k] + sizes[starts[k]])
        prev = im.read(v - 1, 1)
        if outside and known_code(v) and (prev == b"\xcc" or v % 16 == 0):
            lf.calls.add(v)
            guessed.add(v)
# code addresses used as immediate operands (default allocators and callbacks stored with `mov [x], offset f`)
for v in sorted(lf.imm_cands):
    k = bisect.bisect_right(starts, v) - 1
    if not known_code(v) or (k >= 0 and v == starts[k]):
        continue
    outside = k < 0 or v >= starts[k] + sizes[starts[k]]
    if not outside or im.read(v - 1, 1) == b"\xcc" or v % 16 == 0:
        lf.calls.add(v)
        guessed.add(v)

# functions that hand-written overrides call by address (optional file)
override = os.path.join(cfg.RT, "override.c")
if os.path.exists(override):
    for m in re.finditer(r"gcall\(0x([0-9A-Fa-f]+)", open(override, encoding="utf-8").read()):
        lf.calls.add(int(m.group(1), 16))
print("data-referenced code addresses outside known functions:", len(lf.calls))

extra_lifted = 0
while True:
    pending = sorted(c for c in lf.calls if c not in texts and c not in set(starts) and c not in SKIP
                     and im.read(c, 1) and (only is None or c in only))
    if not pending:
        break
    for e in pending:
        n0 = len(lf.unsup)
        lf.record = e not in guessed
        try:
            texts[e] = lf.lift(e)
        except Exception as ex:
            texts[e] = "void f_%08x(void) { UNSUP(0x%08x, \"lifter failed: %s\"); }" % (e, e, str(ex).replace('"', "'"))
            unsup_by_fn[e] = [(e, "lifter failed: %s" % ex)]
            continue
        if len(lf.unsup) > n0:
            unsup_by_fn[e] = lf.unsup[n0:]
            for _, t in lf.unsup[n0:]:
                mn[t.split()[0]] += 1
        extra_lifted += 1
called = set(lf.calls)
missing = sorted(c for c in called if c not in texts and c not in set(starts))
print("lifted %d functions (%d of them blocks called from other functions) in %.1fs; %d with unsupported instructions; %d call targets still unlifted"
      % (len(texts), extra_lifted, time.time() - t0, len(unsup_by_fn), len(missing)))
print("unsupported mnemonics:", mn.most_common(40))

keys = sorted(texts)
written = set()


def emit_file(name, text):
    """Write a generated file only when its content changed, so make-style rebuilds recompile just the chunks that differ."""
    path = os.path.join(OUT, name)
    os.makedirs(os.path.dirname(path) or OUT, exist_ok=True)
    written.add(name.replace("\\", "/"))
    if os.path.exists(path) and open(path, encoding="utf-8", newline="").read() == text:
        return
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


allf = sorted(set(starts) | set(missing) | set(texts))
NL = chr(10)
emit_file("protos.h", '#include "rt.h"' + NL + "".join("void f_%08x(void);" % e + NL for e in allf) + "".join("void f_%08x_lifted(void);" % e + NL for e in sorted(WRAP)))
cat = {int(r["ea"], 16): r.get("category", "app") for r in csv.DictReader(open(os.path.join(cfg.DATA, "functions.tsv"), encoding="utf-8"), delimiter="\t")}


def group_of(e):
    """File a function belongs to: its library, its class (Class::method), its prefix, or the 4 KB page it sits in."""
    c = cat.get(e, "")
    if c.startswith("lib:") or c.startswith("crt:"):
        return c.replace(":", "_")
    n = names.get(e, "")
    if n.startswith("?"):
        return "mangled_%04x" % (e >> 12)
    if "::" in n:
        return n.split("::")[0].split("<")[0]
    if n and not n.startswith("sub_") and not n.startswith("loc_") and "_" in n.strip("_"):
        return n.strip("_").split("_")[0]
    return "unnamed_%04x" % (e >> 12)


AREAS = cfg.areas()


def area_of(g):
    if g.startswith("lib_"):
        name = g[4:].split("_")[0]
        return "third_party/" + (name if name else "lib")
    if g.startswith("crt_"):
        return "crt"
    if g.startswith("mangled_"):
        return "third_party/mangled"
    if g.startswith("unnamed_"):
        return "unnamed"
    n = g[1:] if len(g) > 1 and g[0] == "T" and g[1].isupper() else g
    for folder, pat in AREAS:
        if re.match("(?:%s)" % pat, n):
            return folder
    return "misc"


groups = {}
spelling = {}
for e in keys:
    g = re.sub(r"[^A-Za-z0-9_]", "_", group_of(e)) or "misc"
    groups.setdefault(spelling.setdefault(g.lower(), g), []).append(e)
MAXF = cfg.max_functions_per_file()
nfiles = 0
for g, es in sorted(groups.items()):
    for k in range(0, len(es), MAXF):
        part = es[k:k + MAXF]
        fname = "%s/%s.c" % (area_of(g), g if len(es) <= MAXF else "%s_%d" % (g, k // MAXF + 1))
        emit_file(fname, '#include "protos.h"' + NL + NL + "".join(texts[e] + NL + NL for e in part))
        nfiles += 1
have = set(keys) | SKIP | WRAP
emit_file("stubs.c", '#include "protos.h"' + NL + "".join(
    'void f_%08x(void) { UNSUP(0x%08x, "function not lifted"); }' % (e, e) + NL for e in allf if e not in have))
emit_file("dispatch.c", '#include "protos.h"' + NL + "const FnEnt fn_table[] = {" + NL + "".join(
    "    {0x%08x, f_%08x}," % (e, e) + NL for e in allf) + "};" + NL + "const unsigned fn_count = %d;" % len(allf) + NL)
emit_file("unsupported.txt", "".join("%08x %08x %s" % (e, ad, t) + NL for e, lst in sorted(unsup_by_fn.items()) for ad, t in lst))
for root, _, fs in os.walk(OUT):
    for f in fs:
        rel = os.path.relpath(os.path.join(root, f), OUT).replace("\\", "/")
        if rel not in written and (f.endswith(".c") or f.endswith(".h") or f.endswith(".txt")):
            os.remove(os.path.join(root, f))
print("wrote %d chunk files" % nfiles)

# The data the lifted code works on, emitted with it so the recompiled program does not need the original exe:
# PE headers (the C runtime start-up validates them), the data part of the image (strings, vtables, tables, globals),
# resources and the import table. The machine code itself is not part of it: the lifted C replaces it, and the runtime
# makes those ranges unreadable so any remaining read shows up as a crash.
# Format: u32 count, count x (u32 address, u32 length, u32 offset in this file), then the bytes.
_e = struct.unpack_from("<I", im.d, 0x3C)[0]
_hdr = struct.unpack_from("<I", im.d, _e + 24 + 60)[0]
pieces = [(cfg.IMAGE_BASE, im.d[:_hdr])]
for _sec in im.secs:
    if _sec[0] == ".text" or not _sec[3]:
        continue
    pieces.append((_sec[2], im.read(_sec[2], _sec[3])))
CODE_END = cfg.CODE_HI
run = None
for addr in range(cfg.CODE_LO, CODE_END + 1):
    if addr < CODE_END and (addr not in lf.insn_bytes or os.environ.get("GEN_FULL_CODE")):
        if run is None:
            run = addr
    elif run is not None:
        pieces.append((run, im.read(run, addr - run)))
        run = None
head = 4 + 12 * len(pieces)
blob = bytearray(struct.pack("<I", len(pieces)))
off = head
for va, b in pieces:
    blob += struct.pack("<III", va, len(b), off)
    off += len(b)
for va, b in pieces:
    blob += b
path = os.path.join(cfg.SRC, "image.bin")
if not os.path.exists(path) or open(path, "rb").read() != bytes(blob):
    open(path, "wb").write(blob)
print("data image: %d bytes" % len(blob))
