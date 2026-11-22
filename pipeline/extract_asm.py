# extract_asm.py: write the pure x86 disassembly of every lifted function to asm/, one file per src/*.c.
# usage: extract_asm.py [--exe PATH]      (GAME_EXE is used when --exe is absent)
# Layout: src/<area>/<File>.c  ->  asm/<area>/<File>.asm, the same functions in the same order, plus asm/index.tsv.
# The function extent is the one the lifter used (Lifter.decode: recursive descent from the start address); bytes of the
# function that were not reached as code (jump tables, padding) are written as db/dd lines.  Only writes under asm/.
import csv, os, re, struct, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cfg
from pe_image import Image
from lift import Lifter

OUT = os.path.join(cfg.ROOT, "asm")
ORIGIN = str(cfg.SRC)

im = Image(cfg.game_exe())
FUNCTIONS = os.path.join(cfg.DATA, "functions.tsv")
if not os.path.exists(FUNCTIONS):
    sys.exit("missing %s; run: python static_shock.py functions" % FUNCTIONS)
rows = list(csv.DictReader(open(FUNCTIONS, encoding="utf-8"), delimiter="\t"))
info = {int(r["ea"], 16): (r["name"], int(r["size"])) for r in rows}
live = [r for r in rows if not r["category"].startswith("themida") and r["category"] != "other"]
starts = sorted(int(r["ea"], 16) for r in live)
lf = Lifter(im, starts, {int(r["ea"], 16): r["name"] for r in live})
lf.record = False

pat = re.compile(r"^void f_([0-9a-f]{8})(?:_lifted)?\(void\)")


def data_lines(lo, hi, table_words):
    """db/dd lines for the bytes lo..hi (dd for aligned words inside a jump table)."""
    out = []
    a = lo
    while a < hi:
        if a in table_words and a + 4 <= hi:
            out.append("%08x:  %-20s dd 0x%08x" % (a, im.read(a, 4).hex(" "), struct.unpack("<I", im.read(a, 4))[0]))
            a += 4
            continue
        n = 1
        while a + n < hi and n < 8 and (a + n) not in table_words:
            n += 1
        b = im.read(a, n)
        if not b:
            break
        out.append("%08x:  %-20s db %s" % (a, b.hex(" "), ", ".join("0x%02x" % x for x in b)))
        a += len(b)
    return out


def render(ea):
    name, size = info.get(ea, ("block", None))
    ins = lf.decode(ea)
    tables = lf.tables
    hi_fn = lf.starts[lf._bisect.bisect_right(lf.starts, ea)] if lf._bisect.bisect_right(lf.starts, ea) < len(lf.starts) else None
    words = set()
    tabranges = []
    for a, (tab, tg) in tables.items():
        lo, hi = ea - 0x400, hi_fn if hi_fn else ea + 0x100000
        # forward and backward extent of the table, the same entries the lifter used
        t = tab
        while t < tab + 4 * 1024:
            v = im.u32(t)
            if v is not None and lo <= v < hi and im.read(v, 1):
                t += 4
            else:
                break
        t0 = tab
        while t0 > tab - 4 * 256:
            v = im.u32(t0 - 4)
            if v is not None and lo <= v < hi and im.read(v, 1):
                t0 -= 4
            else:
                break
        tabranges.append((t0, t))
        words.update(range(t0, t, 4))
    targets = set()
    for i in ins.values():
        if i.mn.startswith("j") or i.mn == "jmp":
            targets.update(s for s in i.succ if s in ins)
    for _, tg in tables.values():
        targets.update(t for t in tg if t in ins)
    out = ["; 0x%08X  %s  (%s)" % (ea, name, "%d bytes" % size if size else "block")]
    order = sorted(ins)
    cov = set()
    for a in order:
        cov.update(range(a, a + ins[a].size))
    # data gaps: between instructions that are close together (jump tables, padding), and the tail of the cluster that
    # holds the entry up to the known size; far apart pieces (a block that jumps into another function's code) are not joined
    GAP = 0x1000
    gaps = []
    for x, y in zip(order, order[1:]):
        e = x + ins[x].size
        if y > e and y - e <= GAP:
            gaps.append((e, y))
    if order:
        k = order.index(ea) if ea in ins else 0
        while k + 1 < len(order) and order[k + 1] - (order[k] + ins[order[k]].size) <= GAP:
            k += 1
        e = order[k] + ins[order[k]].size
        stop = ea + size if size else e
        if hi_fn:
            stop = min(stop, hi_fn)
        if stop > e:
            gaps.append((e, stop))
    gapbytes = set()
    for g0, g1 in gaps:
        gapbytes.update(range(g0, g1))
    lines = {}
    for a in order:
        c = ins[a].raw
        lines[a] = [("L_%08x:" % a) if a in targets else None,
                    "%08x:  %-20s %s" % (a, bytes(c.bytes).hex(" "), (c.mnemonic + " " + c.op_str).strip())]
    for g0, g1 in gaps:
        lines[g0] = [None, "; data"] + data_lines(g0, g1, words)
    for k in sorted(lines):
        v = lines[k]
        if v[0]:
            out.append(v[0])
        out.extend(x for x in v[1:])
    # jump tables outside the covered range
    for t0, t1 in tabranges:
        if t0 not in gapbytes and t0 not in ins:
            out.append("; jump table")
            out.extend(data_lines(t0, t1, words))
    out.append("")
    return "\n".join(out) + "\n"


files = {}
for root, _, fs in os.walk(ORIGIN):
    for f in sorted(fs):
        if not f.endswith(".c"):
            continue
        p = os.path.join(root, f)
        eas = []
        for line in open(p, encoding="utf-8", errors="replace"):
            m = pat.match(line)
            if m and "{" not in line.split("(void)")[1][:3] and not line.rstrip().endswith(";"):
                eas.append(int(m.group(1), 16))
        if eas:
            files[p] = eas

t0 = time.time()
nfun = 0
total = 0
index = []
for p, eas in sorted(files.items()):
    rel = os.path.relpath(p, ORIGIN)[:-2] + ".asm"
    dst = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    text = "".join(render(e) for e in eas)
    nfun += len(eas)
    total += len(text)
    with open(dst, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    for e in eas:
        name, size = info.get(e, ("block", 0))
        index.append((e, name, size or 0, rel.replace("\\", "/")))
with open(os.path.join(OUT, "index.tsv"), "w", encoding="utf-8", newline="\n") as fh:
    fh.write("ea\tname\tsize\tfile\n")
    for e, name, size, rel in sorted(index):
        fh.write("%08x\t%s\t%d\t%s\n" % (e, name, size, rel))
print("%d files, %d functions/blocks, %d bytes, %d index rows, %.1fs"
      % (len(files), nfun, total, len(index), time.time() - t0))
