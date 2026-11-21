# difftest.py: run random inputs through each function in Unicorn (original bytes) and through the lifted C (recomp.exe)
# and compare registers and a CRC of the data/stack/heap regions.
# usage: difftest.py [--funcs hex,hex] [--tests 3] [--limit N] [--skip-api]
import csv, os, random, subprocess, sys, zlib, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_image import Image
import cfg
try:
    from difftest_gens import GENS
except ImportError:
    GENS = {}

EXE = cfg.game_exe()
RECOMP_EXE = os.path.join(cfg.BIN, os.environ.get("RECOMP_EXE", "recomp.exe"))      # driver build
# Linux with a sysroot: start the driver through the sysroot's loader
_sysroot = os.environ.get("SS_SYSROOT")
DRIVER = ([os.path.join(_sysroot, "usr/lib/i386-linux-gnu/ld-linux.so.2"), "--library-path", os.path.join(_sysroot, "usr/lib/i386-linux-gnu")]
          if _sysroot and os.name != "nt" else []) + [RECOMP_EXE]
try:
    from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL
    from unicorn.x86_const import *
except ImportError:
    sys.exit("difftest needs Unicorn: pip install unicorn")
HERE = os.path.dirname(os.path.abspath(__file__))
DATA_LO, DATA_HI = cfg.CODE_LO, cfg.CODE_HI
STK_BASE, STK_SIZE, STK_TOP = 0x0A000000, 0x100000, 0x0A0F0000
HEAP, HEAP_SIZE = 0x03000000, 0x10000
TEB = 0x2E000000
SENT = 0xDEAD0000

args = sys.argv[1:]
def opt(n, d=None):
    return args[args.index(n) + 1] if n in args else d
ntests = int(opt("--tests", 3))
if "--struct-heap" in args:
    os.environ["STRUCT_HEAP"] = "1"       # read by the test driver, which fills its heap the same way
limit = int(opt("--limit", 0))
only = {int(x, 16) for x in opt("--funcs").split(",")} if opt("--funcs") else None

im = Image(EXE)
rows = list(csv.DictReader(open(os.path.join(cfg.DATA, "functions.tsv"), encoding="utf-8"), delimiter="\t"))
rows = [r for r in rows if not r["category"].startswith("themida") and r["category"] != "other"]
names = {int(r["ea"], 16): r["name"] for r in rows}
unsup = set()
for l in open(os.path.join(cfg.BUILD_OUT, "unsupported.txt")):
    unsup.add(int(l.split()[0], 16))
cands = [int(r["ea"], 16) for r in rows if int(r["ea"], 16) not in unsup and int(r["size"]) > 0]
if only:
    cands = [c for c in cands if c in only]
if limit:
    random.Random(1).shuffle(cands)
    cands = sorted(cands[:limit])

# unicorn machine
uc = Uc(UC_ARCH_X86, UC_MODE_32)
for nm, vs, va, rs, rp in im.secs:
    sz = (max(vs, rs) + 0xFFF) & ~0xFFF
    uc.mem_map(va, sz, UC_PROT_ALL)
    uc.mem_write(va, im.d[rp:rp + rs])
uc.mem_map(STK_BASE, STK_SIZE, UC_PROT_ALL)
uc.mem_map(HEAP, HEAP_SIZE, UC_PROT_ALL)
uc.mem_map(TEB, 0x1000, UC_PROT_ALL)
uc.mem_map(SENT & ~0xFFF, 0x1000, UC_PROT_ALL)
pristine = im.read(DATA_LO, DATA_HI - DATA_LO)
GDT = 0x02100000
uc.mem_map(GDT, 0x1000, UC_PROT_ALL)
def gdt_entry(base, limit, access, flags):
    return struct.pack("<HHBBBB", limit & 0xFFFF, base & 0xFFFF, (base >> 16) & 0xFF, access, ((limit >> 16) & 0xF) | (flags << 4), (base >> 24) & 0xFF)
for i_, e_ in enumerate([bytes(8), gdt_entry(0, 0xFFFFF, 0x9B, 0xC), gdt_entry(0, 0xFFFFF, 0x93, 0xC), gdt_entry(TEB, 0xFFF, 0x93, 0x4)]):
    uc.mem_write(GDT + 8 * i_, e_)
uc.reg_write(UC_X86_REG_GDTR, (0, GDT, 8 * 4 - 1, 0))
uc.reg_write(UC_X86_REG_CS, 0x08)
uc.reg_write(UC_X86_REG_SS, 0x10)
uc.reg_write(UC_X86_REG_DS, 0x10)
uc.reg_write(UC_X86_REG_ES, 0x10)
uc.reg_write(UC_X86_REG_FS, 0x18)

heaps = {}
def heap_bytes(seed):
    if seed not in heaps:
        s = seed
        out = bytearray()
        for _ in range(HEAP_SIZE // 4):
            s ^= (s << 13) & 0xFFFFFFFF
            s ^= s >> 17
            s ^= (s << 5) & 0xFFFFFFFF
            w = s
            if "--struct-heap" in args:      # a heap of linked objects (the driver does the same with STRUCT_HEAP=1)
                if s & 3 == 0:
                    w = HEAP + ((s >> 8) % (HEAP_SIZE // 4 - 64)) * 4
                elif s & 3 == 1:
                    w = (s >> 8) & 7
            out += struct.pack("<I", w)
        heaps[seed] = bytes(out)
    return heaps[seed]

rnd = random.Random(12345)
def val():
    k = rnd.random()
    if k < 0.25: return 0
    if k < 0.5: return rnd.randrange(1, 64)
    if k < 0.9: return HEAP + 4 * rnd.randrange(0, HEAP_SIZE // 4 - 64)
    return rnd.getrandbits(32)

def xm_vals(seed, ea):
    r = random.Random(seed * 1000003 ^ ea)
    out = []
    for _ in range(8):
        k = r.random()
        if k < 0.3:
            out += [0, 0]
        elif k < 0.7:
            out += list(struct.unpack("<II", struct.pack("<d", float(r.randrange(-50, 50)) / r.choice((1, 2, 4, 10)))) ) + list(struct.unpack("<II", struct.pack("<d", float(r.randrange(-9, 9)))))
        else:
            out += [r.getrandbits(32) for _ in range(4)]
    return out[:32] if len(out) == 32 else (out + [0] * 32)[:32]

def ov_vals(stack):
    ov = getattr(stack, 'ov', {})
    return [len(ov)] + [x for kv in ov.items() for x in kv] if ov else []

def unicorn_run(addr, regs, seed, stack):
    uc.mem_write(DATA_LO, pristine)
    uc.mem_write(STK_BASE, bytes(STK_SIZE))
    uc.mem_write(HEAP, heap_bytes(seed))
    for a_, v_ in getattr(stack, 'ov', {}).items():
        uc.mem_write(a_, struct.pack('<I', v_))
    uc.mem_write(TEB, bytes(0x1000))
    uc.mem_write(TEB, struct.pack("<IIII", 0xFFFFFFFF, STK_TOP + 0x1000, STK_BASE, 0))
    uc.mem_write(TEB + 0x18, struct.pack("<I", TEB))
    esp = STK_TOP
    for a in reversed(stack):
        esp -= 4
        uc.mem_write(esp, struct.pack("<I", a))
    esp -= 4
    uc.mem_write(esp, struct.pack("<I", SENT))
    for r, v in zip((UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP), regs):
        uc.reg_write(r, v)
    uc.reg_write(UC_X86_REG_ESP, esp)
    xv = xm_vals(seed, addr)
    for k in range(8):
        uc.reg_write(UC_X86_REG_XMM0 + k, xv[4 * k] | (xv[4 * k + 1] << 32) | (xv[4 * k + 2] << 64) | (xv[4 * k + 3] << 96))
    uc.reg_write(UC_X86_REG_MXCSR, 0x1F80)
    uc.reg_write(UC_X86_REG_EFLAGS, 2)
    for sr, sv in ((UC_X86_REG_CS, 0x08), (UC_X86_REG_SS, 0x10), (UC_X86_REG_DS, 0x10), (UC_X86_REG_ES, 0x10), (UC_X86_REG_FS, 0x18)):
        uc.reg_write(sr, sv)
    try:
        uc.reg_write(UC_X86_REG_FPCW, 0x37F)
        uc.reg_write(UC_X86_REG_FPSW, 0)
    except Exception:
        pass
    try:
        uc.emu_start(addr, SENT, count=3000000)
    except UcError:
        return None
    if uc.reg_read(UC_X86_REG_EIP) != SENT:
        return None
    out = [uc.reg_read(r) for r in (UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP)]
    c = zlib.crc32(bytes(uc.mem_read(DATA_LO, DATA_HI - DATA_LO)))
    esp_end = out[7]       # only the live part of the stack counts (the driver does the same): below the final esp is dead
    live = esp_end if STK_TOP - 0x4000 <= esp_end <= STK_TOP + 0x100 else STK_TOP - 0x4000
    if not os.environ.get("NOSTACK"):
        c = zlib.crc32(bytes(uc.mem_read(live, STK_TOP + 0x100 - live)), c)
    c = zlib.crc32(bytes(uc.mem_read(HEAP, HEAP_SIZE)), c)
    return out + [c]

cases = []   # (addr, regs, seed, stack, expected)
for ea in cands:
    for t in range(ntests):
        regs = [val() for _ in range(7)]
        seed = rnd.randrange(1, 9)
        stack = GENS[ea](rnd, HEAP) if ea in GENS else [val() for _ in range(8)]
        exp = unicorn_run(ea, regs, seed, stack)
        if exp is None:
            continue
        cases.append((ea, regs, seed, stack, exp))
print("unicorn produced %d test cases for %d functions" % (len(cases), len(set(c[0] for c in cases))))

def run_c(cs):
    path = os.path.join(cfg.BUILD, "tests-%d.txt" % os.getpid())
    with open(path, "w") as f:
        for ea, regs, seed, stack, _ in cs:
            f.write(" ".join("%x" % x for x in [ea] + regs + [seed, len(stack)] + stack + xm_vals(seed, ea) + ov_vals(stack)) + "\n")
    for _try in range(40):
        p = subprocess.run([*DRIVER, EXE, path], capture_output=True, text=True, timeout=600)
        if p.returncode != 77:
            break
    return [l for l in p.stdout.splitlines() if l.strip()], p.returncode

results = []
rest = cases
crashed = []
while rest:
    lines, rc = run_c(rest)
    results.extend(lines[:len(rest)] if rc == 0 else lines)
    done = len(lines)
    if rc != 0 and done and lines[-1].startswith("CRASH"):
        crashed.append(rest[done - 1][0])
        rest = rest[done:]
    else:
        rest = []
        if rc != 0:
            print("driver exit", rc)

bad, unsupc, ok = {}, {}, 0
okby = {}      # address -> number of passed tests
for (ea, regs, seed, stack, exp), line in zip(cases, results):
    p = line.split()
    if p[0] == "UNSUP":
        unsupc.setdefault(ea, line)
        continue
    if p[0] == "CRASH":
        bad.setdefault(ea, "C crashed at " + p[1])
        continue
    got = [int(x, 16) for x in p[1:]]
    # --ignore ecx,edx: registers a hand-written replacement does not have to reproduce (scratch registers of the calling convention)
    skip = {"eax ecx edx ebx esi edi ebp esp crc".split().index(r) for r in (opt("--ignore") or "").split(",") if r}
    if all(g == e for i, (g, e) in enumerate(zip(got, exp)) if i not in skip):
        ok += 1
        okby[ea] = okby.get(ea, 0) + 1
    else:
        names_ = "eax ecx edx ebx esi edi ebp esp crc".split()
        d = ", ".join("%s %08x!=%08x" % (n, g, e) for n, g, e in zip(names_, got, exp) if g != e)
        bad.setdefault(ea, d)
print("tests passed: %d; functions with a mismatch: %d; functions whose C hit an unsupported/unknown path: %d" % (ok, len(bad), len(unsupc)))
with open(os.path.join(cfg.BUILD, "difftest_report-%d.txt" % os.getpid()), "w", encoding="utf-8") as o:
    for ea, d in sorted(bad.items()):
        o.write("MISMATCH %08x %s: %s\n" % (ea, names.get(ea, ""), d))
    for ea, d in sorted(unsupc.items()):
        o.write("UNSUP %08x %s: %s\n" % (ea, names.get(ea, ""), d))
for ea, d in sorted(bad.items())[:40]:
    print("MISMATCH %08x %s: %s" % (ea, names.get(ea, ""), d))

if "--record" in args:
  import srclock
  with srclock.lock():
    # rewrite/verified.tsv: every hand-written function that passed (address, name, tests passed, registers not compared); read by progress.py
    vpath = os.path.join(cfg.ROOT, "rewrite", "verified.tsv")
    rows_v = {}
    if os.path.exists(vpath):
        for l in open(vpath, encoding="utf-8").read().splitlines()[1:]:
            p = l.split("\t")
            rows_v[int(p[0], 16)] = p
    for ea, n in okby.items():
        if ea not in bad and ea not in unsupc:
            rows_v[ea] = ["%08x" % ea, names.get(ea, ""), str(n), opt("--ignore") or ""]
    with open(vpath, "w", encoding="utf-8", newline="") as f:
        f.write("address\tname\ttests\tignored registers\tmethod\n")
        for ea in sorted(rows_v):
            f.write("\t".join(rows_v[ea]) + "\n")
    print("recorded %d verified functions in rewrite/verified.tsv" % len(rows_v))

if "--show" in args:
    # re-run the first mismatching test of each --funcs function with byte-level diffs of both sides
    for (ea, regs, seed, stack, exp), line in zip(cases, results):
        p = line.split()
        sk_ = {"eax ecx edx ebx esi edi ebp esp crc".split().index(r) for r in (opt("--ignore") or "").split(",") if r}
        if p[0] != "OK" or all(int(g, 16) == e for i_, (g, e) in enumerate(zip(p[1:], exp)) if i_ not in sk_):
            continue
        exp2 = unicorn_run(ea, regs, seed, stack)
        cur = bytes(uc.mem_read(DATA_LO, DATA_HI - DATA_LO))
        ud = {DATA_LO + i: cur[i] for i in range(len(cur)) if cur[i] != pristine[i]}
        hp = bytes(uc.mem_read(HEAP, HEAP_SIZE)); h0 = heap_bytes(seed)
        ud.update({HEAP + i: hp[i] for i in range(len(hp)) if hp[i] != h0[i]})
        sk = bytes(uc.mem_read(STK_TOP - 0x4000, 0x4100))
        ud.update({STK_TOP - 0x4000 + i: sk[i] for i in range(len(sk)) if sk[i]})
        os.environ["DIFF"] = "1"
        path = os.path.join(cfg.BUILD, "tests1-%d.txt" % os.getpid())
        with open(path, "w") as f:
            f.write(" ".join("%x" % x for x in [ea] + regs + [seed, len(stack)] + stack + xm_vals(seed, ea) + ov_vals(stack)) + "\n")
        for _t in range(40):
            pr_ = subprocess.run([*DRIVER, EXE, path], capture_output=True, text=True)
            if pr_.returncode != 77:
                break
        out = pr_.stdout.splitlines()
        if not out:
            print("  driver exit", pr_.returncode, pr_.stderr[-300:])
        cd = {int(l.split()[1], 16): int(l.split()[2], 16) for l in out if l.startswith("D ")}
        hfile = os.path.join(cfg.BUILD, "heapdump-%d.bin" % os.getpid())
        os.environ["DUMPHEAP"] = hfile
        for _t in range(40):
            if subprocess.run([*DRIVER, EXE, path], capture_output=True, text=True).returncode != 77:
                break
        if os.path.exists(hfile):
            ch = open(hfile, "rb").read()
            dif = [i for i in range(min(len(ch), len(hp))) if ch[i] != hp[i]]
            print("  heap bytes differing: %d" % len(dif), ["%x: unicorn %02x C %02x" % (HEAP + i, hp[i], ch[i]) for i in dif[:12]])
            os.remove(hfile)
        os.environ.pop("DUMPHEAP", None)
        print("function %08x %s: regs in=%s stack=%s" % (ea, names.get(ea, ""), ["%x" % r for r in regs], ["%x" % s for s in stack]))
        print("  unicorn regs", ["%x" % v for v in exp2], "\n  C regs      ", out[-1] if out else "")
        for a in sorted(set(ud) | set(cd))[:int(os.environ.get("SHOWN", "30"))]:
            if ud.get(a) != cd.get(a):
                print("   byte %08x: unicorn %s, C %s" % (a, ud.get(a), cd.get(a)))
        break

if "--parts" in args and cases:
    ea, regs, seed, stack, exp = cases[0]
    unicorn_run(ea, regs, seed, stack)
    print("unicorn parts data %08x stack %08x heap %08x" % (zlib.crc32(bytes(uc.mem_read(DATA_LO, DATA_HI - DATA_LO))), zlib.crc32(bytes(uc.mem_read(STK_TOP - 0x4000, 0x4100))), zlib.crc32(bytes(uc.mem_read(HEAP, HEAP_SIZE)))))
    os.environ["PARTS"] = "1"
    path = os.path.join(cfg.BUILD, "tests1-%d.txt" % os.getpid())
    with open(path, "w") as f:
        f.write(" ".join("%x" % x for x in [ea] + regs + [seed, len(stack)] + stack + xm_vals(seed, ea) + ov_vals(stack)) + "\n")
    for _t in range(40):
        pr_ = subprocess.run([*DRIVER, EXE, path], capture_output=True, text=True)
        if pr_.returncode != 77:
            break
    print(pr_.stdout)
