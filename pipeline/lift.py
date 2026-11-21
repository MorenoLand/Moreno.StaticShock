# lift.py: lift one function of the original PE (x86-32) to C.
#
# Model (see rt.h): the guest image is mapped at its own addresses in a 32-bit process, so a guest address is a host
# pointer.  Guest registers are globals (r_eax ...), the guest stack lives in guest memory, every function is
# `void f_XXXXXXXX(void)`, a call pushes the real return address and calls the C function, `ret N` pops 4+N and returns.
# Flags are local variables (fZ fS fC fO fP fA), computed only where a later instruction can read them (liveness).
import re
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import *

REG32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
FLAGS = "ZSCOPA"
ALLF = frozenset(FLAGS)

COND = {
    "e": "fZ", "ne": "!fZ", "a": "(!fC&&!fZ)", "ae": "!fC", "b": "fC", "be": "(fC||fZ)",
    "g": "(!fZ&&fS==fO)", "ge": "(fS==fO)", "l": "(fS!=fO)", "le": "(fZ||fS!=fO)",
    "s": "fS", "ns": "!fS", "o": "fO", "no": "!fO", "p": "fP", "np": "!fP",
}
COND_FLAGS = {
    "e": "Z", "ne": "Z", "a": "CZ", "ae": "C", "b": "C", "be": "CZ", "g": "ZSO", "ge": "SO", "l": "SO", "le": "ZSO",
    "s": "S", "ns": "S", "o": "O", "no": "O", "p": "P", "np": "P",
}

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True


def regparts(name):
    if name in REG32:
        return name, 32, 0
    if name in ("ax", "cx", "dx", "bx", "sp", "bp", "si", "di"):
        return "e" + name, 16, 0
    if name in ("al", "cl", "dl", "bl"):
        return "e" + name[0] + "x", 8, 0
    if name in ("ah", "ch", "dh", "bh"):
        return "e" + name[0] + "x", 8, 8
    return None


class Unsupported(Exception):
    pass


class Ins:
    __slots__ = ("addr", "size", "mn", "ops", "text", "succ", "uses", "defs", "may", "live_out", "live_in", "raw")


def mask(bits):
    return {8: "0xffu", 16: "0xffffu", 32: "0xffffffffu"}[bits]


class Lifter:
    def __init__(self, image, func_starts, func_names=None, iat=None, code_lo=None, code_hi=None):
        self.im = image
        self.code_lo = code_lo if code_lo is not None else image.base + 0x1000
        self.code_hi = code_hi if code_hi is not None else image.base + image.image_size
        self.starts = func_starts            # sorted list of function entry addresses
        self.startset = set(func_starts)
        self.names = func_names or {}
        self.iat = iat or {}                  # slot address -> import name
        self.unsup = []                       # (addr, text) of instructions emitted as UNSUP
        self.calls = set()                    # static call/tail-call targets
        self.imm_cands = set()                # code addresses used as immediate operands (function pointers: callbacks, allocators)
        self.insn_bytes = set()               # every byte that belongs to a decoded instruction; the rest of the code range is data (jump tables, padding)
        self.record = True                    # False while lifting a guessed function start (see gen.py): its bytes may be a table, so they stay data
        import bisect
        self._bisect = bisect

    # ---- operand helpers ----
    def rname(self, r):
        return md.reg_name(r)

    def addr_expr(self, m, with_seg=True):
        parts = []
        if m.base:
            parts.append("r_" + self.rname(m.base))
        if m.index:
            s = "r_" + self.rname(m.index)
            if m.scale != 1:
                s += "*%d" % m.scale
            parts.append(s)
        d = m.disp & 0xFFFFFFFF
        if with_seg and m.segment == X86_REG_FS:
            parts.append("TEB")
        if d or not parts:
            parts.append("0x%xu" % d)
        return "(u32)(" + "+".join(parts) + ")"

    def read(self, op, bits=None):
        bits = bits or op.size * 8
        if op.type == X86_OP_REG:
            segs = {"cs": 0x23, "ss": 0x2B, "ds": 0x2B, "es": 0x2B, "gs": 0x2B, "fs": 0x53}      # Windows user-mode selectors
            if self.rname(op.reg) in segs:
                return "0x%xu" % segs[self.rname(op.reg)]
            full, rb, sh = regparts(self.rname(op.reg))
            if rb == 32:
                return "r_" + full
            if sh:
                return "(u8)(r_%s>>8)" % full
            return "(u%d)r_%s" % (rb, full)
        if op.type == X86_OP_IMM:
            return "0x%xu" % (op.imm & ((1 << bits) - 1))
        if op.type == X86_OP_MEM:
            return "R%d(%s)" % (bits, self.addr_expr(op.mem))
        raise Unsupported("operand")

    def write(self, op, v, bits=None):
        bits = bits or op.size * 8
        if op.type == X86_OP_REG:
            full, rb, sh = regparts(self.rname(op.reg))
            if rb == 32:
                return "r_%s = %s;" % (full, v)
            if rb == 16:
                return "r_%s = (r_%s & 0xffff0000u) | ((%s) & 0xffffu);" % (full, full, v)
            if sh:
                return "r_%s = (r_%s & 0xffff00ffu) | (((%s) & 0xffu) << 8);" % (full, full, v)
            return "r_%s = (r_%s & 0xffffff00u) | ((%s) & 0xffu);" % (full, full, v)
        if op.type == X86_OP_MEM:
            return "W%d(%s, %s);" % (bits, self.addr_expr(op.mem), v)
        raise Unsupported("write operand")

    # ---- decode (recursive descent) ----
    def decode(self, ea):
        ins = {}
        work = [ea]
        tables = {}
        owner_lo = ea
        nxt = self._bisect.bisect_right(self.starts, ea)
        owner_hi = self.starts[nxt] if nxt < len(self.starts) else ea + 0x100000
        while work:
            a = work.pop()
            while a not in ins:
                b = self.im.read(a, 16)
                d = list(md.disasm(b, a, 1)) if b else []
                if not d:
                    break
                c = d[0]
                i = Ins()
                i.addr, i.size, i.mn = a, c.size, c.mnemonic
                i.ops = list(c.operands)
                i.text = "%s %s" % (c.mnemonic, c.op_str)
                if not (c.mnemonic.startswith("j") or c.mnemonic == "call"):
                    for o in c.operands:
                        if o.type == X86_OP_IMM and self.code_lo <= (o.imm & 0xFFFFFFFF) < self.code_hi:
                            self.imm_cands.add(o.imm & 0xFFFFFFFF)
                i.raw = c
                i.succ = []
                ins[a] = i
                if self.record:
                    self.insn_bytes.update(range(a, a + c.size))
                nextaddr = a + c.size
                m = c.mnemonic
                if m in ("ret", "hlt", "int3", "retn", "repz ret", "rep ret"):
                    break
                if m == "jmp":
                    o = i.ops[0]
                    if o.type == X86_OP_IMM:
                        t = o.imm
                        if t in self.startset and t != ea:
                            i.succ = []
                            self.calls.add(t)
                        else:
                            i.succ = [t]
                            work.append(t)
                    elif o.type == X86_OP_MEM and o.mem.index and o.mem.scale == 4 and not o.mem.base:
                        tab = o.mem.disp & 0xFFFFFFFF
                        tg = self.read_table(tab, ea, owner_hi)
                        tables[a] = (tab, tg)
                        i.succ = list(dict.fromkeys(tg))
                        work.extend(tg)
                    break
                if m.startswith("j") and m != "jmp":
                    t = i.ops[0].imm
                    i.succ = [nextaddr, t]
                    work.append(t)
                    a = nextaddr
                    continue
                if m == "call":
                    o = i.ops[0]
                    if o.type == X86_OP_IMM:
                        self.calls.add(o.imm)
                i.succ = [nextaddr]
                a = nextaddr
        self.tables = tables
        return ins

    def read_table(self, tab, ea, hi):
        """Entries of a jump table that start at `tab`.  The index can be negative (memcpy's tail table), so entries
        before `tab` that still point into this function are included; the emitted switch dispatches on the loaded
        address, so a superset is harmless."""
        lo = ea - 0x400
        out = []

        def scan(direction, limit):
            bad = 0
            for k in range(0 if direction > 0 else 1, limit):
                v = self.im.u32(tab + direction * 4 * k)
                if v is not None and lo <= v < hi and self.im.read(v, 1):
                    out.append(v)
                    bad = 0
                else:
                    bad += 1          # one junk entry is allowed: memcpy's table overlaps code bytes
                    if bad > 1:
                        break
        scan(-1, 257)
        scan(1, 1024)
        return out

    # ---- semantics: returns (uses, defs, may_def_only, code builder) ----
    def lift(self, ea, suffix=""):
        ins = self.decode(ea)
        self._ins = ins
        order = sorted(ins)
        # liveness
        for a in order:
            self.analyse(ins[a])
        for a in order:
            ins[a].live_out = set()
            ins[a].live_in = set()
        changed = True
        while changed:
            changed = False
            for a in reversed(order):
                i = ins[a]
                lo = set()
                for s in i.succ:
                    if s in ins:
                        lo |= ins[s].live_in
                li = set(i.uses) | (lo - set(i.defs))
                if lo != i.live_out or li != i.live_in:
                    i.live_out, i.live_in = lo, li
                    changed = True
        targets = set()
        for a in order:
            i = ins[a]
            for s in i.succ:
                if s != i.addr + i.size or i.mn.startswith("j"):
                    targets.add(s)
        for tab, tg in self.tables.values():
            targets.update(tg)
        name = self.names.get(ea, "")
        out = ["void f_%08x%s(void)%s" % (ea, suffix, " /* %s */" % name if name else ""), "{",
               "    int fZ = 0, fS = 0, fC = 0, fO = 0, fP = 0, fA = 0; (void)fZ; (void)fS; (void)fC; (void)fO; (void)fP; (void)fA;",
               "    FN_ENTER(0x%08x);" % ea]
        if order and order[0] != ea:
            # code that belongs to the function lies before its entry point: start by jumping to the entry
            targets.add(ea)
            out.append("    goto L_%08x;" % ea)
        for a in order:
            i = ins[a]
            if a in targets:
                out.append("L_%08x:; BB(0x%08x);" % (a, a))
            try:
                code = self.emit(i, ea)
            except Unsupported as e:
                code = ['UNSUP(0x%08x, "%s");' % (a, i.text.replace('"', "'"))]
                self.unsup.append((a, i.text))
            out.append("    /* %08x: %s */ %s" % (a, i.text, " ".join(code)))
            # fall off the end of the decoded region without a terminator: trap
            if i.succ and i.succ[0] == a + i.size and (a + i.size) not in ins and not i.mn.startswith("j") and i.mn != "call":
                out.append("    UNSUP(0x%08x, \"falls out of decoded code\");" % (a + i.size))
            if i.mn == "call" and (a + i.size) not in ins:
                out.append("    UNSUP(0x%08x, \"call does not return\");" % (a + i.size))
        out.append("}")
        return "\n".join(out)

    # ---- flag use/def per instruction ----
    def analyse(self, i):
        m = i.mn
        u, d = set(), set()
        base = m.split()[-1] if m.startswith("rep") else m
        if m.startswith("j") and m != "jmp":
            cc = m[1:]
            u = set(COND_FLAGS.get(cc, "ZSCOPA"))
        elif m.startswith("set") or (m.startswith("cmov")):
            cc = m[3:] if m.startswith("set") else m[4:]
            u = set(COND_FLAGS.get(cc, "ZSCOPA"))
        elif m in ("add", "sub", "cmp", "and", "or", "xor", "test", "neg"):
            d = set("ZSCOPA")
        elif m in ("inc", "dec"):
            d = set("ZSOPA")
        elif m in ("adc", "sbb"):
            u, d = {"C"}, set("ZSCOPA")
        elif m in ("shl", "shr", "sar", "rol", "ror", "shld", "shrd", "sal"):
            cnt = i.ops[-1] if m not in ("shld", "shrd") else i.ops[2]
            fl = set("ZSCOP") if m not in ("rol", "ror") else set("CO")
            if cnt.type == X86_OP_IMM and (cnt.imm & 31) != 0:
                d = fl
            else:
                u = set(fl)          # flags unchanged when the count is zero: value passes through
                d = set()
        elif m in ("mul", "imul"):
            d = set("CO")
        elif m in ("comisd", "ucomisd"):
            d = set(ALLF)
        elif m == "sahf":
            d = set("ZSCPA")
        elif m == "lahf":
            u = set("ZSCPA")
        elif m in ("cmc",):
            u, d = {"C"}, {"C"}
        elif m in ("clc", "stc"):
            d = {"C"}
        elif m in ("rcl", "rcr", "pushfd", "popfd", "pushf", "popf"):
            u = set(ALLF)
            d = set(ALLF) if "pop" in m or m.startswith("rc") else set()
        elif base in ("cmpsb", "cmpsd", "scasb", "scasd", "scasw"):
            d = set("ZSCOPA")
        elif m in ("bt", "bts", "btr", "btc"):
            d = {"C"}
        elif m in ("div", "idiv"):
            d = set()
        elif m in ("call", "ret", "retn", "repz ret", "rep ret"):      # a jmp passes the flags on to its target
            u, d = set(), set(ALLF)
        elif m.startswith("f") and m in ("fcom", "fcomp"):
            pass
        i.uses, i.defs = u, d
        # kill-all at calls / returns so nothing is live across them
        if m in ("call", "ret", "retn"):
            i.uses = set()

    # ---- flag computation code ----
    def flagcode(self, kind, bits, live, cin=False):
        sb = bits - 1
        L = []

        def add(f, e):
            if f in live:
                L.append("f%s = %s;" % (f, e))
        add("Z", "(r == 0)")
        add("S", "((r >> %d) & 1)" % sb)
        add("P", "!__builtin_parity(r & 0xffu)")
        add("A", "(((a ^ b ^ r) & 0x10u) != 0)")
        if kind in ("add", "inc"):
            add("O", "(((a ^ r) & (b ^ r)) >> %d) & 1" % sb)
            if kind == "add":
                add("C", "(r < a)")
        elif kind in ("sub", "dec"):
            add("O", "(((a ^ b) & (a ^ r)) >> %d) & 1" % sb)
            if kind == "sub":
                add("C", "(a < b)")
        elif kind == "logic":
            add("O", "0")
            add("C", "0")
        elif kind == "adc":
            add("O", "(((a ^ r) & (b ^ r)) >> %d) & 1" % sb)
            add("C", "(unsigned)((((u64)a + b + c) >> %d) & 1)" % bits)
        elif kind == "sbb":
            add("O", "(((a ^ b) & (a ^ r)) >> %d) & 1" % sb)
            add("C", "((u64)a < (u64)b + c)")
        return " ".join(L)

    # ---- instruction emission ----
    def emit(self, i, fea):
        m = i.mn
        ops = i.ops
        live = i.live_out
        nxt = i.addr + i.size

        def sz():
            return ops[0].size * 8

        if m == "nop" or m == "wait" or m == "fnclex" or m == "fwait" or m == "int3" and False:
            return [";"]
        if m == "int3" or m == "hlt":
            return ['UNSUP(0x%08x, "%s");' % (i.addr, m)]
        if m == "mov":
            bits = ops[0].size * 8
            return [self.write(ops[0], self.read(ops[1], bits), bits)]
        if m in ("movzx", "movsx"):
            sbits = ops[1].size * 8
            dbits = ops[0].size * 8
            v = self.read(ops[1], sbits)
            if m == "movsx":
                v = "(u32)(i32)(i%d)%s" % (sbits, v)
            else:
                v = "(u32)%s" % v
            return [self.write(ops[0], v, dbits)]
        if m == "lea":
            return [self.write(ops[0], self.addr_expr(ops[1].mem, False), 32)]
        if m == "xchg":
            bits = ops[0].size * 8
            return ["{ u32 x = %s; u32 y = %s; %s %s }" % (self.read(ops[0], bits), self.read(ops[1], bits),
                                                           self.write(ops[0], "y", bits), self.write(ops[1], "x", bits))]
        if m == "push":
            return ["{ u32 v = %s; r_esp -= 4; W32(r_esp, v); }" % (self.read(ops[0], 32) if ops[0].type != X86_OP_IMM else "0x%xu" % (ops[0].imm & 0xFFFFFFFF))]
        if m == "pop":
            return ["{ u32 v = R32(r_esp); r_esp += 4; %s }" % self.write(ops[0], "v", 32)]
        if m == "leave":
            return ["r_esp = r_ebp; r_ebp = R32(r_esp); r_esp += 4;"]
        if m in ("ret", "retn", "repz ret", "rep ret"):
            n = ops[0].imm if ops else 0
            return ["FN_RET(0x%08x); r_esp += %d; return;" % (fea, 4 + n)]
        if m == "call":
            o = ops[0]
            ret = "0x%xu" % nxt
            if o.type == X86_OP_IMM:
                return ["r_esp -= 4; W32(r_esp, %s); f_%08x();" % (ret, o.imm)]
            return ["{ u32 t = %s; r_esp -= 4; W32(r_esp, %s); call_ind(t); }" % (self.read(o, 32), ret)]
        if m == "jmp":
            o = ops[0]
            if o.type == X86_OP_IMM:
                if o.imm in self.startset and o.imm != i.addr and not i.succ:
                    return ["f_%08x(); return;" % o.imm]
                if o.imm not in self._ins:
                    return ['UNSUP(0x%08x, "jump to code that was not decoded");' % i.addr]
                return ["goto L_%08x;" % o.imm]
            if i.addr in self.tables:
                tab, tg = self.tables[i.addr]
                cases = " ".join("case 0x%xu: goto L_%08x;" % (t, t) for t in dict.fromkeys(tg))
                return ["{ u32 t = R32(%s); switch (t) { %s default: UNSUP(0x%08x, \"jump table entry is not a known target\"); } }" % (self.addr_expr(o.mem), cases, i.addr)]
            return ["{ u32 t = %s; call_ind(t); return; }" % self.read(o, 32)]
        if m.startswith("j"):
            cc = m[1:]
            if cc not in COND:
                raise Unsupported(m)
            if ops[0].imm not in self._ins:
                return ['if (%s) UNSUP(0x%08x, "branch to code that was not decoded");' % (COND[cc], i.addr)]
            return ["if (%s) goto L_%08x;" % (COND[cc], ops[0].imm)]
        if m.startswith("set"):
            cc = m[3:]
            return [self.write(ops[0], "(%s) ? 1 : 0" % COND[cc], 8)]
        if m.startswith("cmov"):
            cc = m[4:]
            return ["if (%s) { %s }" % (COND[cc], self.write(ops[0], self.read(ops[1], 32), 32))]
        if m == "cdq":
            return ["r_edx = (r_eax >> 31) ? 0xffffffffu : 0;"]
        if m == "cwde":
            return ["r_eax = (u32)(i32)(i16)r_eax;"]
        if m == "cwd":
            return ["r_edx = (r_edx & 0xffff0000u) | (((r_eax >> 15) & 1) ? 0xffffu : 0);"]
        if m == "sahf":
            return ["{ u32 h = (r_eax >> 8) & 0xff; fS = (h >> 7) & 1; fZ = (h >> 6) & 1; fA = (h >> 4) & 1; fP = (h >> 2) & 1; fC = h & 1; }"]
        if m == "lahf":
            return ["r_eax = (r_eax & 0xffff00ffu) | ((u32)((fS << 7) | (fZ << 6) | (fA << 4) | (fP << 2) | 2 | fC) << 8);"]
        if m == "clc":
            return ["fC = 0;"]
        if m == "stc":
            return ["fC = 1;"]
        if m == "cmc":
            return ["fC = !fC;"]
        if m == "cld":
            return ["rt_df = 0;"]
        if m == "std":
            return ["rt_df = 1;"]

        if m in ("add", "sub", "cmp", "and", "or", "xor", "test", "adc", "sbb"):
            bits = ops[0].size * 8
            mk = mask(bits)
            a = self.read(ops[0], bits)
            b = self.read(ops[1], bits)
            if ops[1].type == X86_OP_IMM:
                b = "0x%xu" % (ops[1].imm & ((1 << bits) - 1))
            exprs = {"add": "a + b", "sub": "a - b", "cmp": "a - b", "and": "a & b", "or": "a | b", "xor": "a ^ b",
                     "test": "a & b", "adc": "a + b + c", "sbb": "a - b - c"}
            kind = {"add": "add", "sub": "sub", "cmp": "sub", "and": "logic", "or": "logic", "xor": "logic",
                    "test": "logic", "adc": "adc", "sbb": "sbb"}[m]
            pre = "u32 c = fC;" if m in ("adc", "sbb") else ""
            store = "" if m in ("cmp", "test") else self.write(ops[0], "r", bits)
            fc = self.flagcode(kind, bits, live)
            # memory destination: evaluate the address once through a temp when it is a read-modify-write
            if ops[0].type == X86_OP_MEM and m not in ("cmp", "test"):
                ad = self.addr_expr(ops[0].mem)
                a = "R%d(ad)" % bits
                store = "W%d(ad, r);" % bits
                return ["{ u32 ad = %s; %s u32 a = %s; u32 b = %s; u32 r = (%s) & %s; %s %s }" % (ad, pre, a, b, exprs[m], mk, store, fc)]
            return ["{ %s u32 a = %s; u32 b = %s; u32 r = (%s) & %s; %s %s }" % (pre, a, b, exprs[m], mk, store, fc)]
        if m in ("inc", "dec", "neg", "not"):
            bits = ops[0].size * 8
            mk = mask(bits)
            if m == "not":
                if ops[0].type == X86_OP_MEM:
                    ad = self.addr_expr(ops[0].mem)
                    return ["{ u32 ad = %s; W%d(ad, ~R%d(ad)); }" % (ad, bits, bits)]
                return [self.write(ops[0], "~%s" % self.read(ops[0], bits), bits)]
            if m == "neg":
                pre, aa, bb, ex, kind = "", "0u", "x", "a - b", "sub"
            elif m == "inc":
                pre, aa, bb, ex, kind = "", "x", "1u", "a + b", "inc"
            else:
                pre, aa, bb, ex, kind = "", "x", "1u", "a - b", "dec"
            fc = self.flagcode(kind, bits, live)
            if m == "neg" and "C" in live:
                fc += " fC = (b != 0);"
            if ops[0].type == X86_OP_MEM:
                ad = self.addr_expr(ops[0].mem)
                return ["{ u32 ad = %s; u32 x = R%d(ad); u32 a = %s; u32 b = %s; u32 r = (%s) & %s; W%d(ad, r); %s }" % (ad, bits, aa, bb, ex, mk, bits, fc)]
            return ["{ u32 x = %s; u32 a = %s; u32 b = %s; u32 r = (%s) & %s; %s %s }" % (self.read(ops[0], bits), aa, bb, ex, mk, self.write(ops[0], "r", bits), fc)]
        if m in ("shl", "sal", "shr", "sar", "rol", "ror"):
            return self.shift(i, m)
        if m in ("shld", "shrd"):
            return self.dshift(i, m)
        if m in ("mul", "imul", "div", "idiv"):
            return self.muldiv(i, m)
        if m in ("bt", "bts", "btr", "btc") and ops[0].size == 4:
            off = self.read(ops[1], 32) if ops[1].type != X86_OP_IMM else "0x%xu" % (ops[1].imm & 31)
            op = {"bt": "", "bts": "v |= 1u << bit;", "btr": "v &= ~(1u << bit);", "btc": "v ^= 1u << bit;"}[m]
            if ops[0].type == X86_OP_MEM:
                head = "u32 bo = %s; u32 ad = %s + (u32)(((i32)bo >> 5) * 4); u32 bit = bo & 31; u32 v = R32(ad);" % (off, self.addr_expr(ops[0].mem))
                tail = "W32(ad, v);" if op else ""
            else:
                head = "u32 bo = %s; u32 bit = bo & 31; u32 v = %s;" % (off, self.read(ops[0], 32))
                tail = self.write(ops[0], "v", 32) if op else ""
            return ["{ %s fC = (v >> bit) & 1; %s %s }" % (head, op, tail)]
        if m == "pushfd":
            return ["{ u32 v = 0x202u | rt_eflags_extra | (u32)fC | ((u32)fP << 2) | ((u32)fA << 4) | ((u32)fZ << 6) | ((u32)fS << 7) | ((u32)fO << 11); r_esp -= 4; W32(r_esp, v); }"]
        if m == "popfd":
            return ["{ u32 v = R32(r_esp); r_esp += 4; fC = v & 1; fP = (v >> 2) & 1; fA = (v >> 4) & 1; fZ = (v >> 6) & 1; fS = (v >> 7) & 1; fO = (v >> 11) & 1; rt_eflags_extra = v & 0x240000u; }"]
        if m == "cpuid":
            return ["{ u32 a, b, c, d; rt_cpuid(r_eax, r_ecx, &a, &b, &c, &d); r_eax = a; r_ebx = b; r_ecx = c; r_edx = d; }"]
        if m == "rdtsc":
            return ["{ u64 t = rt_rdtsc(); r_eax = (u32)t; r_edx = (u32)(t >> 32); }"]
        if m in ("rcl", "rcr") and ops[0].size == 4:
            cnt = self.read(ops[1], 8) if ops[1].type != X86_OP_IMM else "%du" % (ops[1].imm & 31)
            a = self.read(ops[0], 32)
            if m == "rcr":
                step = "u32 nc = a & 1; a = (a >> 1) | ((u32)fC << 31); fC = nc;"
            else:
                step = "u32 nc = a >> 31; a = (a << 1) | (u32)fC; fC = nc;"
            return ["{ u32 c = (%s) & 31; u32 a = %s; while (c--) { %s } fO = ((a >> 31) ^ (a >> 30)) & 1; %s }" % (cnt, a, step, self.write(ops[0], "a", 32))]
        if self.is_sse(i):
            return self.sse(i)
        if m in ("movsb", "movsw", "movsd", "stosb", "stosw", "stosd", "rep movsb", "rep movsw", "rep movsd",
                 "rep stosb", "rep stosw", "rep stosd", "lodsb", "lodsd", "repne scasb", "repe scasb", "scasb", "xlatb",
                 "repe cmpsb", "repe cmpsd"):
            return self.strop(i, m)
        if m.startswith("f"):
            return self.x87(i, m)
        raise Unsupported(m)

    def shift(self, i, m):
        ops = i.ops
        live = i.live_out
        bits = ops[0].size * 8
        mk = mask(bits)
        sb = bits - 1
        cnt = self.read(ops[1], 8) if ops[1].type != X86_OP_IMM else "%du" % (ops[1].imm & 31)
        a = self.read(ops[0], bits)
        pre = "u32 ad = %s; " % self.addr_expr(ops[0].mem) if ops[0].type == X86_OP_MEM else ""
        if pre:
            a = "R%d(ad)" % bits
            st = "W%d(ad, r);" % bits
        else:
            st = self.write(ops[0], "r", bits)
        F = []

        def add(f, e):
            if f in live:
                F.append("f%s = %s;" % (f, e))
        if m in ("shl", "sal"):
            body = "r = (a << c) & %s;" % mk
            add("C", "(c <= %d) ? ((a >> (%d - c)) & 1) : 0" % (bits, bits))
            add("O", "((r >> %d) & 1) ^ fCx" % sb)
        elif m == "shr":
            body = "r = (c >= %d) ? 0 : (a >> c);" % bits
            add("C", "(c <= %d) ? ((a >> (c - 1)) & 1) : 0" % bits)
            add("O", "(a >> %d) & 1" % sb)
        elif m == "sar":
            body = "r = (u32)((i%d)a >> (c > %d ? %d : c)) & %s;" % (bits, sb, sb, mk)
            add("C", "((i%d)a >> ((c > %d ? %d : c - 1))) & 1" % (bits, sb, sb))
            add("O", "0")
        elif m == "rol":
            body = "{ u32 k = c %% %d; r = k ? (((a << k) | (a >> (%d - k))) & %s) : a; }" % (bits, bits, mk)
            add("C", "r & 1")
            add("O", "((r >> %d) ^ r) & 1" % sb)
        else:
            body = "{ u32 k = c %% %d; r = k ? (((a >> k) | (a << (%d - k))) & %s) : a; }" % (bits, bits, mk)
            add("C", "(r >> %d) & 1" % sb)
            add("O", "((r >> %d) ^ (r >> %d)) & 1" % (sb, sb - 1))
        if m in ("shl", "sal", "shr", "sar"):
            if "Z" in live:
                F.append("fZ = (r == 0);")
            if "S" in live:
                F.append("fS = (r >> %d) & 1;" % sb)
            if "P" in live:
                F.append("fP = !__builtin_parity(r & 0xffu);")
        flags = " ".join(F).replace("fCx", "fC")
        if m in ("shl", "sal"):
            # OF uses the new CF: compute C first, then O (order of F is C then O already)
            pass
        return ["{ %su32 c = (%s) & 31; u32 a = %s; u32 r = a; if (c) { %s %s %s } }" % (pre, cnt, a, body if body.startswith("{") else body, st, flags)]

    def dshift(self, i, m):
        ops = i.ops
        live = i.live_out
        bits = ops[0].size * 8
        if bits != 32:
            raise Unsupported(m)
        cnt = self.read(ops[2], 8) if ops[2].type != X86_OP_IMM else "%du" % (ops[2].imm & 31)
        a = self.read(ops[0], 32)
        b = self.read(ops[1], 32)
        if m == "shld":
            body = "r = (a << c) | (b >> (32 - c)); fC = (a >> (32 - c)) & 1;"
        else:
            body = "r = (a >> c) | (b << (32 - c)); fC = (a >> (c - 1)) & 1;"
        fl = ""
        if "Z" in live:
            fl += " fZ = (r == 0);"
        if "S" in live:
            fl += " fS = r >> 31;"
        if "P" in live:
            fl += " fP = !__builtin_parity(r & 0xffu);"
        if "O" in live:
            fl += " fO = ((r ^ a) >> 31) & 1;"
        return ["{ u32 c = (%s) & 31; u32 a = %s; u32 b = %s; u32 r = a; if (c) { %s %s%s } }" % (cnt, a, b, body, self.write(ops[0], "r", 32), fl)]

    def muldiv(self, i, m):
        ops = i.ops
        if m == "imul" and len(ops) >= 2:
            if len(ops) == 2:
                d, s1, s2 = ops[0], ops[0], ops[1]
            else:
                d, s1, s2 = ops[0], ops[1], ops[2]
            bits = d.size * 8
            if bits != 32:
                a = self.read(s1, bits)
                b = self.read(s2, bits) if s2.type != X86_OP_IMM else "0x%xu" % (s2.imm & 0xFFFF)
                return ["{ i32 t = (i32)(i%d)%s * (i32)(i%d)%s; %s fC = fO = (t != (i32)(i%d)t); }" % (bits, a, bits, b, self.write(d, "(u32)t", bits), bits)]
            a = self.read(s1, 32)
            b = self.read(s2, 32) if s2.type != X86_OP_IMM else "0x%xu" % (s2.imm & 0xFFFFFFFF)
            return ["{ i64 t = (i64)(i32)%s * (i64)(i32)%s; %s fC = fO = (t != (i64)(i32)(u32)t); }" % (a, b, self.write(d, "(u32)t", 32))]
        bits = ops[0].size * 8
        s = self.read(ops[0], bits)
        if bits == 32:
            if m == "mul":
                return ["{ u64 t = (u64)r_eax * %s; r_eax = (u32)t; r_edx = (u32)(t >> 32); fC = fO = (r_edx != 0); }" % s]
            if m == "imul":
                return ["{ i64 t = (i64)(i32)r_eax * (i64)(i32)%s; r_eax = (u32)t; r_edx = (u32)((u64)t >> 32); fC = fO = (t != (i64)(i32)(u32)t); }" % s]
            if m == "div":
                return ["{ u32 d = %s; if (!d) UNSUP(0x%08x, \"divide by zero\"); { u64 n = ((u64)r_edx << 32) | r_eax; u64 q = n / d; if (q >> 32) UNSUP(0x%08x, \"divide overflow\"); r_eax = (u32)q; r_edx = (u32)(n %% d); } }" % (s, i.addr, i.addr)]
            return ["{ i32 d = (i32)%s; if (!d) UNSUP(0x%08x, \"divide by zero\"); { i64 n = (i64)(((u64)r_edx << 32) | r_eax); i64 q = n / d; if (q != (i64)(i32)q) UNSUP(0x%08x, \"divide overflow\"); r_eax = (u32)q; r_edx = (u32)(n %% d); } }" % (s, i.addr, i.addr)]
        if bits == 16:
            if m == "mul":
                return ["{ u32 t = (r_eax & 0xffffu) * %s; r_eax = (r_eax & 0xffff0000u) | (t & 0xffffu); r_edx = (r_edx & 0xffff0000u) | (t >> 16); fC = fO = ((t >> 16) != 0); }" % s]
            if m == "div":
                return ["{ u32 d = %s; if (!d) UNSUP(0x%08x, \"divide by zero\"); { u32 n = ((r_edx & 0xffffu) << 16) | (r_eax & 0xffffu); u32 q = n / d; if (q >> 16) UNSUP(0x%08x, \"divide overflow\"); r_eax = (r_eax & 0xffff0000u) | q; r_edx = (r_edx & 0xffff0000u) | (n %% d); } }" % (s, i.addr, i.addr)]
            if m == "imul":
                return ["{ i32 t = (i32)(i16)r_eax * (i32)(i16)%s; r_eax = (r_eax & 0xffff0000u) | ((u32)t & 0xffffu); r_edx = (r_edx & 0xffff0000u) | (((u32)t >> 16) & 0xffffu); fC = fO = (t != (i32)(i16)t); }" % s]
            if m == "idiv":
                return ["{ i32 d = (i16)%s; if (!d) UNSUP(0x%08x, \"divide by zero\"); { i32 n = (i32)(((r_edx & 0xffffu) << 16) | (r_eax & 0xffffu)); i32 q = n / d; if (q != (i16)q) UNSUP(0x%08x, \"divide overflow\"); r_eax = (r_eax & 0xffff0000u) | ((u32)q & 0xffffu); r_edx = (r_edx & 0xffff0000u) | ((u32)(n %% d) & 0xffffu); } }" % (s, i.addr, i.addr)]
            raise Unsupported(m + "16")
        if bits == 8:
            if m == "imul":
                return ["{ i32 t = (i32)(i8)r_eax * (i32)(i8)%s; r_eax = (r_eax & 0xffff0000u) | ((u32)t & 0xffffu); fC = fO = (t != (i32)(i8)t); }" % s]
            if m == "idiv":
                return ["{ i32 d = (i8)%s; if (!d) UNSUP(0x%08x, \"divide by zero\"); { i32 n = (i16)r_eax; i32 q = n / d; if (q != (i8)q) UNSUP(0x%08x, \"divide overflow\"); r_eax = (r_eax & 0xffff0000u) | (((u32)(n %% d) & 0xffu) << 8) | ((u32)q & 0xffu); } }" % (s, i.addr, i.addr)]
            if m == "mul":
                return ["{ u32 t = (r_eax & 0xffu) * %s; r_eax = (r_eax & 0xffff0000u) | t; fC = fO = ((t >> 8) != 0); }" % s]
            if m == "div":
                return ["{ u32 d = %s; if (!d) UNSUP(0x%08x, \"divide by zero\"); { u32 n = r_eax & 0xffffu; u32 q = n / d; if (q >> 8) UNSUP(0x%08x, \"divide overflow\"); r_eax = (r_eax & 0xffff0000u) | ((n %% d) << 8) | q; } }" % (s, i.addr, i.addr)]
            raise Unsupported(m + "8")
        raise Unsupported(m)

    def strop(self, i, m):
        live = i.live_out
        rep = m.startswith("rep")
        base = m.split()[-1]
        w = {"b": 1, "w": 2, "d": 4}[base[-1]] if base not in ("xlatb",) else 1
        bits = w * 8
        if base.startswith("movs"):
            one = "W%d(r_edi, R%d(r_esi)); r_esi += rt_df ? -%d : %d; r_edi += rt_df ? -%d : %d;" % (bits, bits, w, w, w, w)
            if rep:
                return ["while (r_ecx) { %s r_ecx--; }" % one]
            return [one]
        if base.startswith("stos"):
            val = {1: "(u8)r_eax", 2: "(u16)r_eax", 4: "r_eax"}[w]
            one = "W%d(r_edi, %s); r_edi += rt_df ? -%d : %d;" % (bits, val, w, w)
            if rep:
                return ["while (r_ecx) { %s r_ecx--; }" % one]
            return [one]
        if base == "lodsb":
            return ["r_eax = (r_eax & 0xffffff00u) | R8(r_esi); r_esi += rt_df ? -1 : 1;"]
        if base == "lodsd":
            return ["r_eax = R32(r_esi); r_esi += rt_df ? -4 : 4;"]
        if base == "xlatb":
            return ["r_eax = (r_eax & 0xffffff00u) | R8(r_ebx + (r_eax & 0xffu));"]
        if base == "scasb":
            fl = self.flagcode("sub", 8, live)
            step = "{ u32 a = r_eax & 0xffu; u32 b = R8(r_edi); u32 r = (a - b) & 0xffu; r_edi += rt_df ? -1 : 1; %s }" % fl
            if m.startswith("repne"):
                return ["while (r_ecx) { %s r_ecx--; if (fZ) break; }" % step.replace("{ u32 a", "{ u32 a", 1) if "Z" in live else
                        "while (r_ecx) { u32 a = r_eax & 0xffu; u32 b = R8(r_edi); r_edi += rt_df ? -1 : 1; r_ecx--; if (a == b) break; }"]
            return [step]
        raise Unsupported(m)

    # ---- x87 ----
    def x87(self, i, m):
        ops = i.ops
        live = i.live_out

        def isreg(o):
            return o.type == X86_OP_REG and self.rname(o.reg).startswith("st")

        def stn(o):
            n = self.rname(o.reg)
            return 0 if n == "st" else int(re.sub(r"[^0-9]", "", n))

        def mem(o):
            return o.type == X86_OP_MEM

        if m in ("fld", "fst", "fstp") and ops:
            o = ops[0]
            if mem(o):
                ad = self.addr_expr(o.mem)
                sz = o.size
                if m == "fld":
                    rd = {4: "R_F32(%s)", 8: "R_F64(%s)", 10: "R_F80(%s)"}[sz] % ad
                    return ["FPUSH(%s);" % rd]
                wr = {4: "W_F32(%s, ST(0));", 8: "W_F64(%s, ST(0));", 10: "W_F80(%s, ST(0));"}[sz] % ad
                return [wr + (" FPOP();" if m == "fstp" else "")]
            n = stn(o)
            if m == "fld":
                return ["{ long double v = ST(%d); FPUSH(v); }" % n]
            return ["ST(%d) = ST(0);%s" % (n, " FPOP();" if m == "fstp" else "")]
        if m == "fild":
            ad = self.addr_expr(ops[0].mem)
            t = {2: "i16", 4: "i32", 8: "i64"}[ops[0].size]
            return ["FPUSH((long double)(%s)R%d(%s));" % (t, ops[0].size * 8, ad)]
        if m in ("fist", "fistp"):
            ad = self.addr_expr(ops[0].mem)
            n = ops[0].size
            return ["W%d(%s, (u%d)fx_int%d(ST(0)));%s" % (n * 8, ad, n * 8, n * 8, " FPOP();" if m == "fistp" else "")]
        consts = {"fldz": "0.0", "fld1": "1.0", "fldpi": "3.14159265358979323846", "fldln2": "0.69314718055994530942",
                  "fldlg2": "0.30102999566398119521", "fldl2e": "1.44269504088896340736", "fldl2t": "3.32192809488736234787",
                  "fldln2": "0.69314718055994530942"}
        if m in consts:
            return ["FPUSH(%s);" % consts[m]]
        if m == "fxch":
            n = stn(ops[-1]) if ops else 1
            return ["{ long double t = ST(0); ST(0) = ST(%d); ST(%d) = t; }" % (n, n)]
        if m == "fchs":
            return ["ST(0) = -ST(0);"]
        if m == "fabs":
            return ["ST(0) = fabsl(ST(0));"]
        if m == "fsqrt":
            return ["ST(0) = sqrtl(ST(0));"]
        if m == "frndint":
            return ["ST(0) = fx_rint(ST(0));"]
        arith = {"fadd": "+", "fsub": "-", "fsubr": "r-", "fmul": "*", "fdiv": "/", "fdivr": "r/",
                 "faddp": "+", "fsubp": "-", "fsubrp": "r-", "fmulp": "*", "fdivp": "/", "fdivrp": "r/",
                 "fiadd": "+", "fisub": "-", "fisubr": "r-", "fimul": "*", "fidiv": "/", "fidivr": "r/"}
        if m in arith:
            op = arith[m]
            pop = m.endswith("p") and m not in ("fiadd",)
            rev = op.startswith("r")
            o = op[-1]

            def comb(dst, src):
                return ("%s = %s %s %s;" % (dst, src, o, dst)) if rev else ("%s = %s %s %s;" % (dst, dst, o, src))
            if m.startswith("fi"):
                ad = self.addr_expr(ops[0].mem)
                t = {2: "i16", 4: "i32"}[ops[0].size]
                return [comb("ST(0)", "(long double)(%s)R%d(%s)" % (t, ops[0].size * 8, ad))]
            if ops and mem(ops[0]):
                ad = self.addr_expr(ops[0].mem)
                v = "R_F32(%s)" % ad if ops[0].size == 4 else "R_F64(%s)" % ad
                return [comb("ST(0)", v)]
            if len(ops) == 2:
                d, s = stn(ops[0]), stn(ops[1])
            elif len(ops) == 1:
                d, s = (stn(ops[0]), 0) if pop else (0, stn(ops[0]))
            else:
                d, s = 1, 0
            return [comb("ST(%d)" % d, "ST(%d)" % s) + (" FPOP();" if pop else "")]
        if m in ("fcom", "fcomp", "fcompp", "fucom", "fucomp", "fucompp", "ficom", "ficomp", "ftst"):
            if m == "ftst":
                other = "0.0"
            elif m in ("fcompp", "fucompp"):
                other = "ST(1)"
            elif m.startswith("fi"):
                other = "(long double)(%s)R%d(%s)" % ({2: "i16", 4: "i32"}[ops[0].size], ops[0].size * 8, self.addr_expr(ops[0].mem))
            elif ops and mem(ops[0]):
                other = ("R_F32(%s)" if ops[0].size == 4 else "R_F64(%s)") % self.addr_expr(ops[0].mem)
            elif ops:
                other = "ST(%d)" % stn(ops[0])
            else:
                other = "ST(1)"
            pops = "FPOP(); FPOP();" if m.endswith("pp") else ("FPOP();" if m.endswith("p") else "")
            return ["fx_compare(ST(0), %s); %s" % (other, pops)]
        if m == "fnstsw":
            if ops and ops[0].type == X86_OP_REG:
                return ["r_eax = (r_eax & 0xffff0000u) | fx_sw();"]
            return ["W16(%s, fx_sw());" % self.addr_expr(ops[0].mem)]
        if m == "fnstcw":
            return ["W16(%s, fcw);" % self.addr_expr(ops[0].mem)]
        if m == "fldcw":
            return ["fcw = R16(%s);" % self.addr_expr(ops[0].mem)]
        if m == "fprem" or m == "fprem1":
            return ["ST(0) = fmodl(ST(0), ST(1)); fsw &= ~0x400;"]
        if m == "fscale":
            return ["ST(0) = ldexpl(ST(0), (int)ST(1));"]
        if m == "fsin":
            return ["ST(0) = sinl(ST(0));"]
        if m == "fcos":
            return ["ST(0) = cosl(ST(0));"]
        if m == "fyl2x":
            return ["ST(1) = ST(1) * log2l(ST(0)); FPOP();"]
        if m == "fpatan":
            return ["ST(1) = atan2l(ST(1), ST(0)); FPOP();"]
        if m == "f2xm1":
            return ["ST(0) = exp2l(ST(0)) - 1.0;"]
        if m == "fptan":
            return ["ST(0) = tanl(ST(0)); FPUSH(1.0);"]
        if m == "ffree":
            return [";"]
        raise Unsupported(m)

    # ---- SSE / SSE2 (the subset the image uses) ----
    SSE_MN = {
        "movapd", "movaps", "movupd", "movups", "movdqa", "movdqu", "movsd", "movlpd", "movhpd", "movd", "movq",
        "addsd", "subsd", "mulsd", "divsd", "minsd", "maxsd", "sqrtsd", "addpd", "subpd", "mulpd", "divpd",
        "andpd", "andnpd", "orpd", "xorpd", "pand", "pandn", "por", "pxor", "unpcklpd", "unpckhpd", "shufpd",
        "pshufd", "pcmpeqd", "psubd", "paddd", "paddq", "psubq", "pmaxsw", "pextrw", "pinsrw", "pmovmskb",
        "psrlq", "psllq", "comisd", "ucomisd", "cvtsi2sd", "cvtsd2si", "cvttsd2si", "cvtdq2pd", "stmxcsr", "ldmxcsr",
    }
    CMP_PRED = {"eq": "a == b", "lt": "a < b", "le": "a <= b", "unord": "(a != a || b != b)", "neq": "!(a == b)",
                "nlt": "!(a < b)", "nle": "!(a <= b)", "ord": "(a == a && b == b)"}

    def isx(self, o):
        return o.type == X86_OP_REG and self.rname(o.reg).startswith("xmm")

    def xi(self, o):
        return int(self.rname(o.reg)[3:])

    def is_sse(self, i):
        m = i.mn
        if m.startswith("cmp") and len(m) > 5 and m[-2:] in ("sd", "pd") and m[3:-2] in self.CMP_PRED:
            return True
        if m in self.SSE_MN:
            return any(self.isx(o) for o in i.ops) or m in ("stmxcsr", "ldmxcsr", "cvtsd2si", "cvttsd2si", "cvtsi2sd")
        return False

    def sse(self, i):
        m = i.mn
        ops = i.ops

        def X(o):
            return "xmm[%d]" % self.xi(o)

        def load_s(o, nbytes):
            if self.isx(o):
                return "XMM s = %s;" % X(o)
            a = self.addr_expr(o.mem)
            if nbytes == 16:
                return "XMM s; memcpy(&s, (void *)(uintptr_t)%s, 16);" % a
            if nbytes == 8:
                return "XMM s; s.q[0] = R64(%s); s.q[1] = 0;" % a
            return "XMM s; s.q[0] = 0; s.q[1] = 0; s.d[0] = R32(%s);" % a

        d = ops[0]
        if m in ("movapd", "movaps", "movupd", "movups", "movdqa", "movdqu"):
            if self.isx(d):
                return ["{ %s %s = s; }" % (load_s(ops[1], 16), X(d))]
            return ["memcpy((void *)(uintptr_t)%s, &%s, 16);" % (self.addr_expr(d.mem), X(ops[1]))]
        if m == "movsd":
            if self.isx(d) and self.isx(ops[1]):
                return ["%s.q[0] = %s.q[0];" % (X(d), X(ops[1]))]
            if self.isx(d):
                return ["{ %s.q[0] = R64(%s); %s.q[1] = 0; }" % (X(d), self.addr_expr(ops[1].mem), X(d))]
            return ["W64(%s, %s.q[0]);" % (self.addr_expr(d.mem), X(ops[1]))]
        if m in ("movlpd", "movhpd"):
            lane = 0 if m == "movlpd" else 1
            if self.isx(d):
                return ["%s.q[%d] = R64(%s);" % (X(d), lane, self.addr_expr(ops[1].mem))]
            return ["W64(%s, %s.q[%d]);" % (self.addr_expr(d.mem), X(ops[1]), lane)]
        if m == "movd":
            if self.isx(d):
                src = self.read(ops[1], 32)
                return ["{ u32 v = %s; %s.d[0] = v; %s.d[1] = 0; %s.q[1] = 0; }" % (src, X(d), X(d), X(d))]
            return [self.write(d, "%s.d[0]" % X(ops[1]), 32)]
        if m == "movq":
            if self.isx(d):
                return ["{ %s %s.q[0] = s.q[0]; %s.q[1] = 0; }" % (load_s(ops[1], 8), X(d), X(d))]
            return ["W64(%s, %s.q[0]);" % (self.addr_expr(d.mem), X(ops[1]))]
        sc = {"addsd": "+", "subsd": "-", "mulsd": "*", "divsd": "/"}
        if m in sc:
            return ["{ %s %s.f[0] = %s.f[0] %s s.f[0]; }" % (load_s(ops[1], 8), X(d), X(d), sc[m])]
        if m in ("minsd", "maxsd"):
            op = "<" if m == "minsd" else ">"
            return ["{ %s %s.f[0] = (%s.f[0] %s s.f[0]) ? %s.f[0] : s.f[0]; }" % (load_s(ops[1], 8), X(d), X(d), op, X(d))]
        if m == "sqrtsd":
            return ["{ %s %s.f[0] = sqrt(s.f[0]); }" % (load_s(ops[1], 8), X(d))]
        pc = {"addpd": "+", "subpd": "-", "mulpd": "*", "divpd": "/"}
        if m in pc:
            return ["{ %s %s.f[0] = %s.f[0] %s s.f[0]; %s.f[1] = %s.f[1] %s s.f[1]; }" % (load_s(ops[1], 16), X(d), X(d), pc[m], X(d), X(d), pc[m])]
        lg = {"andpd": "{D} & {S}", "orpd": "{D} | {S}", "xorpd": "{D} ^ {S}", "andnpd": "~{D} & {S}",
              "pand": "{D} & {S}", "por": "{D} | {S}", "pxor": "{D} ^ {S}", "pandn": "~{D} & {S}"}
        if m in lg:
            e0 = lg[m].format(D=X(d) + ".q[0]", S="s.q[0]")
            e1 = lg[m].format(D=X(d) + ".q[1]", S="s.q[1]")
            return ["{ %s %s.q[0] = %s; %s.q[1] = %s; }" % (load_s(ops[1], 16), X(d), e0, X(d), e1)]
        if m == "unpcklpd":
            return ["{ %s %s.f[1] = s.f[0]; }" % (load_s(ops[1], 16), X(d))]
        if m == "unpckhpd":
            return ["{ %s %s.f[0] = %s.f[1]; %s.f[1] = s.f[1]; }" % (load_s(ops[1], 16), X(d), X(d), X(d))]
        if m == "shufpd":
            imm = ops[2].imm
            return ["{ %s double lo = %s.f[%d]; double hi = s.f[%d]; %s.f[0] = lo; %s.f[1] = hi; }" % (load_s(ops[1], 16), X(d), imm & 1, (imm >> 1) & 1, X(d), X(d))]
        if m == "pshufd":
            imm = ops[2].imm
            return ["{ %s XMM r; r.d[0] = s.d[%d]; r.d[1] = s.d[%d]; r.d[2] = s.d[%d]; r.d[3] = s.d[%d]; %s = r; }" % (
                load_s(ops[1], 16), imm & 3, (imm >> 2) & 3, (imm >> 4) & 3, (imm >> 6) & 3, X(d))]
        lane32 = {"pcmpeqd": "(%s.d[{k}] == s.d[{k}]) ? 0xffffffffu : 0", "psubd": "%s.d[{k}] - s.d[{k}]", "paddd": "%s.d[{k}] + s.d[{k}]"}
        if m in lane32:
            body = " ".join(("%s.d[%d] = " % (X(d), k)) + (lane32[m].replace("{k}", str(k)) % X(d)) + ";" for k in range(4))
            return ["{ %s %s }" % (load_s(ops[1], 16), body)]
        if m in ("paddq", "psubq"):
            op = "+" if m == "paddq" else "-"
            return ["{ %s %s.q[0] %s= s.q[0]; %s.q[1] %s= s.q[1]; }" % (load_s(ops[1], 16), X(d), op, X(d), op)]
        if m == "pmaxsw":
            body = " ".join("if ((i16)s.w[%d] > (i16)%s.w[%d]) %s.w[%d] = s.w[%d];" % (k, X(d), k, X(d), k, k) for k in range(8))
            return ["{ %s %s }" % (load_s(ops[1], 16), body)]
        if m == "pextrw":
            return [self.write(d, "(u32)%s.w[%d]" % (X(ops[1]), ops[2].imm & 7), 32)]
        if m == "pinsrw":
            if ops[1].type == X86_OP_MEM:
                src = "R16(%s)" % self.addr_expr(ops[1].mem)
            else:
                src = "r_" + regparts(self.rname(ops[1].reg))[0]
            return ["%s.w[%d] = (u16)(%s);" % (X(d), ops[2].imm & 7, src)]
        if m == "pmovmskb":
            bits = " | ".join("((u32)(%s.b[%d] >> 7) << %d)" % (X(ops[1]), k, k) for k in range(16))
            return [self.write(d, bits, 32)]
        if m in ("psrlq", "psllq"):
            if ops[1].type == X86_OP_IMM:
                cnt = "%du" % ops[1].imm
                pre = ""
            else:
                pre = load_s(ops[1], 16)
                cnt = "(u32)(s.q[0] > 64 ? 64 : s.q[0])"          # only the low 64 bits of the count operand are used
            op = ">>" if m == "psrlq" else "<<"
            sh = "{ u32 c = %s; %s.q[0] = c > 63 ? 0 : %s.q[0] %s c; %s.q[1] = c > 63 ? 0 : %s.q[1] %s c; }" % (cnt, X(d), X(d), op, X(d), X(d), op)
            return ["{ %s %s }" % (pre, sh)]
        if m in ("comisd", "ucomisd"):
            return ["{ %s double a = %s.f[0]; double b = s.f[0]; fO = 0; fS = 0; fA = 0; "
                    "if (a != a || b != b) { fZ = 1; fP = 1; fC = 1; } else if (a > b) { fZ = 0; fP = 0; fC = 0; } "
                    "else if (a < b) { fZ = 0; fP = 0; fC = 1; } else { fZ = 1; fP = 0; fC = 0; } }" % (load_s(ops[1], 8), X(d))]
        if m == "cvtsi2sd":
            return ["%s.f[0] = (double)(i32)(%s);" % (X(d), self.read(ops[1], 32))]
        if m in ("cvtsd2si", "cvttsd2si"):
            rnd = "fx_rint_mx(v)" if m == "cvtsd2si" else "trunc(v)"
            return ["{ %s double v = s.f[0]; double r = %s; %s }" % (load_s(ops[1], 8), rnd,
                    self.write(d, "(r >= -2147483648.0 && r < 2147483648.0) ? (u32)(i32)r : 0x80000000u", 32))]
        if m == "cvtdq2pd":
            return ["{ %s %s.f[0] = (double)(i32)s.d[0]; %s.f[1] = (double)(i32)s.d[1]; }" % (load_s(ops[1], 8), X(d), X(d))]
        if m == "stmxcsr":
            return ["W32(%s, mxcsr);" % self.addr_expr(d.mem)]
        if m == "ldmxcsr":
            return ["mxcsr = R32(%s);" % self.addr_expr(d.mem)]
        if m.startswith("cmp"):
            pred, kind = m[3:-2], m[-2:]
            cond = self.CMP_PRED[pred]
            if kind == "sd":
                return ["{ %s double a = %s.f[0]; double b = s.f[0]; %s.q[0] = (%s) ? ~0ull : 0ull; }" % (load_s(ops[1], 8), X(d), X(d), cond)]
            return ["{ %s double a = %s.f[0]; double b = s.f[0]; %s.q[0] = (%s) ? ~0ull : 0ull; a = %s.f[1]; b = s.f[1]; %s.q[1] = (%s) ? ~0ull : 0ull; }" % (
                load_s(ops[1], 16), X(d), X(d), cond, X(d), X(d), cond)]
        raise Unsupported(m)
