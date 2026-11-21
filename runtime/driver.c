/* driver.c: differential-test driver. usage: driver <exe> <tests.txt>
 * test line: addr eax ecx edx ebx esi edi ebp seed nargs a0 a1 ...   (all hex, seed hex)
 * output per test: "OK eax ecx edx ebx esi edi ebp esp crc" or "UNSUP addr msg" or "CRASH addr" */
#include "rt.h"
#include "project.h"
#include "sys.h"
#if defined(_WIN32)
#include <windows.h>
#include <float.h>
#else
#include <signal.h>
#include <unistd.h>
#if defined(__linux__) && defined(__i386__)
#include <fpu_control.h>
#endif
#endif
#include <setjmp.h>

extern jmp_buf rt_unsup_jmp;
extern const char *rt_unsup_msg;
extern u32 rt_unsup_addr;
extern int rt_unsup_armed;
int rt_load_image(const char *path);

#define DATA_LO SS_CODE_LO
#define DATA_HI SS_CODE_HI
#define STK_BASE 0x0A000000u
#define STK_SIZE 0x100000u
#define STK_TOP  0x0A0F0000u
#define HEAP 0x03000000u
#define HEAP_SIZE 0x10000u
#define SENT 0xDEAD0000u
#ifdef CALLTEST
static u32 ct_mode;
#define STRUCT_HEAP_ON (ct_mode != 0)       /* heap mode 0: random words, 1: linked objects, 2 and 3: mostly pointers */
#else
#define STRUCT_HEAP_ON (getenv("STRUCT_HEAP") != NULL)
#endif

static unsigned char *pristine;
static u32 crc_tab[256];

static void crc_init(void)
{
    for (u32 i = 0; i < 256; ++i) {
        u32 c = i;
        for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        crc_tab[i] = c;
    }
}
static u32 crc(u32 c, const unsigned char *p, size_t n)
{
    c = ~c;
    while (n--) c = crc_tab[(c ^ *p++) & 0xFF] ^ (c >> 8);
    return ~c;
}

#ifdef CALLTEST
/* Call-trace mode (scripts/calltest.py, build target `calltest`): the function under test is the real code, every other function
 * of the program is a logging stub (ct_stub).  A stub records the call (callee, the registers the callee reads, the first stack
 * arguments), sets eax/ecx/edx to values derived from the callee, the test seed and the number of calls so far (calltest.py
 * derives the same values on the Unicorn side), and returns the way the callee would: it removes its return address and
 * arguments.  The records are printed before the result line as "T <record>". */
typedef struct { u32 addr; u16 retn; u8 nargs, regs; i8 xd; u8 xin; } CtInfo;     /* regs: bit 0 eax, 1 ecx, 2 edx, 3 ebx, 4 esi, 5 edi are read by the callee; bit 6: ecx is read on some paths.
                                                                                  * xd: how many values the callee leaves on (+) or takes off (-) the x87 stack, xin: how many of the caller's x87 values it reads */
extern const CtInfo ct_info[];
extern const unsigned ct_info_count;
/* The imports (calls through an import table slot, or through a data word that holds an OpenGL entry point): the slot holds 0xFE000000 + index
 * in this build, so a call lands in api_dispatch(), which logs it by name and removes its stdcall arguments.  kind: 0 import table, 1 OpenGL 1.x
 * entry point, 2 OpenGL extension (the slot stays empty in some cases, as when the driver does not offer it). */
typedef struct { u32 slot; u8 nargs, kind; } CtImport;
extern const CtImport ct_imports[];
extern const char *const ct_import_names[];
extern const unsigned ct_import_count;
void ct_call_target(u32 addr);                                 /* generated: calls the real function under test */
#define CT_MAXCALLS 400
static u32 ct_cur, ct_seed, ct_n;
static u32 ct_seq_addr[8], ct_seq_cnt[8];
static int ct_seq_used;
static u32 ct_stack_hi = 0xFFFFFFFFu;     /* main's frame: every local of a rewrite lies below it */
static char ct_log[CT_MAXCALLS][768];

/* CT_WRITE has two forms in one variable: <callee>:<ecx|a<i>>+<offset>=<value> (the first block below) and <callee>:<address>=<value> (the second);
 * an entry belongs to the first when a '+' stands between its ':' and its '='.  Each block skips the entries of the other. */
static int ct_write_regform(const char *p)
{
    const char *colon = strchr(p, ':'), *eq = strchr(p, '='), *comma = strchr(p, ',');
    if (!colon || !eq || (comma && comma < colon)) return 0;
    for (const char *q = colon; q < eq; ++q) if (*q == '+') return 1;
    return 0;
}
static const char *ct_write_next(const char *p) { const char *c = strchr(p, ','); return c ? c + 1 : p + strlen(p); }

static u32 ct_mix(u32 x)
{
    x ^= x >> 16; x *= 0x7feb352du; x ^= x >> 15; x *= 0x846ca68bu; x ^= x >> 16;
    return x;
}
static u32 ct_seqaddr[32];           /* CT_SEQ: the callees that have been called in this case and how often */
static unsigned ct_seqcount[32], ct_seqn;
static unsigned ct_seq_next(u32 addr)
{
    unsigned i;
    for (i = 0; i < ct_seqn; ++i)
        if (ct_seqaddr[i] == addr) return ct_seqcount[i]++;
    if (ct_seqn < 32) { ct_seqaddr[ct_seqn] = addr; ct_seqcount[ct_seqn] = 1; ++ct_seqn; }
    return 0;
}
static u32 ct_policy;                /* the test line's stub policy: 0, or 1 for more kinds of numbers (-1, large values) */
static u32 ct_value(u32 h)           /* what a stub returns: 0, a small number or a pointer into the test heap */
{
    if (ct_policy == 1) {
        static const u32 wide[8] = { 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x10000, 0x80000000u };
        switch (h & 7) {
        case 0: return 0;
        case 1: return 0xFFFFFFFFu;
        case 2: return 1 + ((h >> 8) & 7);
        case 3: return wide[(h >> 8) & 7];
        default: return HEAP + ((h >> 8) % (HEAP_SIZE / 4 - 64)) * 4;
        }
    }
    switch (h & 7) {
    case 0: case 1: return 0;
    case 2: return 1 + ((h >> 8) & 7);
    default: return HEAP + ((h >> 8) % (HEAP_SIZE / 4 - 64)) * 4;
    }
}
static double ct_fvalue(u32 h)       /* what a stub pushes on the x87 stack: 0, or a multiple of 1/8 up to +-250 (now and then 1000 times that) */
{
    double v = (double)((int)((h >> 8) % 4001) - 2000) / 8.0;
    if ((h & 7) < 2) v = 0.0;
    else if (((h >> 20) & 15) == 0) v *= 1000.0;
    return v;
}
static int ct_depth(void) { return (-ftop) & 7; }
static void ct_fbits(char *o, long double v)     /* a value of the x87 stack, as the bits of the double it rounds to (nan and inf by name: the payload is no matter) */
{
    double d = (double)v;
    if (d != d) strcpy(o, "nan");
    else { u64 b; memcpy(&b, &d, 8); sprintf(o, "%016llx", (unsigned long long)b); }
}
static void ct_word(char *o, u32 v)  /* a value in a record: stack addresses (the guest stack, or the host stack for a local of a rewrite) differ between a rewrite and the original, so they are written as S */
{
    u32 here = (u32)(uintptr_t)&o;
    /* a local of the rewrite lies between this frame and main's frame (4 KB of slack below): on Linux the host stack is at the top of the
     * address space, where small negative numbers (0xFFFFFFC8), or a random word like 0xFF8009EC, would otherwise count as stack addresses */
    if ((v >= STK_BASE && v < STK_TOP + 0x1000) || (v < ct_stack_hi && v >= here - 0x1000u)) strcpy(o, "S");
    else sprintf(o, "%x", v);
}
static u32 ct_obj_callee;   /* the callee whose arguments are being recorded */
static int ct_stackobj_callee(void)  /* CT_STACKOBJ_ONLY=<hex callee>,...: the stack objects of these callees only */
{
    char *p = getenv("CT_STACKOBJ_ONLY");
    while (p && *p) {
        unsigned long a = strtoul(p, &p, 16);
        if (a == ct_obj_callee) return 1;
        if (*p == 0x2c) ++p;
    }
    return !getenv("CT_STACKOBJ_ONLY");
}
static void ct_obj(char *o, u32 v)   /* a pointer into the heap or the data: the CRC of 64 bytes of the object */
{
    ct_word(o, v);
    if (getenv("CT_STACKOBJ") && v >= STK_BASE && v < STK_TOP + 0x1000 - 64 && ct_stackobj_callee()) sprintf(o + strlen(o), "/%08x", crc(0, (unsigned char *)v, atoi(getenv("CT_STACKOBJ"))));
    if ((v >= HEAP && v < HEAP + HEAP_SIZE - 64) || (v >= DATA_LO && v < DATA_HI - 64)) sprintf(o + strlen(o), "/%08x", crc(0, (unsigned char *)v, 64));
}
static const CtInfo *ct_find(u32 addr)
{
    unsigned lo = 0, hi = ct_info_count;
    while (lo < hi) {
        unsigned m = (lo + hi) / 2;
        if (ct_info[m].addr < addr) lo = m + 1; else hi = m;
    }
    return lo < ct_info_count && ct_info[lo].addr == addr ? &ct_info[lo] : NULL;
}
static void ct_x87_in(char **o, unsigned n)      /* the caller's x87 values a callee reads (a float argument in st(0)): depth and the top n values */
{
    char w[40];
    int depth = ct_depth();
    *o += sprintf(*o, " fp%d:", depth);
    for (int i = 0; i < (int)n && i < depth; ++i) { ct_fbits(w, ST(i)); *o += sprintf(*o, "%s%s", i ? "," : "", w); }
}
static int ct_fseq(u32 addr, double *out)        /* CT_FSEQ=<callee>=<d1>:<d2>:...,...: the k-th call of the callee pushes the double d_k (the last value stays) */
{
    char *p = getenv("CT_FSEQ");
    while (p && *p) {
        unsigned long a = strtoul(p, &p, 16);
        double vals[16];
        int nv = 0;
        if (*p != '=') break;
        ++p;
        for (;;) { vals[nv++] = strtod(p, &p); if (*p == ':' && nv < 16) ++p; else break; }
        if (a == addr) { unsigned k = ct_seq_next(addr | 0x80000000u); *out = vals[k < (unsigned)nv ? k : (unsigned)nv - 1]; return 1; }
        if (*p == ',') ++p;
    }
    return 0;
}
static void ct_x87_out(int xd, u32 h, u32 addr)  /* what the callee does to the x87 stack: it pushes values (a getter that returns a double) or pops its argument */
{
    int first = 1;
    for (; xd > 0; --xd) {
        double v = ct_fvalue(ct_mix(h + 3 + xd));
        if (first && ct_fseq(addr, &v)) first = 0;
        FPUSH((long double)v);
    }
    for (; xd < 0; ++xd) FPOP();
}
void ct_stub(u32 addr)
{
    if (addr == ct_cur) { ct_call_target(addr); return; }      /* the function calling itself runs as real code on both sides */
    const CtInfo *ci = ct_find(addr);
    if (!ci) rt_unsup(addr, "call trace: no information about this function");
    if (ct_n >= CT_MAXCALLS) rt_unsup(addr, "call trace: too many calls");
    char *o = ct_log[ct_n], w[48];
    ct_obj_callee = addr;
    o += sprintf(o, "%08x", addr);
    static const char *rn[6] = { "eax", "ecx", "edx", "ebx", "esi", "edi" };
    u32 rv[6] = { r_eax, r_ecx, r_edx, r_ebx, r_esi, r_edi };
    for (int i = 0; i < 6; ++i)
        if (ci->regs >> i & 1) { ct_obj(w, rv[i]); o += sprintf(o, " %s=%s", rn[i], w); }
        else if (i == 1 && (ci->regs & 0x40)) { ct_obj(w, rv[i]); o += sprintf(o, " ~%s=%s", rn[i], w); }   /* ecx read on some paths only */
    if (ci->xin) ct_x87_in(&o, ci->xin);
    o += sprintf(o, " |");
    for (unsigned i = 0; i < ci->nargs && i < 20; ++i) { ct_obj(w, R32(r_esp + 4 + 4 * i)); o += sprintf(o, " %s", w); }
    u32 h = ct_mix(addr * 0x9E3779B1u ^ ct_mix(ct_seed * 0x85EBCA6Bu + ct_n));
    ++ct_n;
    u32 ecx_in = r_ecx;
    if (!(getenv("CT_KEEP") && strtoul(getenv("CT_KEEP"), 0, 16) == addr)) {      /* CT_KEEP=<callee> (hex): the stub of that callee leaves eax, ecx and edx as the call found them (the stack cookie check preserves them) */
        r_eax = ct_value(h); r_ecx = ct_value(ct_mix(h + 1)); r_edx = ct_value(ct_mix(h + 2));
        if (getenv("CT_KEEPECX")) {      /* CT_KEEPECX=<callee>,...: the stub leaves ecx as the call made it (see calltest.py) */
            char *p = getenv("CT_KEEPECX");
            while (*p) { unsigned long a = strtoul(p, &p, 16); if (a == addr) r_ecx = ecx_in; if (*p == ',') ++p; else break; }
        }
    }
    if (getenv("CT_WRITE")) {        /* CT_WRITE=<callee>:<ecx|a<i>>+<offset>=<value|h<heap offset>|@<j>>,...: this stub also stores a dword where the real callee would have written (see calltest.py) */
        char *p = getenv("CT_WRITE");
        while (*p) {
            if (!ct_write_regform(p)) { p = (char *)ct_write_next(p); continue; }       /* an entry of the other form */
            unsigned long a = strtoul(p, &p, 16), o, v;
            int arg = -1;
            if (*p != ':') break;
            ++p;
            if (p[0] == 'a') { arg = atoi(p + 1); while (*p && *p != '+') ++p; } else p += 3;
            if (*p != '+') break;
            o = strtoul(p + 1, &p, 16);
            if (*p != '=') break;
            ++p;
            {
                unsigned k = 0, idx = 0;       /* <v1>/<v2>/...: the value for the n-th call of the callee (the last one for later calls) */
                for (u32 i = 0; i + 1 < ct_n; ++i) if (strtoul(ct_log[i], NULL, 16) == addr) ++idx;
                for (;;) {
                    unsigned long t;
                    if (*p == '@') { t = R32(r_esp + 4 + 4 * strtoul(p + 1, &p, 10)); }
                    else if (*p == 'h') t = HEAP + strtoul(p + 1, &p, 16); else t = strtoul(p, &p, 16);
                    if (k <= idx) v = t;
                    ++k;
                    if (*p == '/') ++p; else break;
                }
            }
            if (a == addr) {
                u32 at = (arg < 0 ? ecx_in : R32(r_esp + 4 + 4 * arg)) + (u32)o;
                if ((at >= HEAP && at < HEAP + HEAP_SIZE - 3) || (at >= STK_BASE && at < STK_TOP + 0x1000 - 3)) W32(at, (u32)v);
            }
            if (*p == ',') ++p;
        }
    }
    if (getenv("CT_POKE")) {            /* CT_POKE=<callee>=c<off>:<value> or <callee>=a<n>.<off>:<value>, ...: a stub that writes a dword at ecx + off or at stack argument n + off */
        char *p = getenv("CT_POKE");
        while (*p) {
            unsigned long a = strtoul(p, &p, 16);
            u32 base, off, v = 0;
            if (*p != '=') break;
            ++p;
            if (*p++ == 'c') { base = ecx_in; off = (u32)strtoul(p, &p, 16); }
            else { unsigned n = (unsigned)strtoul(p, &p, 16); if (*p == '.') ++p; off = (u32)strtoul(p, &p, 16); base = R32(r_esp + 4 + 4 * n); }
            if (*p == ':') v = (u32)strtoul(p + 1, &p, 16);
            if (a == addr) W32(base + off, v);
            if (*p == ',') ++p;
        }
    }
    if (getenv("CT_RET")) {
        char *p = getenv("CT_RET");
        while (*p) {
            unsigned long a = strtoul(p, &p, 16);
            u32 v = 0;
            unsigned k = 0, idx = 0;
            if (*p != '=') break;
            ++p;
            for (u32 i = 0; i + 1 < ct_n; ++i) if (strtoul(ct_log[i], NULL, 16) == addr) ++idx;      /* CT_RET=<callee>=<v1>/<v2>/...: the value of the n-th call of that callee (the last one for later calls); `ecx` is the callee's ecx */
            for (;;) {
                u32 t;
                if (p[0] == 'e' && p[1] == 'c' && p[2] == 'x') { t = ecx_in; p += 3; } else if (p[0] == '@') { t = R32(r_esp + 4 + 4 * strtoul(p + 1, &p, 10)); } else t = (u32)strtoul(p, &p, 16);
                if (k <= idx) v = t;
                ++k;
                if (*p == '/') ++p; else break;
            }
            if (a == addr) r_eax = v;
            if (*p == ',') ++p;
        }
    }
    if (getenv("CT_RETSEQ")) {                              /* CT_RETSEQ=<callee>=v1:v2:...,...: the n-th call of <callee> in a test case (cycling) returns the n-th value in eax */
        char *p = getenv("CT_RETSEQ");
        while (*p) {
            unsigned long a = strtoul(p, &p, 16), vals[64];
            int nv = 0;
            if (*p != '=') break;
            ++p;
            for (;;) { vals[nv++] = strtoul(p, &p, 16); if (*p == ':' && nv < 64) ++p; else break; }
            if (a == addr) {
                int k = 0;
                while (k < ct_seq_used && ct_seq_addr[k] != addr) ++k;
                if (k == ct_seq_used && k < 8) { ct_seq_addr[k] = addr; ct_seq_cnt[k] = 0; ++ct_seq_used; }
                if (k < 8) r_eax = (u32)vals[ct_seq_cnt[k]++ % nv];
            }
            if (*p == ',') ++p;
        }
    }
    if (getenv("CT_WRITE")) {                               /* CT_WRITE=<callee>:<address>=<value>,...: the stub of <callee> stores the dword (what a real callee does to memory) */
        char *p = getenv("CT_WRITE");
        while (*p) {
            if (ct_write_regform(p)) { p = (char *)ct_write_next(p); continue; }          /* an entry of the other form */
            unsigned long a = strtoul(p, &p, 16), m, v;
            if (*p == ':') m = strtoul(p + 1, &p, 16); else break;
            if (*p == '=') v = strtoul(p + 1, &p, 16); else break;
            if (a == addr) W32(m, v);
            if (*p == ',') ++p;
        }
    }
    if (getenv("CT_SEQ")) {             /* CT_SEQ=<callee>=<v1>:<v2>:...,...: the k-th call of the callee in a case returns v_k in eax (the last value stays) */
        char *p = getenv("CT_SEQ");
        while (*p) {
            unsigned long a = strtoul(p, &p, 16);
            u32 vals[16];
            int nv = 0;
            if (*p != '=') break;
            ++p;
            for (;;) { vals[nv++] = (u32)strtoul(p, &p, 16); if (*p == ':' && nv < 16) ++p; else break; }
            if (a == addr) { unsigned k = ct_seq_next(addr); r_eax = vals[k < (unsigned)nv ? k : (unsigned)nv - 1]; break; }
            if (*p == ',') ++p;
        }
    }
    ct_x87_out(ci->xd, h, addr);
    r_esp += 4 + ci->retn;
}
/* An import: the guest called a slot that holds 0xFE000000 + index (see ct_imports).  Same record and results as a stub, by name. */
void api_dispatch(u32 sentinel)
{
    u32 k = sentinel - 0xFE000000u;
    if (k >= ct_import_count) rt_unsup(sentinel, "call trace: an import that is not in the table");
    if (ct_n >= CT_MAXCALLS) rt_unsup(sentinel, "call trace: too many calls");
    char *o = ct_log[ct_n], w[48];
    ct_obj_callee = ct_imports[k].slot;
    o += sprintf(o, "imp:%s |", ct_import_names[k]);
    for (unsigned i = 0; i < ct_imports[k].nargs && i < 16; ++i) { ct_obj(w, R32(r_esp + 4 + 4 * i)); o += sprintf(o, " %s", w); }
    if (getenv("CT_WRITE")) {        /* CT_WRITE for an import: the callee is the address of its import table slot (see calltest.py) */
        char *p = getenv("CT_WRITE");
        while (*p) {
            unsigned long a = strtoul(p, &p, 16), o2, v;
            int arg = -1;
            if (*p != ':') break;
            ++p;
            if (p[0] == 'a') { arg = atoi(p + 1); while (*p && *p != '+') ++p; } else p += 3;
            if (*p != '+') break;
            o2 = strtoul(p + 1, &p, 16);
            if (*p != '=') break;
            ++p;
            if (*p == '@') { v = R32(r_esp + 4 + 4 * strtoul(p + 1, &p, 10)); }
            else if (*p == 'h') v = HEAP + strtoul(p + 1, &p, 16); else v = strtoul(p, &p, 16);
            if (a == ct_imports[k].slot && arg >= 0) {
                u32 at = R32(r_esp + 4 + 4 * arg) + (u32)o2;
                if ((at >= HEAP && at < HEAP + HEAP_SIZE - 3) || (at >= STK_BASE && at < STK_TOP + 0x1000 - 3)) W32(at, (u32)v);
            }
            if (*p == ',') ++p;
        }
    }
    u32 h = ct_mix((0x1000u + k) * 0x9E3779B1u ^ ct_mix(ct_seed * 0x85EBCA6Bu + ct_n));
    ++ct_n;
    r_eax = ct_value(h); r_ecx = ct_value(ct_mix(h + 1)); r_edx = ct_value(ct_mix(h + 2));
    if (getenv("CT_RET")) {        /* CT_RET for an import: the callee is the address of its import table slot; the value of the n-th call of that import (the last one for later calls) */
        char *p = getenv("CT_RET"), tag[80];
        unsigned idx = 0;
        sprintf(tag, "imp:%s |", ct_import_names[k]);
        for (u32 i = 0; i + 1 < ct_n; ++i) if (strncmp(ct_log[i], tag, strlen(tag)) == 0) ++idx;
        while (*p) {
            unsigned long a = strtoul(p, &p, 16);
            u32 v = 0;
            unsigned kk = 0;
            if (*p != '=') break;
            ++p;
            for (;;) {
                u32 t = 0;
                if (*p == '@' || *p == 'e') { while (*p && *p != '/' && *p != ',') ++p; } else t = (u32)strtoul(p, &p, 16);
                if (kk <= idx) v = t;
                ++kk;
                if (*p == '/') ++p; else break;
            }
            if (a == ct_imports[k].slot) r_eax = v;
            if (*p == ',') ++p;
        }
    }
    r_esp += 4 + 4 * ct_imports[k].nargs;
}
static void ct_fill_imports(u32 seed)            /* the slots of the imports: the same rule as calltest.py (an extension entry point is missing in one case of four) */
{
    for (unsigned k = 0; k < ct_import_count; ++k)
        if (ct_imports[k].kind < 2 || (ct_mix((ct_imports[k].slot * 0x9E3779B1u) ^ (seed * 0x85EBCA6Bu)) & 3) != 0) W32(ct_imports[k].slot, 0xFE000000u + k);
}
static void ct_print_log(void)
{
    for (u32 i = 0; i < ct_n; ++i) printf("T %s\n", ct_log[i]);
}
#endif

#if defined(_WIN32)
static LONG WINAPI on_crash(EXCEPTION_POINTERS *e)
{
#ifdef CALLTEST
    ct_print_log();
#endif
    printf("CRASH %08lx code %08lx info %08lx %08lx guest esp %08x eax %08x\n", (unsigned long)(uintptr_t)e->ExceptionRecord->ExceptionAddress,
           (unsigned long)e->ExceptionRecord->ExceptionCode, (unsigned long)e->ExceptionRecord->ExceptionInformation[0],
           (unsigned long)e->ExceptionRecord->ExceptionInformation[1], r_esp, r_eax);
    fflush(stdout);
    ExitProcess(4);
    return EXCEPTION_EXECUTE_HANDLER;
}
#else
static char crash_stack[32768];
static void on_crash_sig(int sig, siginfo_t *si, void *ctx)
{
    (void)ctx;
#ifdef CALLTEST
    ct_print_log();
#endif
    printf("CRASH %08lx code %08lx info %08lx %08lx guest esp %08x eax %08x\n", 0ul, (unsigned long)sig, 0ul,
           (unsigned long)(uintptr_t)si->si_addr, r_esp, r_eax);
    fflush(stdout);
    _exit(4);
}
static void install_crash_handler(void)
{
    stack_t ss = { .ss_sp = crash_stack, .ss_size = sizeof crash_stack, .ss_flags = 0 };
    sigaltstack(&ss, NULL);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_crash_sig;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
}
#endif

int main(int argc, char **argv)
{
#ifdef CALLTEST
    ct_stack_hi = (u32)(uintptr_t)&argc;
    /* The original runs with the x87 in 53-bit precision (the state of a Windows process, and the one calltest.py sets in Unicorn): the host's
     * long double arithmetic must round the same way, or the last bits of a result differ. */
#if defined(_WIN32)
    _controlfp(_PC_53, _MCW_PC);
#elif defined(__linux__) && defined(__i386__)
    { fpu_control_t cw; _FPU_GETCW(cw); cw = (cw & ~_FPU_EXTENDED) | _FPU_DOUBLE; _FPU_SETCW(cw); }
#endif
#endif
    if (argc < 3) return 2;
    if (!rt_load_image(argv[1])) {    /* address range taken by the loader this run: caller retries */
#if defined(_WIN32)
        if (getenv("RECOMP_VERBOSE")) {
            for (unsigned long a = SS_IMAGE_BASE; a < SS_IMAGE_END;) {
                MEMORY_BASIC_INFORMATION m;
                if (!VirtualQuery((void *)a, &m, sizeof m)) break;
                if (m.State != MEM_FREE) { fprintf(stderr, "occupied: %p +%lx type %lx", m.BaseAddress, (unsigned long)m.RegionSize, (unsigned long)m.Type); fputc(10, stderr); }
                a = (unsigned long)m.BaseAddress + m.RegionSize;
            }
        }
#endif
        return 77;
    }
    crc_init();
#if defined(_WIN32)
    SetUnhandledExceptionFilter(on_crash);
#else
    install_crash_handler();
#endif
#ifdef CALLTEST
    rt_sys_map_fixed(SENT & ~0xFFFu, 0x1000);      /* the page of the return address: the original side maps it too */
#endif
    /* the test areas sit at fixed addresses: when the loader put a DLL there, start again like for the image range */
    if (!rt_sys_map_fixed(STK_BASE, STK_SIZE) || !rt_sys_map_fixed(HEAP, HEAP_SIZE) || !rt_sys_map_fixed(TEB, 0x1000)) {
#if defined(_WIN32)
        if (getenv("RECOMP_VERBOSE")) {
            unsigned long area[3] = { STK_BASE, HEAP, (unsigned long)TEB };
            for (int i = 0; i < 3; ++i) {
                MEMORY_BASIC_INFORMATION m;
                VirtualQuery((void *)area[i], &m, sizeof m);
                fprintf(stderr, "test area %lx: state %lx type %lx region %p +%lx", area[i], (unsigned long)m.State, (unsigned long)m.Type, m.AllocationBase, (unsigned long)m.RegionSize);
                fputc(10, stderr);
            }
        }
#endif
        return 77;
    }
    pristine = malloc(DATA_HI - DATA_LO);
    memcpy(pristine, (void *)DATA_LO, DATA_HI - DATA_LO);
    FILE *f = fopen(argv[2], "r");
    if (!f) return 2;
    static char line[16384];
    while (fgets(line, sizeof line, f)) {
        unsigned long v[1100];
        int n = 0;
        char *p = strtok(line, " \r\n");
        while (p && n < 1100) { v[n++] = strtoul(p, NULL, 16); p = strtok(NULL, " \r\n"); }
        if (n < 10) continue;
        u32 addr = (u32)v[0], seed = (u32)v[8], nargs = (u32)v[9];
        memcpy((void *)DATA_LO, pristine, DATA_HI - DATA_LO);
        memset((void *)STK_BASE, getenv("CT_STKFILL") ? (int)strtoul(getenv("CT_STKFILL"), 0, 16) : 0, STK_SIZE);
        memset((void *)TEB, 0, 0x1000);
        W32(TEB, 0xFFFFFFFFu);
        W32(TEB + 4, STK_TOP + 0x1000);
        W32(TEB + 8, STK_BASE);
        W32(TEB + 0x18, TEB);
#ifdef CALLTEST
        ct_policy = (seed >> 10) & 3; ct_mode = (seed >> 8) & 3; seed &= 0xFF; ct_cur = addr; ct_seed = seed; ct_n = 0; ct_seq_used = 0; ct_seqn = 0;      /* the test line's seed carries the heap mode in bits 8-9 and the stub policy in bits 10-11 */
        ct_fill_imports(seed);
#endif
        u32 s = seed ? seed : 1;
        for (u32 i = 0; i < HEAP_SIZE; i += 4) {
            s ^= s << 13; s ^= s >> 17; s ^= s << 5;
            u32 w = s;
            if (STRUCT_HEAP_ON) {      /* a heap of linked objects: a quarter of the words point into the heap, a quarter are small counts */
                if ((s & 3) == 0) w = HEAP + ((s >> 8) % (HEAP_SIZE / 4 - 64)) * 4;
                else if ((s & 3) == 1) w = (s >> 8) & 7;
            }
#ifdef CALLTEST
            if (ct_mode == 2) {               /* heap mode 2: five eighths of the words are pointers into the heap, one eighth small counts */
                if ((s & 7) < 5) w = HEAP + ((s >> 8) % (HEAP_SIZE / 4 - 64)) * 4;
                else if ((s & 7) == 5) w = (s >> 8) & 7;
            } else if (ct_mode == 3) {        /* heap mode 3: three quarters pointers, a quarter small counts */
                w = (s & 7) < 6 ? HEAP + ((s >> 8) % (HEAP_SIZE / 4 - 64)) * 4 : (s >> 8) & 7;
            }
#endif
            W32(HEAP + i, w);
        }
        if (n > 10 + (int)nargs + 32) {        /* after the xmm values: a count, then address/value pairs written over the data and the heap (calltest.py's input search) */
            u32 nov = (u32)v[10 + nargs + 32];
            for (u32 k = 0; k < nov && 10 + nargs + 34 + 2 * k < (u32)n; ++k) W32(v[10 + nargs + 33 + 2 * k], v[10 + nargs + 34 + 2 * k]);
        }
        r_eax = v[1]; r_ecx = v[2]; r_edx = v[3]; r_ebx = v[4]; r_esi = v[5]; r_edi = v[6]; r_ebp = v[7];
        r_esp = STK_TOP;
        for (int i = (int)nargs - 1; i >= 0; --i) { r_esp -= 4; W32(r_esp, v[10 + i]); }
        r_esp -= 4; W32(r_esp, SENT);
        memset(fpr, 0, sizeof fpr); ftop = 0; fsw = 0; fcw = 0x27F; mxcsr = 0x1F80;      /* the x87 state of a new Windows process: empty, 53-bit precision */
        for (int k = 0; k < 32; ++k) xmm[k / 4].d[k % 4] = (u32)v[10 + nargs + k];
        rt_unsup_armed = 1;
        if (setjmp(rt_unsup_jmp)) {
            printf("UNSUP %08x %s\n", rt_unsup_addr, rt_unsup_msg);
            continue;
        }
        static unsigned char heap0[HEAP_SIZE];
        memcpy(heap0, (void *)HEAP, HEAP_SIZE);
#ifdef CALLTEST
        ct_call_target(addr);
        ct_print_log();
#else
        call_ind(addr);
#endif
        if (getenv("DIFF")) {
            int shown = 0;
            for (u32 i = 0; i < DATA_HI - DATA_LO && shown < 40; ++i)
                if (((unsigned char *)DATA_LO)[i] != pristine[i]) { printf("D %08x %02x\n", DATA_LO + i, ((unsigned char *)DATA_LO)[i]); ++shown; }
            for (u32 i = 0; i < HEAP_SIZE && shown < 80; ++i)
                if (((unsigned char *)HEAP)[i] != heap0[i]) { printf("D %08x %02x\n", HEAP + i, ((unsigned char *)HEAP)[i]); ++shown; }
            for (u32 i = 0; i < 0x4100 && shown < 120; ++i)
                if (((unsigned char *)(STK_TOP - 0x4000))[i]) { printf("D %08x %02x\n", STK_TOP - 0x4000 + i, ((unsigned char *)(STK_TOP - 0x4000))[i]); ++shown; }
        }
        if (getenv("DUMPHEAP")) { FILE *hf = fopen(getenv("DUMPHEAP"), "wb"); if (hf) { fwrite((void *)HEAP, 1, HEAP_SIZE, hf); fclose(hf); } }      /* difftest --show compares the whole heap with the original's */
        u32 c = crc(0, (unsigned char *)DATA_LO, DATA_HI - DATA_LO);
        if (getenv("PARTS")) printf("PARTS data %08x stack %08x heap %08x\n", c, crc(0, (unsigned char *)(STK_TOP - 0x4000), 0x4100), crc(0, (unsigned char *)HEAP, HEAP_SIZE));
        if (getenv("PARTS")) {
            for (u32 i = 0; i < 0x4100; ++i)
                if (((unsigned char *)(STK_TOP - 0x4000))[i]) printf("S %08x %02x\n", STK_TOP - 0x4000 + i, ((unsigned char *)(STK_TOP - 0x4000))[i]);
        }
        /* only the live part of the stack counts (from the final esp up): what lies below it is dead, and a rewrite
         * that does not push the same temporaries must not be reported for it */
        u32 live = r_esp >= STK_TOP - 0x4000 && r_esp <= STK_TOP + 0x100 ? r_esp : STK_TOP - 0x4000;
        if (!getenv("NOSTACK")) c = crc(c, (unsigned char *)live, STK_TOP + 0x100 - live);      /* NOSTACK: callee-owned argument slots the original used as scratch do not count */
        c = crc(c, (unsigned char *)HEAP, HEAP_SIZE);
        printf("OK %08x %08x %08x %08x %08x %08x %08x %08x %08x", r_eax, r_ecx, r_edx, r_ebx, r_esi, r_edi, r_ebp, r_esp, c);
#ifdef CALLTEST
        {                                         /* the x87 stack at the end: the depth and st(0) (calltest.py compares them with the original's) */
            char w[40];
            printf(" X %d", ct_depth());
            if (ct_depth() > 0) { ct_fbits(w, ST(0)); printf(" %s", w); }      /* st(0) is a returned double; what lies below is a leak of dead values */
        }
#endif
        printf("\n");
        fflush(stdout);
    }
    return 0;
}
