/* rt.c: registers, FPU helpers, image loader, indirect-call dispatch. */
#include "rt.h"
#include "project.h"
#include "sys.h"
#if defined(_WIN32)
#include <windows.h>
#elif !defined(__EMSCRIPTEN__)
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#endif
#include <setjmp.h>

/* ---- operating-system services (sys.h) ---- */
#if defined(_WIN32)
int rt_sys_map_fixed(u32 addr, u32 size)
{
    MEMORY_BASIC_INFORMATION m;
    if (VirtualQuery((void *)(uintptr_t)addr, &m, sizeof m) && m.State == MEM_RESERVE &&
        (u32)(uintptr_t)m.BaseAddress == addr && m.RegionSize >= size)
        return VirtualAlloc((void *)(uintptr_t)addr, size, MEM_COMMIT, PAGE_READWRITE) != NULL;
    return VirtualAlloc((void *)(uintptr_t)addr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) != NULL;
}
u32 rt_sys_alloc(u32 size)
{
    return (u32)(uintptr_t)VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}
void rt_sys_free(u32 addr, u32 size)
{
    (void)size;
    VirtualFree((void *)(uintptr_t)addr, 0, MEM_RELEASE);
}
void rt_sys_noaccess(u32 addr, u32 size)
{
    DWORD old;
    VirtualProtect((void *)(uintptr_t)addr, size, PAGE_NOACCESS, &old);
}
int rt_readable(u32 addr, u32 n)
{
    return !IsBadReadPtr((void *)(uintptr_t)addr, n);
}
#elif !defined(__EMSCRIPTEN__)
int rt_sys_map_fixed(u32 addr, u32 size)
{
#ifdef MAP_FIXED_NOREPLACE
    void *p = mmap((void *)(uintptr_t)addr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
#else
    void *p = mmap((void *)(uintptr_t)addr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);   /* a hint only */
#endif
    if (p == MAP_FAILED) return 0;
    if ((uintptr_t)p != addr) {             /* the kernel placed it elsewhere: the range is taken */
        munmap(p, size);
        return 0;
    }
    return 1;
}
u32 rt_sys_alloc(u32 size)
{
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? 0 : (u32)(uintptr_t)p;
}
void rt_sys_free(u32 addr, u32 size)
{
    munmap((void *)(uintptr_t)addr, size);
}
void rt_sys_noaccess(u32 addr, u32 size)
{
    mprotect((void *)(uintptr_t)addr, size, PROT_NONE);
}
int rt_readable(u32 addr, u32 n)
{
    /* the kernel copies from the buffer for write(): an unreadable byte gives EFAULT instead of a fault */
    static int fd[2] = { -1, -1 };
    if (fd[0] < 0 && pipe(fd) != 0) return 0;
    if (fd[0] >= 0) { fcntl(fd[0], F_SETFL, O_NONBLOCK); fcntl(fd[1], F_SETFL, O_NONBLOCK); }
    char sink[256];
    while (n) {
        u32 k = n > sizeof sink ? sizeof sink : n;
        ssize_t w = write(fd[1], (const void *)(uintptr_t)addr, k);
        if (w < 0) return errno != EFAULT;
        while (read(fd[0], sink, sizeof sink) > 0) {}
        addr += (u32)w;
        n -= (u32)w;
    }
    return 1;
}
#endif

u32 r_eax, r_ecx, r_edx, r_ebx, r_esp, r_ebp, r_esi, r_edi;
long double fpr[8];
XMM xmm[8];
u32 mxcsr = 0x1F80;
int ftop;
u16 fsw, fcw = 0x27F;

jmp_buf rt_unsup_jmp;
const char *rt_unsup_msg;
u32 rt_unsup_addr;
int rt_unsup_armed;

void rt_unsup(u32 addr, const char *msg)
{
    rt_unsup_addr = addr;
    rt_unsup_msg = msg;
    if (rt_unsup_armed) {
        longjmp(rt_unsup_jmp, 1);
    }
    fprintf(stderr, "unsupported at %08x: %s (guest esp %08x [esp] %08x eax %08x ecx %08x edx %08x)\n", addr, msg, r_esp,
            rt_readable(r_esp, 4) ? R32(r_esp) : 0, r_eax, r_ecx, r_edx);
    rt_shadow_dump();
    exit(3);
}

long double rt_r_f80(u32 a)
{
    long double v = 0;
    memcpy(&v, (void *)(uintptr_t)a, 10);
    return v;
}

void rt_w_f80(u32 a, long double v)
{
    memcpy((void *)(uintptr_t)a, &v, 10);
}

long double fx_rint(long double v)
{
    switch ((fcw >> 10) & 3) {
    case 0: return nearbyintl(v);
    case 1: return floorl(v);
    case 2: return ceill(v);
    default: return truncl(v);
    }
}
i16 fx_int16(long double v) { long double r = fx_rint(v); return (r >= -32768.0 && r < 32768.0) ? (i16)r : (i16)0x8000; }
i32 fx_int32(long double v) { long double r = fx_rint(v); return (r >= -2147483648.0 && r < 2147483648.0) ? (i32)r : (i32)0x80000000u; }
i64 fx_int64(long double v) { long double r = fx_rint(v); return (r >= -9223372036854775808.0 && r < 9223372036854775808.0) ? (i64)r : (i64)0x8000000000000000ull; }

void fx_compare(long double a, long double b)
{
    fsw &= ~0x4500;
    if (a != a || b != b) fsw |= 0x4500;
    else if (a > b) { }
    else if (a < b) fsw |= 0x0100;
    else fsw |= 0x4000;
}
u16 fx_sw(void) { return (u16)((fsw & ~0x3800) | ((ftop & 7) << 11)); }

static int cmp_ent(const void *k, const void *e)
{
    u32 a = *(const u32 *)k, b = ((const FnEnt *)e)->addr;
    return a < b ? -1 : a > b;
}

u32 rt_teb = 0x2E000000u;   /* test driver: the area sits low, where no system DLL is loaded */

RT_FALLBACK void api_dispatch(u32 sentinel)
{
    rt_unsup(sentinel, "import called but this build has no API bridge");
}

void call_ind(u32 target)
{
    if ((target & 0xFF000000u) == 0xFE000000u) {
        api_dispatch(target);
        return;
    }
    /* the script machine and the virtual methods come through here all the time: a small direct-mapped cache in front of the search */
    enum { CALL_CACHE = 1 << 14 };
    static const FnEnt *cache[CALL_CACHE];
    const FnEnt **slot = &cache[(target ^ (target >> 14)) & (CALL_CACHE - 1)];
    const FnEnt *e = *slot;
    if (!e || e->addr != target) {
        e = bsearch(&target, fn_table, fn_count, sizeof(FnEnt), cmp_ent);
        if (!e) {
            rt_unsup(target, "indirect call to a target that is not a lifted function");
        }
        *slot = e;
    }
    e->fn();
}

#if !defined(__EMSCRIPTEN__)
/* map the sections of the original image at their own addresses and copy the raw bytes */
extern const unsigned char rt_image_blob[] __attribute__((weak));     /* the original exe, embedded by scripts/build.sh */
extern const unsigned int rt_image_size __attribute__((weak));
int rt_load_image(const char *path)
{
    unsigned char *d;
    if (!path) {
        /* the data image emitted by gen.py: list of (address, length, offset) pieces */
        if (!&rt_image_blob[0]) return 0;
        DWORD old;
        VirtualProtect((void *)(uintptr_t)SS_IMAGE_BASE, 0x2000, PAGE_READWRITE, &old);
        if (!rt_sys_map_fixed(SS_IMAGE_BASE, SS_MAP_SIZE)) {
            if (!rt_readable(SS_IMAGE_BASE, 0x1000)) {
                fprintf(stderr, "map guest range failed: %lu\n", (unsigned long)GetLastError());
                return 0;
            }
            if (!rt_readable(SS_IMAGE_BASE + SS_MAP_SIZE, SS_TAIL_MAP_SIZE) && !rt_sys_map_fixed(SS_IMAGE_BASE + SS_MAP_SIZE, SS_TAIL_MAP_SIZE)) {
                MEMORY_BASIC_INFORMATION m;
                VirtualQuery((void *)(uintptr_t)(SS_IMAGE_BASE + SS_MAP_SIZE), &m, sizeof m);
                fprintf(stderr, "map guest tail failed: %lu state=%lx type=%lx base=%p size=%lx\n",
                        (unsigned long)GetLastError(), (unsigned long)m.State, (unsigned long)m.Type,
                        m.BaseAddress, (unsigned long)m.RegionSize);
                return 0;
            }
        }
        const u32 *t = (const u32 *)rt_image_blob;
        for (u32 i = 0; i < t[0]; ++i) memcpy((void *)(uintptr_t)t[1 + 3 * i], rt_image_blob + t[3 + 3 * i], t[2 + 3 * i]);
        /* the machine code is not part of the image: pages without any data piece must never be read, so make them
         * fault (the crash report names the reader) */
        if (getenv("RECOMP_NOACCESS")) {
        for (u32 pg = SS_CODE_LO; pg < SS_CODE_HI; pg += 0x1000) {
            int used = 0;
            for (u32 i = 0; i < t[0] && !used; ++i) used = t[1 + 3 * i] < pg + 0x1000 && t[1 + 3 * i] + t[2 + 3 * i] > pg;
            if (!used) rt_sys_noaccess(pg, 0x1000);
        }
        }
        return 1;
    } else {
        /* take the guest range first: reading the exe into a heap block would otherwise put that block in it */
        if (!rt_sys_map_fixed(SS_IMAGE_BASE, SS_DATA_SIZE)) return 0;
        FILE *f = fopen(path, "rb");
        if (!f) return 0;
        fseek(f, 0, SEEK_END);
        long n = ftell(f);
        fseek(f, 0, SEEK_SET);
        d = malloc(n);
        if (fread(d, 1, n, f) != (size_t)n) return 0;
        fclose(f);
    }
    u32 o = *(u32 *)(d + 0x3C);
    u16 ns = *(u16 *)(d + o + 6);
    u16 so = *(u16 *)(d + o + 20);
    memcpy((void *)(uintptr_t)SS_IMAGE_BASE, d, *(u32 *)(d + o + 24 + 60));      /* PE headers: the C runtime start-up validates them */
    for (int i = 0; i < ns; ++i) {
        unsigned char *h = d + o + 24 + so + 40 * i;
        u32 vs = *(u32 *)(h + 8), va = *(u32 *)(h + 12), rs = *(u32 *)(h + 16), rp = *(u32 *)(h + 20);
        u32 sz = vs > rs ? vs : rs;
        memcpy((void *)(uintptr_t)(SS_IMAGE_BASE + va), d + rp, rs < sz ? rs : sz);
    }
    free(d);
    return 1;
}
#endif

double fx_rint_mx(double v)
{
    switch ((mxcsr >> 13) & 3) {
    case 0: return nearbyint(v);
    case 1: return floor(v);
    case 2: return ceil(v);
    default: return trunc(v);
    }
}

u32 rt_eflags_extra;
int rt_df;
#if defined(__EMSCRIPTEN__)
void rt_cpuid(u32 leaf, u32 sub, u32 *a, u32 *b, u32 *c, u32 *d)
{
    (void)leaf;
    (void)sub;
    *a = *b = *c = *d = 0;
}
u64 rt_rdtsc(void) { return 0; }
#else
#include <cpuid.h>
void rt_cpuid(u32 leaf, u32 sub, u32 *a, u32 *b, u32 *c, u32 *d)
{
    __cpuid_count(leaf, sub, *a, *b, *c, *d);
}
u64 rt_rdtsc(void) { return __builtin_ia32_rdtsc(); }
#endif

u32 rt_watch_lo, rt_watch_hi;
void rt_watch_hit(u32 addr, u32 value, const char *fn)
{
    fprintf(stderr, "[watch] %s wrote %08x to %08x (guest esp %08x)\n", fn, value, addr, r_esp);
}

#ifdef RT_PROFILE
static unsigned char prof_seen[SS_DATA_SIZE / 8 + 1];
static unsigned int *prof_count;
static struct { u32 fn, esp; } shadow[8192];
static int shadow_n;
void rt_shadow_dump(void)      /* the live lifted functions, innermost first (profile builds only) */
{
    fprintf(stderr, "      guest call stack:");
    for (int i = shadow_n - 1; i >= 0 && i > shadow_n - 40; --i) fprintf(stderr, " %08x", shadow[i].fn);
    fprintf(stderr, "\n");
}
/* FN_ENTER / FN_RET take the function itself (FN_ENTER(TString__release);) or, as older code does, its guest address; this gives the address. */
u32 rt_fn_addr(const void *f)
{
    static const void *key[32768];
    static u32 val[32768];
    u32 raw = (u32)(uintptr_t)f;
    if (raw < 0x1000000) return raw;                                 /* already a guest address */
    u32 h = (raw >> 4) * 2654435761u >> 17;
    while (key[h & 32767] && key[h & 32767] != f) ++h;
    if (!key[h & 32767]) {
        key[h & 32767] = f;
        for (unsigned i = 0; i < fn_count; ++i) if ((const void *)fn_table[i].fn == f) { val[h & 32767] = fn_table[i].addr; break; }
    }
    return val[h & 32767];
}
void rt_snap_enter(u32 addr);
void rt_snap_ret(u32 fea);
void rt_prof(u32 addr)
{
    rt_snap_enter(addr);
    while (shadow_n > 0 && shadow[shadow_n - 1].esp <= r_esp) --shadow_n;     /* callers are entered with a higher esp: anything lower has returned */
    if (shadow_n < 8192) { shadow[shadow_n].fn = addr; shadow[shadow_n].esp = r_esp; ++shadow_n; }
    u32 k = addr - SS_IMAGE_BASE;
    if (k >= SS_DATA_SIZE) return;
    if (!prof_count) prof_count = (unsigned int *)calloc(SS_DATA_SIZE, sizeof(unsigned int));
    if (prof_count[k]++ == 0) fprintf(stderr, "[first] %08x\n", addr);
    static u32 list[64];
    static int n = -1;
    if (n < 0) {
        n = 0;
        const char *v = getenv("RECOMP_ENTLOG");        /* RECOMP_ENTLOG=hex,hex prints ecx and the first stack words when those functions start */
        while (v && *v && n < 64) { list[n++] = (u32)strtoul(v, (char **)&v, 16); if (*v == ',') ++v; }
    }
    static u32 peek = 1;
    if (peek == 1) { const char *p = getenv("RECOMP_ENTPEEK"); peek = p ? (u32)strtoul(p, NULL, 16) : 0; }   /* RECOMP_ENTPEEK=hex also prints the dword at that address */
    for (int i = 0; i < n; ++i)
        if (list[i] == addr) {
            fprintf(stderr, "[ent] %08x ecx=%08x a0=%08x a1=%08x a2=%08x peek=%08x\n", addr, r_ecx, R32(r_esp + 4), R32(r_esp + 8), R32(r_esp + 12), peek ? R32(peek) : 0);
            if (getenv("RECOMP_ENTDUMP") && r_ecx > 0x10000 && rt_readable(r_ecx, 0x60)) {       /* the first 0x60 bytes of the object in ecx */
                fprintf(stderr, "[ent]   this:");
                for (u32 o = 0; o < 0x60; o += 4) fprintf(stderr, " %08x", R32(r_ecx + o));
                fprintf(stderr, "\n");
            }
            u32 p0 = R32(r_esp + 4);
            if (getenv("RECOMP_ENTDUMP") && p0 > 0x10000 && rt_readable(p0, 0x70)) {      /* and of the object the first argument points to */
                fprintf(stderr, "[ent]   a0->:");
                for (u32 o = 0; o < 0x70; o += 4) fprintf(stderr, " %08x", R32(p0 + o));
                fprintf(stderr, "\n");
            }
        }
}
void rt_bb(u32 addr)
{
    static u32 lo, hi;
    static int init;
    if (!init) {
        init = 1;
        const char *v = getenv("RECOMP_BBLOG");
        if (v) { char *e; lo = (u32)strtoul(v, &e, 16); if (*e == '-') hi = (u32)strtoul(e + 1, NULL, 16); }
    }
    if (addr >= lo && addr < hi) fprintf(stderr, "[bb] %08x\n", addr);
}
void rt_fn_ret(u32 fea)
{
    rt_snap_ret(fea);
    static u32 list[64];
    static int n = -1;
    if (n < 0) {
        n = 0;
        const char *v = getenv("RECOMP_RETLOG");
        while (v && *v && n < 64) { list[n++] = (u32)strtoul(v, (char **)&v, 16); if (*v == ',') ++v; }
    }
    for (int i = 0; i < n; ++i)
        if (list[i] == fea) {
            u32 p1 = 0, p2 = 0;      /* eax as a pointer to a pointer to a counted block: for a string object these are its buffer and its length */
            if (r_eax > 0x10000 && rt_readable(r_eax, 4)) {
                p1 = R32(r_eax);
                if (p1 > 0x10000 && rt_readable(p1, 4)) p2 = R32(p1);
            }
            fprintf(stderr, "[ret] %08x eax=%08x [eax]=%08x [[eax]]=%08x esp=%08x\n", fea, r_eax, p1, p2, r_esp);
        }
}
void rt_prof_dump(void)       /* called at exit: how many times each function ran */
{
    if (!prof_count) return;
    for (u32 k = 0; k < SS_DATA_SIZE; ++k)
        if (prof_count[k]) fprintf(stderr, "[count] %08x %u\n", SS_IMAGE_BASE + k, prof_count[k]);
}
#else
void rt_prof_dump(void) {}
void rt_shadow_dump(void) {}
#endif

/* the functions that rt/override.c replaces: weak versions so the test driver (recomp.exe), which does not link
 * override.c, still links.  They are never meaningful in a test. */
RT_FALLBACK void f_00469df0(void) { rt_unsup(0x469df0, "function is replaced by override.c"); }
RT_FALLBACK void f_0046c010(void) { rt_unsup(0x46c010, "function is replaced by override.c"); }
RT_FALLBACK void f_0046c3d0(void) { rt_unsup(0x46c3d0, "function is replaced by override.c"); }
RT_FALLBACK void f_005dc8b3(void)
{
    if (r_ecx != R32(0x726EE8)) rt_unsup(0x5dc8b3, "stack cookie mismatch");
    r_esp += 4;
}

#ifdef RT_PROFILE
/* Snapshot of the guest state at the nth call of a lifted function, for replaying that call in Unicorn
 * (scripts/replay_snapshot.py) and comparing the result: RECOMP_SNAP=<function hex>:<n>[:<output prefix>].
 * Writes <prefix>.bin (registers and every private committed memory region) and, when the call returns, <prefix>.res. */
static u32 snap_fn, snap_n, snap_count, snap_esp;
static char snap_prefix[260];
static int snap_pending, snap_init;

static void snap_setup(void)
{
    snap_init = 1;
    const char *v = getenv("RECOMP_SNAP");
    if (!v) return;
    char *e;
    snap_fn = (u32)strtoul(v, &e, 16);
    snap_n = *e == ':' ? (u32)strtoul(e + 1, &e, 10) : 1;
    strcpy(snap_prefix, *e == ':' ? e + 1 : "snap");
}

void rt_snap_enter(u32 addr)
{
    if (!snap_init) snap_setup();
    if (addr != snap_fn || ++snap_count != snap_n) return;
    char path[300];
    snprintf(path, sizeof path, "%s.bin", snap_prefix);
    FILE *f = fopen(path, "wb");
    if (!f) return;
    u32 regs[10] = { r_eax, r_ecx, r_edx, r_ebx, r_esp, r_ebp, r_esi, r_edi, addr, rt_teb };
    fwrite(regs, sizeof regs, 1, f);
    u32 nreg = 0;
    long nreg_pos = ftell(f);
    fwrite(&nreg, 4, 1, f);
#if defined(_WIN32)
    MEMORY_BASIC_INFORMATION mbi;
    for (uintptr_t p = 0x10000; p < 0x7FFE0000u; p += mbi.RegionSize) {
        if (!VirtualQuery((void *)p, &mbi, sizeof mbi)) break;
        if (mbi.State == MEM_COMMIT && mbi.Type != MEM_IMAGE && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ))) {
            u32 hdr[2] = { (u32)(uintptr_t)mbi.BaseAddress, (u32)mbi.RegionSize };
            fwrite(hdr, 8, 1, f);
            fwrite(mbi.BaseAddress, 1, mbi.RegionSize, f);
            ++nreg;
        }
    }
#else
    /* private writable mappings (not files): the guest image, heaps, stacks */
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[512];
    while (maps && fgets(line, sizeof line, maps)) {
        unsigned long lo, hi, off;
        char perms[8] = "", dev[16] = "";
        unsigned long inode = 0;
        if (sscanf(line, "%lx-%lx %7s %lx %15s %lu", &lo, &hi, perms, &off, dev, &inode) < 6) continue;
        if (perms[0] != 'r' || perms[1] != 'w' || perms[3] != 'p' || inode != 0 || hi > 0xFFFFF000ul) continue;
        u32 hdr[2] = { (u32)lo, (u32)(hi - lo) };
        fwrite(hdr, 8, 1, f);
        fwrite((void *)(uintptr_t)lo, 1, hi - lo, f);
        ++nreg;
    }
    if (maps) fclose(maps);
#endif
    fseek(f, nreg_pos, SEEK_SET);
    fwrite(&nreg, 4, 1, f);
    fclose(f);
    snap_esp = r_esp;
    snap_pending = 1;
    fprintf(stderr, "[snap] %08x call %u saved to %s\n", addr, snap_n, path);
}

void rt_snap_ret(u32 fea)
{
    if (!snap_pending || fea != snap_fn || r_esp <= snap_esp) return;
    char path[300];
    snprintf(path, sizeof path, "%s.res", snap_prefix);
    FILE *f = fopen(path, "wb");
    if (f) {
        u32 res[8] = { r_eax, r_ecx, r_edx, r_ebx, r_esp, r_ebp, r_esi, r_edi };
        fwrite(res, sizeof res, 1, f);
        fclose(f);
    }
    snap_pending = 0;
    fprintf(stderr, "[snap] %08x returned eax=%08x esp=%08x\n", fea, r_eax, r_esp);
}
#endif
