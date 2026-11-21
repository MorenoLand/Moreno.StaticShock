/* api.c: calls from lifted (guest) code into the real Windows API, and from Windows back into guest code.
 *
 * Guest code reaches an import through its IAT slot; boot.c fills every slot with a sentinel address
 * (API_BASE + index * 16), and call_ind() hands those to api_dispatch().  Arguments are read from the guest stack,
 * the real function is called with the global lock released, and the result goes back into eax/edx.
 *
 * Only one guest thread runs at a time (the "GIL"): the CPU registers are globals, so a thread saves its registers
 * before it leaves the lock for a blocking call and restores them when it re-enters.
 */
#include "rt.h"
#include "sys.h"
#include "api.h"
#if !defined(_WIN32)
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#define __stdcall __attribute__((stdcall))
#define __cdecl __attribute__((cdecl))
#endif

#define API_BASE 0xFE000000u
#define MAX_API 8192
#define SENT_RET 0xDEAD0000u

ApiEnt api_tab[MAX_API];
int api_count;


#if defined(_WIN32)
static CRITICAL_SECTION gil;
static DWORD ts_index = TLS_OUT_OF_INDEXES;
#else
static pthread_mutex_t gil = PTHREAD_MUTEX_INITIALIZER;
#endif
int rt_trace;

typedef struct {
    u32 saved_esp; int in_api; u32 stack_lo, stack_top, teb;
    u32 last_error;                  /* non-Windows hosts: GetLastError of this thread */
    u32 tls[W32_TLS_SLOTS];          /* non-Windows hosts: TlsGetValue slots of this thread */
} ThreadState;
#if !defined(_WIN32)
static __thread ThreadState *ts_self;
#endif

typedef struct { u32 eax, ecx, edx, ebx, esp, ebp, esi, edi, teb; } Cpu;
static void cpu_save(Cpu *c)
{
    c->eax = r_eax; c->ecx = r_ecx; c->edx = r_edx; c->ebx = r_ebx; c->esp = r_esp; c->ebp = r_ebp; c->esi = r_esi; c->edi = r_edi; c->teb = rt_teb;
}
static void cpu_load(const Cpu *c)
{
    r_eax = c->eax; r_ecx = c->ecx; r_edx = c->edx; r_ebx = c->ebx; r_esp = c->esp; r_ebp = c->ebp; r_esi = c->esi; r_edi = c->edi; rt_teb = c->teb;
}

#if defined(_WIN32)
void gil_init(void)
{
    InitializeCriticalSection(&gil);
    ts_index = TlsAlloc();
    EnterCriticalSection(&gil);
}
static void gil_enter(void) { EnterCriticalSection(&gil); }
static void gil_leave(void) { LeaveCriticalSection(&gil); }
#else
void gil_init(void)
{
    pthread_mutex_lock(&gil);
}
static void gil_enter(void) { pthread_mutex_lock(&gil); }
static void gil_leave(void) { pthread_mutex_unlock(&gil); }
#endif

/* a fake TEB: only the fields guest code reads (SEH chain, stack bounds, self pointer) */
u32 rt_new_teb(u32 stack_lo, u32 stack_top)
{
    u32 t = rt_sys_alloc(0x1000);
    W32(t + 0, 0xFFFFFFFFu);
    W32(t + 4, stack_top);
    W32(t + 8, stack_lo);
    W32(t + 0x18, t);
    return t;
}

ThreadState *rt_thread(void)
{
#if defined(_WIN32)
    /* TlsGetValue resets the thread's last-error value to 0.  The guest reads it (GetLastError, WSAGetLastError) after
     * the API that set it, so everything the bridge does in between must leave it alone. */
    DWORD last_error = GetLastError();
    ThreadState *ts = (ThreadState *)TlsGetValue(ts_index);
    SetLastError(last_error);
#else
    ThreadState *ts = ts_self;
#endif
    if (!ts) {
        ts = (ThreadState *)calloc(1, sizeof *ts);
        ts->stack_lo = rt_sys_alloc(0x100000);
        ts->stack_top = ts->stack_lo + 0x100000 - 0x1000;
        ts->teb = rt_new_teb(ts->stack_lo, ts->stack_top);
#if defined(_WIN32)
        TlsSetValue(ts_index, ts);
        SetLastError(last_error);
#else
        ts_self = ts;
#endif
    }
    return ts;
}

/* the main guest thread uses a bigger stack, set up by boot.c */
void rt_main_thread(u32 lo, u32 top)
{
    ThreadState *ts = (ThreadState *)calloc(1, sizeof *ts);
    ts->stack_lo = lo;
    ts->stack_top = top;
    ts->teb = rt_new_teb(lo, top);
#if defined(_WIN32)
    TlsSetValue(ts_index, ts);
#else
    ts_self = ts;
#endif
    rt_teb = ts->teb;
    r_esp = top;
}

u32 *rt_tls_slots(void) { return rt_thread()->tls; }
u32 *rt_last_error(void) { return &rt_thread()->last_error; }

/* ---- calling guest code ---- */
u32 gcall(u32 addr, u32 ecx_value, int cdecl_, int n, ...)
{
    u32 a[32];
    va_list ap;
    va_start(ap, n);
    for (int i = 0; i < n; ++i) a[i] = va_arg(ap, u32);
    va_end(ap);
    r_ecx = ecx_value;
    u32 start = r_esp;
    for (int i = n - 1; i >= 0; --i) { r_esp -= 4; W32(r_esp, a[i]); }
    r_esp -= 4; W32(r_esp, SENT_RET);
    call_ind(addr);
    if (cdecl_) r_esp += 4 * n;
    if (r_esp != start) {       /* the callee removed a different number of argument bytes than the convention says */
        fprintf(stderr, "gcall %08x: stack ends %d bytes off (n=%d, cdecl=%d)\n", addr, (int)(r_esp - start), n, cdecl_);
        r_esp = start;
    }
    return r_eax;
}

/* ---- calling the real API with n 32-bit arguments ---- */
typedef u64 (__stdcall *F0)(void);
typedef u64 (__stdcall *F1)(u32);
typedef u64 (__stdcall *F2)(u32, u32);
typedef u64 (__stdcall *F3)(u32, u32, u32);
typedef u64 (__stdcall *F4)(u32, u32, u32, u32);
typedef u64 (__stdcall *F5)(u32, u32, u32, u32, u32);
typedef u64 (__stdcall *F6)(u32, u32, u32, u32, u32, u32);
typedef u64 (__stdcall *F7)(u32, u32, u32, u32, u32, u32, u32);
typedef u64 (__stdcall *F8)(u32, u32, u32, u32, u32, u32, u32, u32);
typedef u64 (__stdcall *F9)(u32, u32, u32, u32, u32, u32, u32, u32, u32);
typedef u64 (__stdcall *F10)(u32, u32, u32, u32, u32, u32, u32, u32, u32, u32);
typedef u64 (__stdcall *F11)(u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32);
typedef u64 (__stdcall *F12)(u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32);
typedef u64 (__stdcall *F13)(u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32);
typedef u64 (__stdcall *F14)(u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32);
typedef u64 (__stdcall *F15)(u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32);
typedef u64 (__stdcall *F16)(u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32);
typedef u64 (__cdecl *C16)(u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32);

static u64 host_call(void *fn, int n, int cdecl_, const u32 *a, int tc, u32 ecx)
{
    if (tc) {
        switch (n) {
        case 0: return ((u32 (__thiscall *)(void *))fn)((void *)(uintptr_t)ecx);
        case 1: return ((u32 (__thiscall *)(void *, u32))fn)((void *)(uintptr_t)ecx, a[0]);
        case 2: return ((u32 (__thiscall *)(void *, u32, u32))fn)((void *)(uintptr_t)ecx, a[0], a[1]);
        case 3: return ((u32 (__thiscall *)(void *, u32, u32, u32))fn)((void *)(uintptr_t)ecx, a[0], a[1], a[2]);
        case 4: return ((u32 (__thiscall *)(void *, u32, u32, u32, u32))fn)((void *)(uintptr_t)ecx, a[0], a[1], a[2], a[3]);
        }
        return 0;
    }
    if (cdecl_) {
        return ((C16)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
    }
    switch (n) {
    case 0: return ((F0)fn)();
    case 1: return ((F1)fn)(a[0]);
    case 2: return ((F2)fn)(a[0], a[1]);
    case 3: return ((F3)fn)(a[0], a[1], a[2]);
    case 4: return ((F4)fn)(a[0], a[1], a[2], a[3]);
    case 5: return ((F5)fn)(a[0], a[1], a[2], a[3], a[4]);
    case 6: return ((F6)fn)(a[0], a[1], a[2], a[3], a[4], a[5]);
    case 7: return ((F7)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6]);
    case 8: return ((F8)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
    case 9: return ((F9)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
    case 10: return ((F10)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9]);
    case 11: return ((F11)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10]);
    case 12: return ((F12)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11]);
    case 13: return ((F13)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12]);
    case 14: return ((F14)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13]);
    case 15: return ((F15)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14]);
    case 16: return ((F16)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
    }
    return 0;
}

/* ---- host-callable trampolines for guest function pointers (Windows: the real API calls them) ---- */
#if defined(_WIN32)
typedef struct { u32 guest; int nargs; u32 stub; } Tramp;
static Tramp tramps[512];
static int tramp_n;
static unsigned char *tramp_mem;
static int tramp_used;

static u32 __cdecl host_cb(u32 idx, u32 *args)
{
    gil_enter();
    ThreadState *ts = rt_thread();
    Tramp *t = &tramps[idx];
    Cpu keep;
    cpu_save(&keep);
    if (ts->in_api) {
        r_esp = ts->saved_esp - 0x100;
    } else {
        r_esp = ts->stack_top;
    }
    rt_teb = ts->teb;
    for (int i = t->nargs - 1; i >= 0; --i) { r_esp -= 4; W32(r_esp, args[i]); }
    r_esp -= 4; W32(r_esp, SENT_RET);
    if (rt_trace) fprintf(stderr, "[cb] guest %08x (%d args) first %08x\n", t->guest, t->nargs, t->nargs ? args[0] : 0);
    call_ind(t->guest);
    u32 res = r_eax;
    cpu_load(&keep);
    gil_leave();
    return res;
}

u32 rt_tramp(u32 guest, int nargs)
{
    if ((guest & 0xFF000000u) == API_BASE) {
        ApiEnt *e = &api_tab[(guest - API_BASE) >> 4];
        return (u32)(uintptr_t)e->fn;               /* a guest pointer to an API: the real function is directly callable */
    }
    for (int i = 0; i < tramp_n; ++i)
        if (tramps[i].guest == guest && tramps[i].nargs == nargs) return tramps[i].stub;
    if (!tramp_mem || tramp_used + 32 > 0x10000) {
        tramp_mem = (unsigned char *)VirtualAlloc(NULL, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        tramp_used = 0;
    }
    unsigned char *p = tramp_mem + tramp_used;
    tramp_used += 32;
    int idx = tramp_n++;
    tramps[idx].guest = guest;
    tramps[idx].nargs = nargs;
    unsigned k = 0;
    p[k++] = 0x8D; p[k++] = 0x44; p[k++] = 0x24; p[k++] = 0x04;                  /* lea eax, [esp+4] */
    p[k++] = 0x50;                                                               /* push eax */
    p[k++] = 0x68; *(u32 *)(p + k) = (u32)idx; k += 4;                           /* push idx */
    p[k++] = 0xE8; *(u32 *)(p + k) = (u32)((unsigned char *)host_cb - (p + k + 4)); k += 4;   /* call host_cb */
    p[k++] = 0x83; p[k++] = 0xC4; p[k++] = 0x08;                                 /* add esp, 8 */
    p[k++] = 0xC2; *(u16 *)(p + k) = (u16)(nargs * 4); k += 2;                   /* ret nargs*4 */
    tramps[idx].stub = (u32)(uintptr_t)p;
    return tramps[idx].stub;
}
#endif

/* ---- API table ---- */
u32 api_add(const char *module, const char *name, FARPROC fn, int nargs, int cdecl_)
{
    if (api_count >= MAX_API) { fprintf(stderr, "api table full\n"); exit(5); }
    int i = api_count++;
    ApiEnt *e = &api_tab[i];
    e->module = module; e->name = name; e->fn = fn; e->nargs = nargs; e->cdecl_ = cdecl_; e->special = 0;
    e->emu = NULL; e->host_cdecl = 0;
    return API_BASE + (u32)i * 16;
}

u32 api_add_emu(const char *module, const char *name, ApiEmu emu, int nargs, int cdecl_)
{
    u32 s = api_add(module, name, NULL, nargs, cdecl_);
    api_tab[(s - API_BASE) >> 4].emu = emu;
    return s;
}

/* ---- thread start ---- */
typedef struct { u32 fn, param; } GThreadStart;
#if defined(_WIN32)
static DWORD WINAPI guest_thread_main(LPVOID p)
#else
static void *guest_thread_main(void *p)
#endif
{
    GThreadStart st = *(GThreadStart *)p;
    free(p);
    gil_enter();
    ThreadState *ts = rt_thread();
    rt_teb = ts->teb;
    r_esp = ts->stack_top;
    u32 res = gcall(st.fn, 0, 0, 1, st.param);
    gil_leave();
#if defined(_WIN32)
    return res;
#else
    return (void *)(uintptr_t)res;
#endif
}

/* ---- the dispatcher ---- */
static u32 guest_str_nargs_lookup(const char *name);

static unsigned long now_ms(void)
{
#if defined(_WIN32)
    return GetTickCount();
#else
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long)t.tv_sec * 1000ul + (unsigned long)(t.tv_nsec / 1000000);
#endif
}

unsigned api_call_count[MAX_API];                    /* how often each import was called (every host) */
#if defined(_WIN32)
/* RECOMP_SAMPLE=1: a thread looks at where the guest thread is every millisecond (its instruction pointer); the counts per 16-byte block are printed with
 * RECOMP_PROF_SECONDS, to be looked up in bin/lift.map.  Shows the real cost of the code, inlined functions included. */
#define SAMPLE_SLOTS 65536
static u32 sample_eip[SAMPLE_SLOTS], sample_count[SAMPLE_SLOTS];
static HANDLE sample_thread;
static volatile int sample_run;
static void sample_print(int round)
{
    static unsigned shown[MAX_API];
    {   /* the API calls since the last print, the most frequent first (RECOMP_SAMPLE): which system calls a slow stretch is made of */
        int order[MAX_API], n = 0;
        for (int i = 0; i < MAX_API; ++i) if (api_call_count[i] != shown[i]) order[n++] = i;
        for (int i = 0; i < n; ++i) for (int j = i + 1; j < n; ++j)
            if (api_call_count[order[j]] - shown[order[j]] > api_call_count[order[i]] - shown[order[i]]) { int tmp = order[i]; order[i] = order[j]; order[j] = tmp; }
        for (int i = 0; i < n && i < 12; ++i) fprintf(stderr, "[apicalls %d] %s!%s %u\n", round, api_tab[order[i]].module, api_tab[order[i]].name, api_call_count[order[i]] - shown[order[i]]);
        for (int i = 0; i < n; ++i) shown[order[i]] = api_call_count[order[i]];
    }
    fprintf(stderr, "[samplebase %d] %08lx\n", round, (unsigned long)(uintptr_t)GetModuleHandleA(NULL));
    for (int i = 0; i < SAMPLE_SLOTS; ++i) if (sample_eip[i]) fprintf(stderr, "[sample %d] %08x %u\n", round, sample_eip[i], sample_count[i]);
    fflush(stderr);
}
static DWORD WINAPI sample_main(LPVOID arg)
{
    int round = 0;
    DWORD last = GetTickCount();
    (void)arg;
    while (sample_run) {
        CONTEXT c;
        Sleep(1);
        if (GetTickCount() - last >= 5000) { last = GetTickCount(); sample_print(++round); }          /* the counts so far, every 5 seconds: the program may be closed before it stops by itself */
        if (SuspendThread(sample_thread) == (DWORD)-1) continue;
        c.ContextFlags = CONTEXT_CONTROL;
        if (GetThreadContext(sample_thread, &c)) {
            u32 block = (u32)c.Eip & ~15u, h = (block >> 4) * 2654435761u >> 16;
            while (sample_eip[h & (SAMPLE_SLOTS - 1)] && sample_eip[h & (SAMPLE_SLOTS - 1)] != block) ++h;
            sample_eip[h & (SAMPLE_SLOTS - 1)] = block;
            ++sample_count[h & (SAMPLE_SLOTS - 1)];
        }
        ResumeThread(sample_thread);
    }
    return 0;
}
static void sample_start(void)
{
    static int started;
    if (started++ || !getenv("RECOMP_SAMPLE")) return;
    DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &sample_thread, 0, FALSE, DUPLICATE_SAME_ACCESS);
    sample_run = 1;
    CreateThread(NULL, 0, sample_main, NULL, 0, NULL);
}
static void sample_dump(void)
{
    sample_run = 0;
    Sleep(5);
    sample_print(0);
}
#else
static void sample_start(void) {}
static void sample_dump(void) {}
#endif

void api_dispatch(u32 sentinel)
{
    int idx = (int)((sentinel - API_BASE) >> 4);
    ApiEnt *e = &api_tab[idx];
    if (idx >= 0 && idx < MAX_API) ++api_call_count[idx];
    sample_start();                                  /* RECOMP_SAMPLE: from the first system call on, so a hang before the message loop shows too */
    u32 a[32];
    u32 *sp = (u32 *)(uintptr_t)(r_esp + 4);
    int n = e->nargs < 0 ? 0 : e->nargs;
    if (e->name[0] == 'P' && !strcmp(e->name, "PeekMessageA")) {          /* debugging: RECOMP_FRAMES=n stops after n message-loop turns */
        sample_start();
        static int frames, limit = -1;
        if (limit < 0) { const char *v = getenv("RECOMP_FRAMES"); limit = v ? atoi(v) : 0; }
        if (rt_trace && frames % 100 == 5) {      /* debugging: the focused GUI control decides whether the script scheduler runs (Timer_MainTick) */
            u32 fr = R32(0x72BD9C);
            fprintf(stderr, "[state] frame %d: first responder %08x (+198 = %02x, vtable %08x), canvas %08x, main window %08x\n", frames, fr,
                    fr ? R8(fr + 198) : 0, fr ? R32(fr) : 0, R32(0x72E1A0), R32(0x72B9DC));
        }
        {   /* RECOMP_PROF_SECONDS=n: stop after n seconds and print the counts, so a profile of a server session does not depend on the speed of the loop */
            static long secs = -1;
            static unsigned long start;
            if (secs < 0) { const char *v = getenv("RECOMP_PROF_SECONDS"); secs = v ? atol(v) : 0; start = now_ms(); }
            if (secs > 0 && now_ms() - start > (unsigned long)secs * 1000ul) limit = 1, frames = 2;
        }
        if (limit > 0 && ++frames > limit) {
            rt_prof_dump();
            sample_dump();
            fflush(stderr);
#if defined(_WIN32)
            ExitProcess(0);
#else
            _exit(0);
#endif
        }
    }
    if (e->nargs < 0) {
        fprintf(stderr, "api %s!%s called but its argument count is unknown (guest esp %08x)\n", e->module, e->name, r_esp);
        exit(6);
    }
    for (int i = 0; i < (e->cdecl_ ? 16 : n); ++i) a[i] = sp[i];
    for (int i = e->cdecl_ ? 16 : n; i < 16; ++i) a[i] = 0;
    if (rt_trace) {
        static unsigned long t0; if (!t0) t0 = now_ms();
        fprintf(stderr, "[api %6lu] %s!%s(", now_ms() - t0, e->module, e->name);
        for (int i = 0; i < n && i < 8; ++i) {
            fprintf(stderr, "%s%x", i ? ", " : "", a[i]);
            const char *s = (const char *)(uintptr_t)a[i];       /* show text arguments: file names, registry keys, host names */
            if (a[i] > 0x10000 && rt_readable(a[i], 4) && (unsigned char)s[0] >= 0x20 && (unsigned char)s[0] < 0x7F && (unsigned char)s[1] >= 0x20 && (unsigned char)s[1] < 0x7F && (unsigned char)s[2] >= 0x20 && (unsigned char)s[2] < 0x7F) {
                char tmp[48];
                int k = 0;
                while (k < 47 && rt_readable(a[i] + k, 1) && (unsigned char)s[k] >= 0x20 && (unsigned char)s[k] < 0x7F) { tmp[k] = s[k]; ++k; }
                tmp[k] = 0;
                fprintf(stderr, " \"%s\"", tmp);
            }
        }
        fprintf(stderr, ")\n");
    }
#if defined(_WIN32)
    /* The notification-area icons are built from image files the game downloads: while
     * they are not there the icon handle is 0 and the entry shows nothing.  Such an entry gets the program's own icon instead. */
    if (e->name[0] == 'S' && !strcmp(e->name, "Shell_NotifyIconA") && a[1] > 0x10000 && rt_readable(a[1], 0x18) && (R32(a[1] + 12) & 2) && R32(a[1] + 20) == 0) {
        static HICON app_icon;
        if (!app_icon) app_icon = LoadIconA(GetModuleHandleA(NULL), MAKEINTRESOURCEA(1));
        if (app_icon) W32(a[1] + 20, (u32)(uintptr_t)app_icon);
    }
#endif
    ThreadState *ts = rt_thread();
    u64 r;
    int special = e->special;
#if defined(_WIN32)
    if (special) {
        r = api_special(special, e, a);
    } else
#else
    (void)special;
#endif
    if (e->emu) {
        r = e->emu(a);                   /* an emulated Win32 function: runs with the lock held, releases it itself if it blocks */
    } else if (!e->fn) {
#if defined(_WIN32)
        /* the import was not found when the program started (a DLL beside the game is missing, fmod.dll for the sound): the call
         * does nothing and returns 0 instead of jumping to address 0 */
        static int shown;
        if (shown++ < 12) fprintf(stderr, "call of %s!%s ignored: the import was not found\n", e->module, e->name);
        r = 0;
#else
        /* outside Windows every import is emulated: one without an emulation is a gap in recomp/rt/win32/, and a made-up result
         * would only fail later somewhere else */
        fprintf(stderr, "import %s!%s is called but this host has no implementation of it (guest esp %08x, return to %08x)\n",
                e->module, e->name, r_esp, R32(r_esp));
        fflush(stderr);
        exit(6);
#endif
    } else {
        Cpu keep;
        cpu_save(&keep);
        ts->saved_esp = r_esp;
        ts->in_api++;
        gil_leave();
        r = host_call((void *)e->fn, n, e->cdecl_ || e->host_cdecl, a, e->module && !strcmp(e->module, "MSVCP80") && strstr(e->name, "@@Q"), keep.ecx);
        gil_enter();
        ts->in_api--;
        cpu_load(&keep);
    }
    {   /* RECOMP_LOGAPI=Name,module,...: show those calls and their results (for a Shell_NotifyIconA call also its NOTIFYICONDATA) */
        static const char *logapi = (const char *)1;
        if (logapi == (const char *)1) logapi = getenv("RECOMP_LOGAPI");
        if (logapi && (strstr(logapi, e->name) || strstr(logapi, e->module))) {
            fprintf(stderr, "[logapi %lu] %s!%s(", now_ms(), e->module, e->name);
            for (int i = 0; i < n && i < 8; ++i) fprintf(stderr, "%s%x", i ? ", " : "", a[i]);
            fprintf(stderr, ") -> %llx", (unsigned long long)r);
            if ((!strcmp(e->name, "inet_addr") || !strcmp(e->name, "gethostbyname")) && a[0] > 0x10000 && rt_readable(a[0], 64))
                fprintf(stderr, "  \"%.63s\"", (const char *)(uintptr_t)a[0]);
            if (!strcmp(e->name, "send") && a[1] > 0x10000 && a[2] > 0 && rt_readable(a[1], a[2] < 24 ? a[2] : 24)) {
                const unsigned char *sb = (const unsigned char *)(uintptr_t)a[1];
                fprintf(stderr, "  \"");
                for (unsigned i = 0; i < a[2] && i < 24; ++i) fprintf(stderr, sb[i] >= 32 && sb[i] < 127 ? "%c" : "\\x%02x", sb[i]);
                fprintf(stderr, "\"");
            }
            if (!strcmp(e->name, "connect") && a[1] > 0x10000 && rt_readable(a[1], 8)) {
                const unsigned char *sa = (const unsigned char *)(uintptr_t)a[1];
                fprintf(stderr, "  %u.%u.%u.%u:%u", sa[4], sa[5], sa[6], sa[7], (sa[2] << 8) | sa[3]);
            }
            if (!strcmp(e->name, "Shell_NotifyIconA") && a[1] > 0x10000 && rt_readable(a[1], 0x20))
                fprintf(stderr, "  cbSize %x hWnd %x uID %x flags %x callback %x hIcon %x", R32(a[1]), R32(a[1] + 4), R32(a[1] + 8), R32(a[1] + 12), R32(a[1] + 16), R32(a[1] + 20));
#if defined(_WIN32)
            fprintf(stderr, "  lasterror %lu", GetLastError());
#endif
            fprintf(stderr, "\n");
        }
    }
    if (rt_trace) fprintf(stderr, "[api]   -> %llx\n", (unsigned long long)r);
    if (rt_trace && e->name[0] == 'g' && e->name[1] == 'l') {          /* RECOMP_TRACE: show the geometry of vertex-array draw calls */
        static u32 vptr, vstride, tptr, tstride, vsize;
        if (!strcmp(e->name, "glVertexPointer")) { vsize = a[0]; vstride = a[2]; vptr = a[3]; }
        else if (!strcmp(e->name, "glTexCoordPointer")) { tstride = a[2]; tptr = a[3]; }
        else if (!strcmp(e->name, "glDrawArrays") && a[2] > 0 && vptr > 0x10000 && rt_readable(vptr, 32)) {
            static int stacks;
            if (a[0] == 7 && stacks++ < 2) rt_shadow_dump();      /* who builds the text quads (profile build only) */
            u32 stepv = vstride ? vstride : vsize * 4, stept = tstride ? tstride : 8;
            for (u32 i = 0; i < a[2] && i < 8; ++i) {
                const float *v = (const float *)(uintptr_t)(vptr + (a[1] + i) * stepv);
                const float *t = tptr > 0x10000 ? (const float *)(uintptr_t)(tptr + (a[1] + i) * stept) : NULL;
                fprintf(stderr, "[gl]   vertex %u: %g %g%s", i, v[0], v[1], t ? "" : "\n");
                if (t) fprintf(stderr, "   tex %g %g\n", t[0], t[1]);
            }
        }
    }
    if (rt_trace && !strcmp(e->name, "recv") && (int)r > 0) {      /* show what the servers send (printable bytes only) */
        const unsigned char *d = (const unsigned char *)(uintptr_t)a[1];
        int len = (int)r > 160 ? 160 : (int)r;
        fprintf(stderr, "[recv %d bytes] ", (int)r);
        for (int i = 0; i < len; ++i) fputc(d[i] >= 0x20 && d[i] < 0x7F ? d[i] : '.', stderr);
        fputc('\n', stderr);
    }
    static int netlog = -1;      /* RECOMP_NETLOG=1: only the traffic of the sockets, with the frame count, cheap enough for a full session */
    if (netlog < 0) netlog = getenv("RECOMP_NETLOG") != NULL;
    if (netlog && !rt_trace && (!strcmp(e->name, "send") || !strcmp(e->name, "recv") || !strcmp(e->name, "sendto") ||
                                !strcmp(e->name, "recvfrom")) && (int)r > 0) {
        const unsigned char *d = (const unsigned char *)(uintptr_t)a[1];
        int len = (int)r > 120 ? 120 : (int)r;
        fprintf(stderr, "[net %s %d bytes] ", e->name, (int)r);
        for (int i = 0; i < len; ++i) fputc(d[i] >= 0x20 && d[i] < 0x7F ? d[i] : '.', stderr);
        fputc('\n', stderr);
    }
    static int glinfo = -1;      /* RECOMP_GLINFO=1: driver strings, missing extension functions and the GL call before every GL error */
    if (glinfo < 0) glinfo = getenv("RECOMP_GLINFO") != NULL;
    if (glinfo && e->name[0] == 'g' && e->name[1] == 'l') {
        static const char *last_gl;
        static int shown;
        if (!strcmp(e->name, "glGetString") && r > 0x10000) fprintf(stderr, "[glinfo] glGetString(%x) = %.600s\n", a[0], (const char *)(uintptr_t)r);
        else if (!strcmp(e->name, "glGetError")) { if (r && shown++ < 40) fprintf(stderr, "[glinfo] glGetError = %x after %s\n", (unsigned)r, last_gl ? last_gl : "?"); }
        else {
            if (!strcmp(e->name, "glTexImage2D") && a[1] == 0)          /* texture uploads: internal format, size, pixel format and type */
                fprintf(stderr, "[glinfo] glTexImage2D internal=%x %ux%u format=%x type=%x pixels=%s\n", a[2], a[3], a[4], a[6], a[7], a[8] ? "yes" : "NULL");
            last_gl = e->name;
        }
    }
    r_eax = (u32)r;
    r_edx = (u32)(r >> 32);
    r_esp += 4 + (e->cdecl_ ? 0 : (u32)n * 4);
}

/* the real call with the lock released, for special handlers that adjust arguments */
u64 api_call_real(ApiEnt *e, u32 *a)
{
    ThreadState *ts = rt_thread();
    Cpu keep;
    cpu_save(&keep);
    ts->saved_esp = r_esp;
    ts->in_api++;
    gil_leave();
    u64 r = host_call((void *)e->fn, e->nargs, e->cdecl_, a, e->module && !strcmp(e->module, "MSVCP80") && strstr(e->name, "@@Q"), keep.ecx);
    gil_enter();
    ts->in_api--;
    cpu_load(&keep);
    return r;
}

u32 api_start_thread(u32 fn, u32 param, u32 *a_out, void **out)
{
    GThreadStart *st = (GThreadStart *)malloc(sizeof *st);
    st->fn = fn; st->param = param;
    *out = st;
    (void)a_out;
    return (u32)(uintptr_t)guest_thread_main;
}

/* ---- for the Win32 emulation of non-Windows hosts (recomp/rt/win32/) ---- */
static __thread Cpu blk_cpu[8];
static __thread int blk_depth;

void rt_blocking_begin(void)
{
    ThreadState *ts = rt_thread();
    cpu_save(&blk_cpu[blk_depth++ & 7]);
    ts->saved_esp = r_esp;
    ts->in_api++;
    gil_leave();
}

void rt_blocking_end(void)
{
    gil_enter();
    ThreadState *ts = rt_thread();
    ts->in_api--;
    cpu_load(&blk_cpu[--blk_depth & 7]);
}

u32 rt_guest_callback(u32 fn, int n, const u32 *args)
{
    Cpu keep;
    cpu_save(&keep);
    for (int i = n - 1; i >= 0; --i) { r_esp -= 4; W32(r_esp, args[i]); }
    r_esp -= 4; W32(r_esp, SENT_RET);
    if (rt_trace) fprintf(stderr, "[cb] guest %08x (%d args) first %08x\n", fn, n, n ? args[0] : 0);
    call_ind(fn);
    u32 res = r_eax;
    cpu_load(&keep);
    return res;
}

u32 rt_guest_thread_run(u32 fn, u32 param)
{
    gil_enter();
    ThreadState *ts = rt_thread();
    rt_teb = ts->teb;
    r_esp = ts->stack_top;
    u32 res = gcall(fn, 0, 0, 1, param);
    gil_leave();
    return res;
}
