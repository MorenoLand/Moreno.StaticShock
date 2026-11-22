/* api.c: import sentinel dispatch and guest callbacks for the wasm host. */
#include "api.h"
#include "wasm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define API_BASE 0xFE000000u
#define MAX_API 8192
#define SENT_RET 0xDEAD0000u

ApiEnt api_tab[MAX_API];
int api_count;
int rt_trace;
unsigned api_call_count[MAX_API];
ApiEnt *wasm_current;
u32 wasm_current_ecx;
char rt_guest_exe[MAX_PATH];

typedef struct {
    u32 saved_esp;
    int in_api;
    u32 stack_lo, stack_top, teb;
    u32 last_error;
    u32 tls[W32_TLS_SLOTS];
} ThreadState;

static ThreadState main_thread;

void gil_init(void) {}
void rt_blocking_begin(void) {}
void rt_blocking_end(void) {}

u32 *rt_tls_slots(void) { return main_thread.tls; }
u32 *rt_last_error(void) { return &main_thread.last_error; }
ThreadState *rt_thread(void) { return &main_thread; }

u32 rt_new_teb(u32 stack_lo, u32 stack_top)
{
    u32 t = (u32)(uintptr_t)calloc(1, 0x1000);
    W32(t + 0, 0xFFFFFFFFu);
    W32(t + 4, stack_top);
    W32(t + 8, stack_lo);
    W32(t + 0x18, t);
    W32(t + 0x20, 0x1000);
    return t;
}

void rt_main_thread(u32 lo, u32 top)
{
    main_thread.stack_lo = lo;
    main_thread.stack_top = top;
    main_thread.teb = rt_new_teb(lo, top);
    rt_teb = main_thread.teb;
    r_esp = top;
}

u32 api_add(const char *module, const char *name, FARPROC fn, int nargs, int cdecl_)
{
    if (api_count >= MAX_API) {
        fprintf(stderr, "api table full\n");
        exit(5);
    }
    int i = api_count++;
    ApiEnt *e = &api_tab[i];
    e->module = module;
    e->name = name;
    e->fn = fn;
    e->nargs = nargs;
    e->cdecl_ = cdecl_ ? 1 : 0;
    e->special = 0;
    e->emu = NULL;
    e->host_cdecl = 0;
    return API_BASE + (u32)i * 16;
}

u32 api_add_emu(const char *module, const char *name, ApiEmu emu, int nargs, int cdecl_)
{
    u32 s = api_add(module, name, NULL, nargs, cdecl_);
    api_tab[(s - API_BASE) >> 4].emu = emu;
    return s;
}

static int cmp_name(const void *k, const void *e)
{
    return strcmp((const char *)k, ((const NameArgs *)e)->name);
}

int name_nargs(const char *name)
{
    const NameArgs *e = bsearch(name, name_args, (size_t)name_args_n, sizeof(NameArgs), cmp_name);
    return e ? e->nargs : -1;
}

void api_dispatch(u32 sentinel)
{
    int idx = (int)((sentinel - API_BASE) >> 4);
    if (idx < 0 || idx >= api_count) {
        fprintf(stderr, "wasm: bad import sentinel %08x\n", sentinel);
        abort();
    }
    ApiEnt *e = &api_tab[idx];
    ++api_call_count[idx];
    if (e->nargs < 0) {
        fprintf(stderr, "wasm: %s!%s has no argument count (guest esp %08x)\n", e->module, e->name, r_esp);
        exit(6);
    }
    u32 a[32];
    u32 *sp = (u32 *)(uintptr_t)(r_esp + 4);
    int n = e->cdecl_ ? 16 : e->nargs;
    if (n > 32) n = 32;
    for (int i = 0; i < n; ++i) a[i] = sp[i];
    for (int i = n; i < 32; ++i) a[i] = 0;
    if (rt_trace) {
        fprintf(stderr, "[wasm api] %s!%s(", e->module, e->name);
        for (int i = 0; i < e->nargs && i < 6; ++i) fprintf(stderr, "%s%x", i ? ", " : "", a[i]);
        fprintf(stderr, ")\n");
    }
    u64 r = 0;
    if (e->special) r = api_special(e->special, e, a);
    else if (e->emu) { wasm_current = e; wasm_current_ecx = r_ecx; r = e->emu(a); }
    r_eax = (u32)r;
    r_edx = (u32)(r >> 32);
    r_esp += 4 + (e->cdecl_ ? 0 : (u32)e->nargs * 4);
}

u64 api_call_real(ApiEnt *e, u32 *a)
{
    if (!e->emu) return 0;
    wasm_current = e;
    return e->emu(a);
}

u32 gcall(u32 addr, u32 ecx_value, int cdecl_, int n, ...)
{
    va_list ap;
    u32 args[16];
    va_start(ap, n);
    for (int i = 0; i < n; ++i) args[i] = va_arg(ap, u32);
    va_end(ap);
    u32 start = r_esp;
    for (int i = n - 1; i >= 0; --i) {
        r_esp -= 4;
        W32(r_esp, args[i]);
    }
    r_esp -= 4;
    W32(r_esp, SENT_RET);
    r_ecx = ecx_value;
    call_ind(addr);
    if (cdecl_) r_esp += 4 * n;
    r_esp = start;
    return r_eax;
}

u32 rt_guest_callback(u32 fn, int n, const u32 *args)
{
    ThreadState *ts = rt_thread();
    u32 keep[8] = { r_eax, r_ecx, r_edx, r_ebx, r_esp, r_ebp, r_esi, r_edi };
    u32 keep_teb = rt_teb;
    r_esp = ts->in_api ? ts->saved_esp - 0x100 : ts->stack_top;
    rt_teb = ts->teb;
    for (int i = n - 1; i >= 0; --i) {
        r_esp -= 4;
        W32(r_esp, args[i]);
    }
    r_esp -= 4;
    W32(r_esp, SENT_RET);
    call_ind(fn);
    u32 result = r_eax;
    r_eax = keep[0]; r_ecx = keep[1]; r_edx = keep[2]; r_ebx = keep[3];
    r_esp = keep[4]; r_ebp = keep[5]; r_esi = keep[6]; r_edi = keep[7];
    rt_teb = keep_teb;
    return result;
}

u32 rt_tramp(u32 guest, int nargs)
{
    (void)nargs;
    return guest;
}

u32 rt_guest_thread_run(u32 fn, u32 param)
{
    return rt_guest_callback(fn, 1, &param);
}
