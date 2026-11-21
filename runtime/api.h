/* api.h: shared declarations of the API bridge (api.c, api_special.c, boot.c, and the Win32 emulation in win32/). */
#ifndef API_H
#define API_H
#include "rt.h"
#include <stdarg.h>
#if defined(_WIN32)
#include <windows.h>
#else
typedef void *FARPROC;                  /* a native function of a host library (OpenGL, GLU) */
#ifndef MAX_PATH
#define MAX_PATH 260
#endif
#endif

/* an emulated import (non-Windows hosts, recomp/rt/win32/): reads its arguments from a, returns eax (low) and edx (high).
 * It runs with the guest lock held; one that blocks releases it with rt_blocking_begin()/rt_blocking_end(). */
typedef u64 (*ApiEmu)(u32 *a);

typedef struct {
    const char *module;
    const char *name;
    FARPROC fn;      /* the real function (Windows: every import; other hosts: native OpenGL / GLU functions) */
    int nargs;       /* argument count; -1 when unknown */
    int cdecl_;      /* the guest's convention: 1 = the caller removes the arguments */
    int special;     /* nonzero: handled by api_special() (Windows) */
    ApiEmu emu;      /* non-Windows hosts: the emulation of a Win32 function */
    int host_cdecl;  /* fn is a cdecl function although the guest calls it as stdcall (OpenGL outside Windows) */
} ApiEnt;

typedef struct { u32 ea; const char *module; const char *name; int nargs; int cdecl_; } ApiStatic;
typedef struct { const char *name; int nargs; } NameArgs;

extern ApiEnt api_tab[];
extern int api_count;
extern int rt_trace;
extern char rt_guest_exe[MAX_PATH];     /* full path of the original exe as the guest sees it (GetModuleFileName) */
extern u32 rt_teb;
extern const ApiStatic api_static[];
extern const int api_static_n;
extern const NameArgs name_args[];       /* GL and similar names looked up with GetProcAddress */
extern const int name_args_n;

void api_dispatch(u32 sentinel);
u32 api_add(const char *module, const char *name, FARPROC fn, int nargs, int cdecl_);
u64 api_call_real(ApiEnt *e, u32 *a);
u64 api_special(int id, ApiEnt *e, u32 *a);
int api_special_id(const char *name);
u32 api_start_thread(u32 fn, u32 param, u32 *a_out, void **out);
u32 rt_tramp(u32 guest, int nargs);
void gil_init(void);
u32 rt_new_teb(u32 stack_lo, u32 stack_top);
void rt_main_thread(u32 lo, u32 top);
int name_nargs(const char *name);

/* used by the Win32 emulation (non-Windows hosts) */
u32 api_add_emu(const char *module, const char *name, ApiEmu emu, int nargs, int cdecl_);
void rt_blocking_begin(void);            /* release the guest lock around a call that may block; guest registers are kept */
void rt_blocking_end(void);
u32 rt_guest_callback(u32 fn, int n, const u32 *args);    /* call a guest function (window procedure, thread entry) from an emulated API */
u32 rt_guest_thread_run(u32 fn, u32 param);              /* on a new host thread: take the lock, run the guest thread function fn(param) on its own stack, return its result */
u32 *rt_tls_slots(void);                 /* the TlsAlloc slots of the calling thread (W32_TLS_SLOTS words) */
u32 *rt_last_error(void);                /* the calling thread's GetLastError value */
#define W32_TLS_SLOTS 128
#endif
