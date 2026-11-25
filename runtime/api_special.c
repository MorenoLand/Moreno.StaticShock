/* api_special.c: imports whose arguments or results involve guest pointers, so they cannot be forwarded unchanged.
 * Windows only: on other systems every import is emulated (recomp/rt/win32/), and the emulation handles these itself. */
#include "api.h"
#include "project.h"
#include <string.h>
#include <math.h>
#if defined(_WIN32)
#include <commdlg.h>

enum {
    S_NONE, S_GETMODULEHANDLE, S_GETPROCADDRESS, S_LOADLIBRARY, S_REGISTERCLASS, S_REGISTERCLASSEX, S_SETTIMER,
    S_CREATETHREAD, S_SETWINDOWLONG, S_GETWINDOWLONG, S_GETCLASSINFO, S_CALLWINDOWPROC, S_SETUNHANDLED, S_RAISE, S_UNWIND, S_WGLGETPROC, S_DIALOG, S_FLSALLOC, S_GETMODULEFILENAME, S_ENUMWINDOWS, S_ENUMCHILD, S_ENUMTHREAD,
    S_CREATEFILE, S_WRITEFILE, S_CLOSEHANDLE, S_SWAPBUFFERS, S_INITTERM, S_INITTERM_E, S_GETMALLOC, S_QSORT, S_BEGINTHREAD, S_BEGINTHREADEX, S_ENDTHREAD, S_BSEARCH, S_CIPOW, S_SETDIBITS, S_MATHFP,
    S_ENUMFONTEX, S_ENUMFONT, S_FILEDIALOG
};

static const struct { const char *name; int id; } specials[] = {
    {"GetModuleHandleA", S_GETMODULEHANDLE}, {"GetModuleHandleW", S_GETMODULEHANDLE},
    {"GetProcAddress", S_GETPROCADDRESS}, {"LoadLibraryA", S_LOADLIBRARY}, {"LoadLibraryW", S_LOADLIBRARY},
    {"RegisterClassA", S_REGISTERCLASS}, {"RegisterClassExA", S_REGISTERCLASSEX}, {"SetTimer", S_SETTIMER},
    {"CreateThread", S_CREATETHREAD}, {"SetWindowLongA", S_SETWINDOWLONG},
    {"GetWindowLongA", S_GETWINDOWLONG}, {"GetClassInfoA", S_GETCLASSINFO}, {"CallWindowProcA", S_CALLWINDOWPROC},
    {"GetOpenFileNameA", S_FILEDIALOG}, {"GetSaveFileNameA", S_FILEDIALOG},
    {"SetUnhandledExceptionFilter", S_SETUNHANDLED}, {"RaiseException", S_RAISE}, {"RtlUnwind", S_UNWIND}, {"wglGetProcAddress", S_WGLGETPROC}, {"FlsAlloc", S_FLSALLOC}, {"GetModuleFileNameA", S_GETMODULEFILENAME},
    {"EnumWindows", S_ENUMWINDOWS}, {"EnumChildWindows", S_ENUMCHILD}, {"EnumThreadWindows", S_ENUMTHREAD},
    {"EnumFontFamiliesExA", S_ENUMFONTEX}, {"EnumFontFamiliesExW", S_ENUMFONTEX},
    {"EnumFontsA", S_ENUMFONT}, {"EnumFontsW", S_ENUMFONT}, {"EnumFontFamiliesA", S_ENUMFONT}, {"EnumFontFamiliesW", S_ENUMFONT},
    {"EnumDisplayMonitors", S_ENUMFONT},
    {"CreateFileA", S_CREATEFILE}, {"WriteFile", S_WRITEFILE}, {"CloseHandle", S_CLOSEHANDLE}, {"SwapBuffers", S_SWAPBUFFERS}, {"wglSwapBuffers", S_SWAPBUFFERS},
    {"_initterm", S_INITTERM}, {"_initterm_e", S_INITTERM_E},
    {"SHGetMalloc", S_GETMALLOC}, {"qsort", S_QSORT}, {"bsearch", S_BSEARCH}, {"SetDIBitsToDevice", S_SETDIBITS},  {"_CIpow", S_CIPOW}, {"_CIlog", S_CIPOW}, {"_CIexp", S_CIPOW}, {"_CIsqrt", S_CIPOW}, {"_CIsin", S_CIPOW}, {"_CIcos", S_CIPOW}, {"_CItan", S_CIPOW}, {"_CIatan", S_CIPOW}, {"_beginthread", S_BEGINTHREAD}, {"_beginthreadex", S_BEGINTHREADEX}, {"_endthread", S_ENDTHREAD}, {"_endthreadex", S_ENDTHREAD},
    {"ldexp", S_MATHFP}, {"frexp", S_MATHFP}, {"modf", S_MATHFP}, {"fmod", S_MATHFP}, {"atof", S_MATHFP}, {"ceil", S_MATHFP}, {"cos", S_MATHFP}, {"fabs", S_MATHFP}, {"floor", S_MATHFP}, {"log10", S_MATHFP}, {"sin", S_MATHFP}, {"sqrt", S_MATHFP}, {"pow", S_MATHFP}, {"exp", S_MATHFP}, {"log", S_MATHFP}, {"atan2", S_MATHFP},
};

/* The client keeps its own console in game_console.log (downloads, script errors, server messages).  The handle of that file is
 * remembered so that what is written to it also appears on stderr: run the exe from a terminal to follow the game's log live.
 * RECOMP_QUIET_GAMELOG=1 turns the echo off. */
static HANDLE game_log;

static int is_game_log(const char *path)
{
    size_t n = path ? strlen(path) : 0;
    return n >= 16 && !_stricmp(path + n - 16, "game_console.log");
}

/* ---- guest SEH: Delphi frames live on the guest fs:[0] chain, not the host TEB ---- */
#define EH_UNWINDING 2u
#define EH_EXIT_UNWIND 4u
static u32 unhandled_filter;

static u32 scratch(u32 n)
{
    r_esp = (r_esp - n) & ~15u;
    return r_esp;
}

static struct { u32 code, flags, nargs, args[15]; } last_raise;

static u64 seh_raise(u32 code, u32 flags, u32 nargs, u32 args)
{
    u32 save_esp = r_esp;
    u32 rec = scratch(0x50 + 0x2D0 + 0x20);
    u32 ctx = rec + 0x50, disp = ctx + 0x2D0;
    memset((void *)(uintptr_t)rec, 0, 0x50 + 0x2D0 + 0x20);
    W32(rec, code);
    W32(rec + 4, flags);
    W32(rec + 0xC, R32(save_esp));
    if (nargs > 15) nargs = 15;
    W32(rec + 0x10, nargs);
    for (u32 i = 0; i < nargs; ++i) W32(rec + 0x14 + 4 * i, R32(args + 4 * i));
    last_raise.code = code; last_raise.flags = flags; last_raise.nargs = nargs;
    for (u32 i = 0; i < nargs; ++i) last_raise.args[i] = R32(args + 4 * i);
    W32(ctx, 0x10007);                            /* CONTEXT_FULL */
    W32(ctx + 0xB8, R32(save_esp));               /* Eip */
    W32(ctx + 0xC4, save_esp + 4);                /* Esp */
    W32(ctx + 0xB4, r_ebp); W32(ctx + 0xB0, r_eax); W32(ctx + 0xAC, r_ecx); W32(ctx + 0xA8, r_edx); W32(ctx + 0xA4, r_ebx);
    W32(ctx + 0xA0, r_esi); W32(ctx + 0x9C, r_edi);
    u32 frame = R32(rt_teb);
    int guard = 0;
    while (frame != 0xFFFFFFFFu && frame != 0 && guard++ < 10000) {
        u32 next = R32(frame);
        u32 handler = R32(frame + 4);
        if (rt_trace || getenv("RECOMP_EXLOG"))
            fprintf(stderr, "[seh] code %08x: frame %08x handler %08x next %08x\n", code, frame, handler, next);
        u32 res = gcall(handler, 0, 1, 4, rec, frame, ctx, disp);
        if (res == 0) {                           /* ExceptionContinueExecution */
            r_esp = save_esp;
            return 0;
        }
        frame = next;
    }
    if (unhandled_filter) {
        u32 ptrs = rec + 0x50 + 0x2D0;
        W32(ptrs, rec);
        W32(ptrs + 4, ctx);
        u32 res = gcall(unhandled_filter, 0, 0, 1, ptrs);
        if (res == 0xFFFFFFFFu) { r_esp = save_esp; return 0; }
    }
    fprintf(stderr, "unhandled exception %08x at %08x (guest esp %08x)\n", code, R32(save_esp), save_esp);
    fflush(stderr);
    ExitProcess(5);
    return 0;
}

static u64 seh_unwind(u32 target, u32 ip, u32 rec, u32 retval)
{
    (void)ip;
    (void)retval;
    u32 save_esp = r_esp;
    u32 mem = scratch(0x50 + 0x2D0 + 0x20);
    u32 ctx = mem + 0x50, disp = ctx + 0x2D0;
    if (!rec) {
        rec = mem;
        memset((void *)(uintptr_t)rec, 0, 0x50);
        W32(rec, 0xC0000027u);                    /* STATUS_UNWIND */
    }
    memset((void *)(uintptr_t)ctx, 0, 0x2D0 + 0x20);
    W32(rec + 4, R32(rec + 4) | (target ? EH_UNWINDING : (EH_UNWINDING | EH_EXIT_UNWIND)));
    u32 frame = R32(rt_teb);
    int guard = 0;
    while (frame != 0xFFFFFFFFu && frame != 0 && frame != target && guard++ < 10000) {
        u32 next = R32(frame);
        u32 handler = R32(frame + 4);
        if (rt_trace || getenv("RECOMP_EXLOG"))
            fprintf(stderr, "[seh] unwind: frame %08x handler %08x next %08x\n", frame, handler, next);
        gcall(handler, 0, 1, 4, rec, frame, ctx, disp);
        W32(rt_teb, next);
        frame = next;
    }
    W32(rt_teb, frame);
    r_esp = save_esp;
    return 0;
}

void rt_reraise(void)
{
    u32 frame = R32(rt_teb);
    if (frame != 0xFFFFFFFFu && frame != 0)
        W32(rt_teb, R32(frame));
    u32 args = scratch(16 * 4);
    for (u32 i = 0; i < last_raise.nargs; ++i) W32(args + 4 * i, last_raise.args[i]);
    seh_raise(last_raise.code, last_raise.flags, last_raise.nargs, args);
}

int api_special_id(const char *name)
{
    for (size_t i = 0; i < sizeof specials / sizeof *specials; ++i)
        if (!strcmp(specials[i].name, name)) return specials[i].id;
    return 0;
}

/* a function pointer a guest passes to Windows becomes a host-callable trampoline (or the real function when it is an API) */
static u32 wndproc(u32 guest)
{
    return rt_tramp(guest, 4);
}

typedef struct { u32 fn, param; } GuestThread;
static DWORD WINAPI guest_thread_entry(LPVOID p)
{
    GuestThread *t = (GuestThread *)p;
    u32 r = rt_guest_thread_run(t->fn, t->param);
    free(t);
    return r;
}

static u32 __stdcall imalloc_stub(void *a)
{
    (void)a;
    return 0;
}

/* wrap a real function pointer returned to the guest so that guest code can call it (stdcall, nargs known by name) */
static u32 wrap_host_fn(const char *module, const char *name, FARPROC fn)
{
    int n = name_nargs(name);
    u32 s = api_add(module, _strdup(name), fn, n, 0);
    api_tab[(s - 0xFE000000u) >> 4].special = api_special_id(name);      /* e.g. FlsAlloc takes a guest callback */
    return s;
}

/* RECOMP_SNAPFRAMES=300,900 RECOMP_SNAPFILE=snap.bmp: write what the client has drawn to a .bmp (name gets the frame number) just before the
 * given buffer swaps: a way to look at the rendering without looking at the screen (compare builds, find missing graphics). */
static void snapshot(HDC dc, int frame)
{
    HWND w = WindowFromDC(dc);
    RECT rc;
    if (!w || !GetClientRect(w, &rc)) return;
    int width = rc.right - rc.left, height = rc.bottom - rc.top;
    if (width <= 0 || height <= 0) return;
    HMODULE gl = GetModuleHandleA("opengl32.dll");
    if (!gl) return;
    typedef void (WINAPI *ReadPixelsFn)(int, int, int, int, unsigned, unsigned, void *);
    typedef void (WINAPI *EnumFn)(unsigned);
    typedef void (WINAPI *PixelStoreFn)(unsigned, int);
    ReadPixelsFn read_pixels = (ReadPixelsFn)GetProcAddress(gl, "glReadPixels");
    EnumFn read_buffer = (EnumFn)GetProcAddress(gl, "glReadBuffer");
    PixelStoreFn pixel_store = (PixelStoreFn)GetProcAddress(gl, "glPixelStorei");
    if (!read_pixels || !read_buffer || !pixel_store) return;
    size_t stride = ((size_t)width * 3 + 3) & ~(size_t)3;
    unsigned char *px = (unsigned char *)malloc(stride * (size_t)height);
    if (!px) return;
    pixel_store(0x0D05, 4);                  /* GL_PACK_ALIGNMENT */
    read_buffer(0x0405);                     /* GL_BACK */
    read_pixels(0, 0, width, height, 0x80E0, 0x1401, px);      /* GL_BGR_EXT, GL_UNSIGNED_BYTE: bottom row first, like a .bmp */
    const char *base = getenv("RECOMP_SNAPFILE");
    char name[512];
    if (!base) base = "snap.bmp";
    const char *dot = strrchr(base, '.');
    snprintf(name, sizeof name, "%.*s-%d%s", dot ? (int)(dot - base) : (int)strlen(base), base, frame, dot ? dot : ".bmp");
    FILE *f = fopen(name, "wb");
    if (f) {
        unsigned char hdr[54] = {'B', 'M'};
        u32 size = (u32)(54 + stride * (size_t)height);
        memcpy(hdr + 2, &size, 4);
        u32 off = 54, dib = 40, planes_bpp = 0x180001, zero = 0, img = (u32)(stride * (size_t)height);
        memcpy(hdr + 10, &off, 4); memcpy(hdr + 14, &dib, 4); memcpy(hdr + 18, &width, 4); memcpy(hdr + 22, &height, 4);
        memcpy(hdr + 26, &planes_bpp, 4); memcpy(hdr + 30, &zero, 4); memcpy(hdr + 34, &img, 4);
        fwrite(hdr, 1, 54, f);
        fwrite(px, 1, stride * (size_t)height, f);
        fclose(f);
        fprintf(stderr, "[snap] frame %d written to %s (%dx%d)\n", frame, name, width, height);
    }
    free(px);
}

static int snapshot_wanted(int frame)
{
    static const char *list = (const char *)1;
    if (list == (const char *)1) list = getenv("RECOMP_SNAPFRAMES");
    if (!list) return 0;
    for (const char *p = list; *p;) {
        char *end;
        long v = strtol(p, &end, 10);
        if (end == p) break;
        if (v == frame) return 1;
        p = *end == ',' ? end + 1 : end;
    }
    return 0;
}

u64 api_special(int id, ApiEnt *e, u32 *a)
{
    switch (id) {
    case S_GETMODULEHANDLE:
        if (a[0] == 0) return SS_IMAGE_BASE;                 /* the guest's own image */
        return api_call_real(e, a);
    case S_CREATEFILE: {
        u64 r = api_call_real(e, a);
        if (r != (u64)(uintptr_t)INVALID_HANDLE_VALUE && is_game_log((const char *)(uintptr_t)a[0]) && !getenv("RECOMP_QUIET_GAMELOG"))
            game_log = (HANDLE)(uintptr_t)r;
        return r;
    }
    case S_SWAPBUFFERS: {
        static int frame;
        ++frame;
        if (snapshot_wanted(frame)) snapshot((HDC)(uintptr_t)a[0], frame);
        return api_call_real(e, a);
    }
    case S_CLOSEHANDLE:
        if ((HANDLE)(uintptr_t)a[0] == game_log) game_log = NULL;     /* the number can be handed out again to any other file */
        return api_call_real(e, a);
    case S_WRITEFILE: {
        u64 r = api_call_real(e, a);
        if (r && game_log && (HANDLE)(uintptr_t)a[0] == game_log && a[1] && a[2]) {
            fwrite((const void *)(uintptr_t)a[1], 1, a[2], stderr);
            fflush(stderr);
        }
        return r;
    }
    case S_GETPROCADDRESS: {
        if ((a[1] >> 16) == 0) {                       /* by ordinal: no name to look the argument count up by */
            u64 r = api_call_real(e, a);
            return r ? wrap_host_fn("?", "ordinal", (FARPROC)(uintptr_t)r) : 0;
        }
        const char *nm = (const char *)(uintptr_t)a[1];
        u64 r = api_call_real(e, a);
        if (!r) return 0;
        return wrap_host_fn("dynamic", nm, (FARPROC)(uintptr_t)r);
    }
    case S_WGLGETPROC: {
        const char *nm = (const char *)(uintptr_t)a[0];
        u64 r = api_call_real(e, a);
        if (getenv("RECOMP_GLINFO")) fprintf(stderr, "[glinfo] wglGetProcAddress(%s) -> %s\n", nm, r ? "found" : "NULL");
        if (!r) return 0;
        return wrap_host_fn("opengl32", nm, (FARPROC)(uintptr_t)r);
    }
    case S_LOADLIBRARY: {
        const char *nm = (const char *)(uintptr_t)a[0];
        if (nm && (!_stricmp(nm, "d3d9.dll") || !_stricmp(nm, "d3d9"))) {   /* host COM objects cannot be called from guest code */
            SetLastError(126);
            return 0;
        }
        return api_call_real(e, a);
    }
    case S_REGISTERCLASS: {
        WNDCLASSA wc;
        memcpy(&wc, (void *)(uintptr_t)a[0], sizeof wc);
        wc.lpfnWndProc = (WNDPROC)(uintptr_t)wndproc((u32)(uintptr_t)wc.lpfnWndProc);
        u32 b[1] = { (u32)(uintptr_t)&wc };
        return api_call_real(e, b);
    }
    case S_REGISTERCLASSEX: {
        WNDCLASSEXA wc;
        memcpy(&wc, (void *)(uintptr_t)a[0], sizeof wc);
        wc.lpfnWndProc = (WNDPROC)(uintptr_t)wndproc((u32)(uintptr_t)wc.lpfnWndProc);
        u32 b[1] = { (u32)(uintptr_t)&wc };
        return api_call_real(e, b);
    }
    case S_SETTIMER: {
        u32 b[4] = { a[0], a[1], a[2], a[3] ? rt_tramp(a[3], 4) : 0 };
        return api_call_real(e, b);
    }
    case S_SETWINDOWLONG: {
        u32 b[3] = { a[0], a[1], a[2] };
        if ((int)a[1] == -4) b[2] = wndproc(a[2]);
        u64 r = api_call_real(e, b);
        return (int)a[1] == -4 ? rt_tramp_guest((u32)r) : r;
    }
    case S_GETWINDOWLONG: {
        u64 r = api_call_real(e, a);
        return (int)a[1] == -4 ? rt_tramp_guest((u32)r) : r;
    }
    case S_GETCLASSINFO: {
        u64 r = api_call_real(e, a);
        if (r) {
            WNDCLASSA wc;
            memcpy(&wc, (void *)(uintptr_t)a[2], sizeof wc);
            wc.lpfnWndProc = (WNDPROC)(uintptr_t)rt_tramp_guest((u32)(uintptr_t)wc.lpfnWndProc);
            memcpy((void *)(uintptr_t)a[2], &wc, sizeof wc);
        }
        return r;
    }
    case S_CALLWINDOWPROC: {
        u32 b[5] = { a[0], a[1], a[2], a[3], a[4] };
        if ((b[0] >= SS_IMAGE_BASE && b[0] < SS_IMAGE_END) || rt_is_thunk(b[0])) b[0] = wndproc(b[0]);
        return api_call_real(e, b);
    }
    case S_FILEDIALOG: {
        OPENFILENAMEA ofn;
        memcpy(&ofn, (void *)(uintptr_t)a[0], sizeof ofn);
        if (ofn.lpfnHook) ofn.lpfnHook = (LPOFNHOOKPROC)(uintptr_t)rt_tramp((u32)(uintptr_t)ofn.lpfnHook, 4);
        u32 b[1] = { (u32)(uintptr_t)&ofn };
        return api_call_real(e, b);
    }
    case S_CREATETHREAD: {
        void *ctx;
        u32 entry = api_start_thread(a[2], a[3], NULL, &ctx);
        u32 b[6] = { a[0], a[1], entry, (u32)(uintptr_t)ctx, a[4], a[5] };
        return api_call_real(e, b);
    }
    case S_GETMODULEFILENAME: {
        if (a[0] != 0) return api_call_real(e, a);
        /* the client finds its own folder from this name: report the original exe, not the host executable */
        char *dst = (char *)(uintptr_t)a[1];
        size_t len = strlen(rt_guest_exe);
        if (len >= a[2]) len = a[2] ? a[2] - 1 : 0;
        if (a[2]) { memcpy(dst, rt_guest_exe, len); dst[len] = 0; }
        return len;
    }
    case S_ENUMFONTEX: {                  /* BOOL CALLBACK proc(const LOGFONT *, const TEXTMETRIC *, DWORD, LPARAM) */
        u32 b[5] = { a[0], a[1], a[2] ? rt_tramp(a[2], 4) : 0, a[3], a[4] };
        return api_call_real(e, b);
    }
    case S_ENUMFONT: {                    /* BOOL CALLBACK proc(const ENUMLOGFONT *, const NEWTEXTMETRIC *, int, LPARAM) */
        u32 b[4] = { a[0], a[1], a[2] ? rt_tramp(a[2], 4) : 0, a[3] };
        return api_call_real(e, b);
    }
    case S_ENUMWINDOWS: {                                /* BOOL CALLBACK proc(HWND, LPARAM): the host calls it, so it needs a trampoline */
        u32 b[2] = { rt_tramp(a[0], 2), a[1] };
        return api_call_real(e, b);
    }
    case S_ENUMCHILD:
    case S_ENUMTHREAD: {
        u32 b[3] = { a[0], rt_tramp(a[1], 2), a[2] };
        return api_call_real(e, b);
    }
    case S_FLSALLOC: {
        u32 b[1] = { a[0] ? rt_tramp(a[0], 1) : 0 };    /* the destructor callback runs on host threads */
        return api_call_real(e, b);
    }
    case S_SETUNHANDLED: {
        u32 old = unhandled_filter;
        unhandled_filter = a[0];
        return old;
    }
    case S_RAISE:
        return seh_raise(a[0], a[1], a[2], a[3]);
    case S_UNWIND:
        return seh_unwind(a[0], a[1], a[2], a[3]);
    case S_INITTERM:
    case S_INITTERM_E: {
        for (u32 p = a[0]; p < a[1]; p += 4) {
            u32 fn = R32(p);
            if (fn) call_ind(fn);                        /* the guest's static initialisers run through the lifter */
        }
        return 0;
    }
    case S_BEGINTHREADEX:
    case S_BEGINTHREAD: {
        GuestThread *t = (GuestThread *)malloc(sizeof *t);
        DWORD tid = 0;
        t->fn = id == S_BEGINTHREADEX ? a[2] : a[0];
        t->param = id == S_BEGINTHREADEX ? a[3] : a[2];
        HANDLE h = CreateThread(NULL, 0, guest_thread_entry, t, 0, &tid);
        if (id == S_BEGINTHREADEX) {
            if (a[5]) *(u32 *)(uintptr_t)a[5] = tid;
            return (u64)(uintptr_t)h;
        }
        return (u64)(uintptr_t)(h ? 1 : 0);
    }
    case S_ENDTHREAD:
        ExitThread(0);
        return 0;
    case S_SETDIBITS: {
        static u32 canvas_bits;
        static int canvas_w, canvas_h;
        HDC hdc = (HDC)(uintptr_t)a[0];
        const BITMAPINFO *bmi = (const BITMAPINFO *)(uintptr_t)a[10];
        int bh = bmi ? bmi->bmiHeader.biHeight : 0;
        if (bh < 0) bh = -bh;
        int bw = bmi ? bmi->bmiHeader.biWidth : 0;
        if (bmi && bh > 0 && bw > 0) {
            int full = a[5] == 0 && a[6] == 0 && a[7] == 0 && (int)a[3] == bw && (int)a[4] == bh && (int)a[8] == bh;
            if (full) {
                canvas_bits = a[9];
                canvas_w = bw;
                canvas_h = bh;
            }
            HWND w = hdc ? WindowFromDC(hdc) : NULL;
            RECT rc;
            if (canvas_bits && w && GetClientRect(w, &rc) && rc.right > 0 && rc.bottom > 0) {
                SetStretchBltMode(hdc, COLORONCOLOR);
                int r = StretchDIBits(hdc, 0, 0, rc.right, rc.bottom, 0, 0, canvas_w, canvas_h,
                                      (const void *)(uintptr_t)canvas_bits, bmi, a[11], SRCCOPY);
                if (r) return r;
            }
        }
        return api_call_real(e, a);
    }
    case S_MATHFP: {
        double d0, d1, r;
        memcpy(&d0, a, 8);
        memcpy(&d1, a + 2, 8);
        if (!strcmp(e->name, "ldexp")) r = ldexp(d0, (int)a[2]);
        else if (!strcmp(e->name, "frexp")) { int ex; r = frexp(d0, &ex); W32(a[2], (u32)ex); }
        else if (!strcmp(e->name, "modf")) { double ip; r = modf(d0, &ip); W_F64(a[2], ip); }
        else if (!strcmp(e->name, "fmod")) r = fmod(d0, d1);
        else if (!strcmp(e->name, "pow")) r = pow(d0, d1);
        else if (!strcmp(e->name, "atan2")) r = atan2(d0, d1);
        else if (!strcmp(e->name, "atof")) r = atof((const char *)(uintptr_t)a[0]);
        else if (!strcmp(e->name, "ceil")) r = ceil(d0);
        else if (!strcmp(e->name, "cos")) r = cos(d0);
        else if (!strcmp(e->name, "exp")) r = exp(d0);
        else if (!strcmp(e->name, "fabs")) r = fabs(d0);
        else if (!strcmp(e->name, "floor")) r = floor(d0);
        else if (!strcmp(e->name, "log")) r = log(d0);
        else if (!strcmp(e->name, "log10")) r = log10(d0);
        else if (!strcmp(e->name, "sin")) r = sin(d0);
        else r = sqrt(d0);
        FPUSH(r);
        return 0;
    }
    case S_CIPOW: {
        long double x = ST(0), y = ST(1), r;
        if (!strcmp(e->name, "_CIpow")) r = powl(y, x);
        else if (!strcmp(e->name, "_CIlog")) r = logl(x);
        else if (!strcmp(e->name, "_CIexp")) r = expl(x);
        else if (!strcmp(e->name, "_CIsqrt")) r = sqrtl(x);
        else if (!strcmp(e->name, "_CIsin")) r = sinl(x);
        else if (!strcmp(e->name, "_CIcos")) r = cosl(x);
        else if (!strcmp(e->name, "_CItan")) r = tanl(x);
        else r = atanl(x);
        if (!strcmp(e->name, "_CIpow")) FPOP();
        FPOP();
        FPUSH(r);
        return 0;
    }
    case S_BSEARCH: {
        u32 key = a[0], base = a[1], num = a[2], width = a[3], cmp = a[4];
        u32 lo = 0, hi = num;
        while (lo < hi) {
            u32 mid = lo + (hi - lo) / 2;
            u32 cargs[2];
            cargs[0] = key;
            cargs[1] = base + mid * width;
            int c = (int)rt_guest_callback(cmp, 2, cargs);
            if (c == 0) return cargs[1];
            if (c < 0) hi = mid;
            else lo = mid + 1;
        }
        return 0;
    }
    case S_QSORT: {
        u32 base = a[0], n = a[1], sz = a[2], cmp = a[3];
        char *tmp = (char *)malloc(sz ? sz : 1);
        if (!tmp) return 0;
        for (u32 i = 1; i < n; ++i) {
            memcpy(tmp, (void *)(uintptr_t)(base + i * sz), sz);
            u32 j = i;
            while (j > 0) {
                u32 cargs[2];
                cargs[0] = base + (j - 1) * sz;
                cargs[1] = (u32)(uintptr_t)tmp;
                if ((int)rt_guest_callback(cmp, 2, cargs) <= 0) break;
                memcpy((void *)(uintptr_t)(base + j * sz), (void *)(uintptr_t)(base + (j - 1) * sz), sz);
                --j;
            }
            memcpy((void *)(uintptr_t)(base + j * sz), tmp, sz);
        }
        free(tmp);
        return 0;
    }
    case S_GETMALLOC: {
        static u32 obj, vt;
        if (!obj) {
            vt = (u32)(uintptr_t)malloc(6 * 4);
            for (int i = 0; i < 6; ++i) ((u32 *)(uintptr_t)vt)[i] = api_add("shim", "imalloc", (FARPROC)imalloc_stub, 1, 0);
            obj = (u32)(uintptr_t)malloc(4);
            ((u32 *)(uintptr_t)obj)[0] = vt;
        }
        if (a[0]) *(u32 *)(uintptr_t)a[0] = obj;
        return 0;
    }
    }
    return 0;
}
#endif
