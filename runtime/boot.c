/* boot.c: host entry point.  Maps the original image, fills the IAT with API sentinels, then runs the original
 * entry point (the C runtime start-up, which calls WinMain).  RECOMP_TRACE=1 logs every API call.
 * usage: recomp [game folder]   (the folder that holds the original executable, DLLs and game data; default: current folder)
 *
 * On Windows the imports are bound to the real DLLs.  On other systems (Linux, macOS) they are bound to the emulation of
 * the Win32 functions in recomp/rt/win32/ (w32_lookup), and the client's folder is shown to the guest as a Windows path
 * on drive Z: (Z:\home\me\game), the way Wine does it. */
#if !defined(_WIN32)
#define _GNU_SOURCE                      /* REG_EIP in the crash report */
#endif
#include "api.h"
#include "project.h"
#include "sys.h"
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <psapi.h>
#endif
#if !defined(_WIN32)
#include "win32/w32.h"
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#if defined(__linux__)
#include <ucontext.h>
#endif
#endif

int rt_load_image(const char *path);
char rt_guest_exe[MAX_PATH];
#define OEP SS_OEP

static int cmp_name(const void *k, const void *e)
{
    return strcmp((const char *)k, ((const NameArgs *)e)->name);
}

int name_nargs(const char *name)
{
    const NameArgs *e = bsearch(name, name_args, (size_t)name_args_n, sizeof(NameArgs), cmp_name);
    return e ? e->nargs : -1;
}

#if defined(_WIN32)
static LONG WINAPI on_crash(EXCEPTION_POINTERS *e)
{
    fprintf(stderr, "CRASH code %08lx at host %p, access %s %p, guest esp %08x eax %08x ecx %08x ebp %08x esi %08x edi %08x edx %08x ebx %08x\n",
            (unsigned long)e->ExceptionRecord->ExceptionCode, e->ExceptionRecord->ExceptionAddress,
            e->ExceptionRecord->NumberParameters > 0 && e->ExceptionRecord->ExceptionInformation[0] ? "write" : "read",
            e->ExceptionRecord->NumberParameters > 1 ? (void *)e->ExceptionRecord->ExceptionInformation[1] : NULL,
            r_esp, r_eax, r_ecx, r_ebp, r_esi, r_edi, r_edx, r_ebx);
    /* the address in bin/lift.map is the host address relative to the linked image base 0x10000000 */
    fprintf(stderr, "      map address %08lx (look it up in bin/lift.map)\n",
            0x10000000ul + (unsigned long)((char *)e->ExceptionRecord->ExceptionAddress - (char *)GetModuleHandleA(NULL)));
    /* likely return addresses on the guest stack (words that point into the code and follow a call instruction) */
    fprintf(stderr, "      guest stack, code addresses:");
    int shown = 0;
    for (u32 p = r_esp; p < r_esp + 0x400 && shown < 14 && !IsBadReadPtr((void *)(uintptr_t)p, 4); p += 4) {
        u32 v = R32(p);
        if (v >= SS_CODE_LO + 5 && v < SS_CODE_HI && !IsBadReadPtr((void *)(uintptr_t)(v - 5), 5) &&
            (R8(v - 5) == 0xE8 || R8(v - 6) == 0xFF || R8(v - 2) == 0xFF || R8(v - 3) == 0xFF)) {
            fprintf(stderr, " %08x", v);
            ++shown;
        }
    }
    fprintf(stderr, "\n");
    /* the host stack holds the real chain of calls (the guest stack does not: calls between lifted functions push no return address): words that point into this
     * program's code and follow a call instruction, as addresses of bin/lift.map (addr2line -f -e the host executable <address>) */
    {
        const char *base = (const char *)GetModuleHandleA(NULL);
        const unsigned char *lo = (const unsigned char *)base + 0x1000;
        const unsigned char *hi = (const unsigned char *)base + 0x1000 + 0x900000;
        const unsigned char **sp = (const unsigned char **)(uintptr_t)e->ContextRecord->Esp;
        int n = 0;
        fprintf(stderr, "      host stack, calls:");
        for (int i = 0; i < 512 && n < 24 && !IsBadReadPtr(sp + i, sizeof *sp); ++i) {
            const unsigned char *v = sp[i];
            if (v > lo + 6 && v < hi && !IsBadReadPtr(v - 6, 6) && (v[-5] == 0xE8 || v[-6] == 0xFF || v[-2] == 0xFF || v[-3] == 0xFF)) {
                fprintf(stderr, " %08lx", 0x10000000ul + (unsigned long)(v - (const unsigned char *)base));
                ++n;
            }
        }
        fprintf(stderr, "\n");
    }
    rt_shadow_dump();
    fflush(stderr);
    ExitProcess(4);
    return EXCEPTION_EXECUTE_HANDLER;
}

static int respawn(int argc, char **argv)
{
    /* the loader's randomised allocations can land inside the guest range: start again in a fresh process */
    char *tries = getenv("RECOMP_TRIES");
    int n = tries ? atoi(tries) : 0;
    if (n > 30) {
        fprintf(stderr, "cannot reserve the guest address range\n");
        return 77;
    }
    char buf[16];
    sprintf(buf, "%d", n + 1);
    SetEnvironmentVariableA("RECOMP_TRIES", buf);
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    char cmd[2048];
    cmd[0] = 0;
    for (int i = 0; i < argc; ++i) {
        strcat(cmd, "\"");
        strcat(cmd, argv[i]);
        strcat(cmd, "\" ");
    }
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) return 78;
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    return (int)code;
}

int main(int argc, char **argv)
{
    /* the original image is embedded in this exe (scripts/build.sh); the argument is only the client's data folder
     * (levels, sounds, config, fmod.dll), default the current folder */
    rt_trace = getenv("RECOMP_TRACE") != NULL;
    const char *watch = getenv("RECOMP_WATCH");      /* RECOMP_WATCH=lo-hi (hex): report writes into that range (watch.exe, built with -DRT_WATCH) */
    if (watch) { char *end; rt_watch_lo = (u32)strtoul(watch, &end, 16); if (*end == '-') rt_watch_hi = (u32)strtoul(end + 1, NULL, 16); }
    /* The message loop waits 1 ms for input each turn (Win_processMessages, MsgWaitForMultipleObjects).  Windows rounds such a wait up to its timer tick, about
     * 15.6 ms, unless a program asks for a finer one, and then every turn of the loop costs 15 ms of idling: the game ran at most about 60 turns a second whatever
     * it had to do, and a busy server made it lag.  One millisecond restores what the wait was meant to be. */
    {
        HMODULE winmm = LoadLibraryA("winmm.dll");
        unsigned (__stdcall *begin)(unsigned) = winmm ? (unsigned (__stdcall *)(unsigned))GetProcAddress(winmm, "timeBeginPeriod") : NULL;
        if (begin) begin(1);
    }
    SetUnhandledExceptionFilter(on_crash);
    /* RECOMP_IMAGE=<exe> maps the original exe instead of the embedded data image (comparison runs when something looks wrong) */
    if (!rt_load_image(getenv("RECOMP_IMAGE"))) {
        const char *try_env = getenv("SS_TRY");
        int attempt = try_env ? atoi(try_env) : 0;
        if (attempt < 16) {
            char buf[16];
            sprintf(buf, "%d", attempt + 1);
            SetEnvironmentVariableA("SS_TRY", buf);
            return respawn(argc, argv);
        }
        return 3;
    }

    char dir[MAX_PATH];
    if (argc >= 2) {
        if (!GetFullPathNameA(argv[1], sizeof dir, dir, NULL)) return 2;
    } else {
        if (!GetModuleFileNameA(NULL, dir, sizeof dir)) return 2;
        char *slash = strrchr(dir, '\\');
        if (slash) *slash = 0;
        char own[MAX_PATH];
        snprintf(own, sizeof own, "%s\\data", dir);
        DWORD a = GetFileAttributesA(own);
        if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) snprintf(dir, sizeof dir, "%s", own);
        else if (!GetFullPathNameA(".", sizeof dir, dir, NULL)) return 2;
    }
    DWORD attr = GetFileAttributesA(dir);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "folder not found: %s\nusage: %s [game folder]\n", dir, SS_HOST_NAME);
        return 2;
    }
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {           /* a path to a file in the folder is accepted too */
        char *slash = strrchr(dir, '\\');
        if (slash) *slash = 0;
    }
    /* the module file name the client reports for itself */
    snprintf(rt_guest_exe, sizeof rt_guest_exe, "%s\\" SS_ORIGINAL_EXE, dir);
    char exedir[MAX_PATH];
    if (GetModuleFileNameA(NULL, exedir, sizeof exedir)) {
        char *sl = strrchr(exedir, '\\');
        if (sl) *sl = 0;
        SetDllDirectoryA(exedir);
    }
    SetCurrentDirectoryA(dir);
    gil_init();
    {
        void *p = VirtualAlloc((void *)(uintptr_t)0xFE000000u, 0x100000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (p) memset(p, 0xC3, 0x100000);
    }

    u32 stack = (u32)(uintptr_t)VirtualAlloc(NULL, 0x800000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    rt_main_thread(stack, stack + 0x800000 - 0x1000);

    for (int i = 0; i < api_static_n; ++i) {
        const ApiStatic *s = &api_static[i];
        char dll[64];
        snprintf(dll, sizeof dll, strchr(s->module, '.') ? "%s" : "%s.dll", s->module);
        int silent = !strcmp(s->name, "PlaySoundA");
        HMODULE m = silent ? NULL : LoadLibraryA(dll);
        FARPROC fn = (m && !silent) ? GetProcAddress(m, s->name) : NULL;
        if (!fn && m && s->name[0] == '#') fn = GetProcAddress(m, (LPCSTR)MAKEINTRESOURCEA(atoi(s->name + 1)));
        if (!fn) fprintf(stderr, "warning: import %s!%s not found\n", s->module, s->name);
        if (!strcmp(s->name, "_acmdln")) {          /* data export: the guest reads the variable, not a function */
            W32(s->ea, (u32)(uintptr_t)fn);
            continue;
        }
        u32 sentinel = api_add(s->module, s->name, fn, s->nargs, s->cdecl_);
        api_tab[(sentinel - 0xFE000000u) >> 4].special = api_special_id(s->name);
        W32(s->ea, sentinel);
    }

    fprintf(stderr, "boot: image mapped, %d imports bound, entering %08x\n", api_static_n, OEP);
    r_esp -= 4;
    W32(r_esp, 0xDEAD0000u);
    call_ind(OEP);
    fprintf(stderr, "guest returned, eax=%08x\n", r_eax);
    return (int)r_eax;
}

#else   /* POSIX hosts: Linux, macOS */

static char crash_stack[64 * 1024];

/* Built against a sysroot of 32-bit libraries (scripts/build.sh), the executable knows where it is: the loader and the
 * libraries are found through the paths written into it; Mesa's drivers, EGL vendors and ALSA's plugins are found
 * through these variables (unless the caller set them), read when they are first used, after this. */
extern const char rt_sysroot[] __attribute__((weak));
static void use_sysroot(char **argv)
{
    if (!&rt_sysroot[0] || !rt_sysroot[0]) return;
    char p[PATH_MAX];
#if defined(__linux__)
    /* Some of the sysroot's libraries name the system's 32-bit folder as their own search path (libpulse, Mesa's LLVM), which
     * hides the sysroot from what they load.  LD_LIBRARY_PATH comes before that, but the loader reads it only at start: set
     * it and start this program again, once (not when it was started through the loader, as run_linux.sh does). */
    char self[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n > 0 && !getenv("SS_RESTARTED")) {
        self[n] = 0;
        if (!strstr(strrchr(self, '/') ? strrchr(self, '/') : self, "ld-linux")) {
            const char *old = getenv("LD_LIBRARY_PATH");
            char libs[PATH_MAX * 4];
            snprintf(libs, sizeof libs, "%s/usr/lib/i386-linux-gnu:%s/usr/lib/i386-linux-gnu/pulseaudio:%s/usr/lib%s%s",
                     rt_sysroot, rt_sysroot, rt_sysroot, old && *old ? ":" : "", old && *old ? old : "");
            setenv("LD_LIBRARY_PATH", libs, 1);
            setenv("SS_RESTARTED", "1", 1);
            execv(self, argv);
            fprintf(stderr, "could not restart %s with the sysroot's libraries; going on\n", self);
        }
    }
    unsetenv("SS_RESTARTED");                  /* programs the client starts begin afresh */
#else
    (void)argv;
#endif
    snprintf(p, sizeof p, "%s/usr/lib/i386-linux-gnu/dri", rt_sysroot);
    setenv("LIBGL_DRIVERS_PATH", p, 0);
    snprintf(p, sizeof p, "%s/usr/share/glvnd/egl_vendor.d", rt_sysroot);
    setenv("__EGL_VENDOR_LIBRARY_DIRS", p, 0);
    snprintf(p, sizeof p, "%s/usr/lib/i386-linux-gnu/alsa-lib", rt_sysroot);
    setenv("ALSA_PLUGIN_DIR", p, 0);
    setenv("SS_SYSROOT", rt_sysroot, 0);       /* programs the client starts get an environment without these */
}

static void on_crash(int sig, siginfo_t *si, void *ctx)
{
    void *pc = NULL;
#if defined(__linux__) && defined(__i386__)
    pc = (void *)(uintptr_t)((ucontext_t *)ctx)->uc_mcontext.gregs[REG_EIP];
#else
    (void)ctx;
#endif
    fprintf(stderr, "CRASH signal %d (%s) at host %p, address %p, guest esp %08x eax %08x ecx %08x ebp %08x esi %08x edi %08x edx %08x ebx %08x\n",
            sig, sig == SIGSEGV ? "segmentation fault" : sig == SIGBUS ? "bus error" : sig == SIGFPE ? "arithmetic" : sig == SIGILL ? "illegal instruction" : "abort",
            pc, si ? si->si_addr : NULL, r_esp, r_eax, r_ecx, r_ebp, r_esi, r_edi, r_edx, r_ebx);
    /* the executable is linked at a fixed address (no PIE), so the host address is the one in bin/lift.map */
    fprintf(stderr, "      look the host address up in bin/lift.map (or: addr2line -f -e the host executable %p)\n", pc);
    fprintf(stderr, "      guest stack, code addresses:");
    int shown = 0;
    for (u32 p = r_esp; p < r_esp + 0x400 && shown < 14 && rt_readable(p, 4); p += 4) {
        u32 v = R32(p);
        if (v >= SS_CODE_LO + 5 && v < SS_CODE_HI && rt_readable(v - 6, 6) &&
            (R8(v - 5) == 0xE8 || R8(v - 6) == 0xFF || R8(v - 2) == 0xFF || R8(v - 3) == 0xFF)) {
            fprintf(stderr, " %08x", v);
            ++shown;
        }
    }
    fprintf(stderr, "\n");
    rt_shadow_dump();
    fflush(stderr);
    _exit(4);
}

static void install_crash_handler(void)
{
    stack_t ss;
    ss.ss_sp = crash_stack;
    ss.ss_size = sizeof crash_stack;
    ss.ss_flags = 0;
    sigaltstack(&ss, NULL);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_crash;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);            /* a socket closed by the server gives an error from send(), as on Windows */
}

int main(int argc, char **argv)
{
    rt_trace = getenv("RECOMP_TRACE") != NULL;
    const char *watch = getenv("RECOMP_WATCH");
    if (watch) { char *end; rt_watch_lo = (u32)strtoul(watch, &end, 16); if (*end == '-') rt_watch_hi = (u32)strtoul(end + 1, NULL, 16); }
    use_sysroot(argv);
    install_crash_handler();
    if (!rt_load_image(getenv("RECOMP_IMAGE"))) {
        fprintf(stderr, "cannot map the guest address range %08x..%08x (something else is mapped there)\n", SS_IMAGE_BASE, SS_IMAGE_END);
        return 77;
    }

    /* without an argument the client folder is the program's own folder, as for the original exe, which sits in its game
     * folder (put the game data next to the executable) */
    /* the first argument is the client folder when it names an existing path; otherwise (a switch such as
     * -listscriptfunctions, a custom URL) every argument goes to the client and the folder is the default one */
    struct stat st;
    int has_folder = argc >= 2 && argv[1][0] != '-' && stat(argv[1], &st) == 0;
    const char *folder = has_folder ? argv[1] : ".";
    char self[PATH_MAX];
#if defined(__linux__)
    if (!has_folder) {
        ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
        if (n > 0) {
            self[n] = 0;
            char *slash = strrchr(self, '/');
            if (slash && strstr(slash, "ld-linux") == NULL) {         /* started through a loader: keep the current folder */
                *slash = 0;
                folder = self[0] ? self : "/";
            }
        }
    }
#endif
    char dir[PATH_MAX];
    if (!realpath(folder, dir)) {
        fprintf(stderr, "folder not found: %s\nusage: %s [game folder]\n", folder, SS_HOST_NAME);
        return 2;
    }
    if (stat(dir, &st) == 0 && !S_ISDIR(st.st_mode)) {     /* a path to a file in the folder is accepted too */
        char *slash = strrchr(dir, '/');
        if (slash && slash != dir) *slash = 0;
    }
    if (chdir(dir) != 0) {
        fprintf(stderr, "cannot enter %s\n", dir);
        return 2;
    }
    w32_init(dir, has_folder ? argc - 2 : argc - 1, has_folder ? argv + 2 : argv + 1);
    gil_init();

    u32 stack = rt_sys_alloc(0x800000);
    rt_main_thread(stack, stack + 0x800000 - 0x1000);

    int missing = 0;
    for (int i = 0; i < api_static_n; ++i) {
        const ApiStatic *s = &api_static[i];
        ApiEmu fn = w32_lookup(s->module, s->name);
        if (!fn) {
            ++missing;
            if (rt_trace) fprintf(stderr, "warning: import %s!%s has no emulation\n", s->module, s->name);
        }
        W32(s->ea, api_add_emu(s->module, s->name, fn, s->nargs, s->cdecl_));
    }

    fprintf(stderr, "boot: image mapped, %d imports bound (%d without emulation), entering %08x\n", api_static_n, missing, OEP);
    r_esp -= 4;
    W32(r_esp, 0xDEAD0000u);
    call_ind(OEP);
    fprintf(stderr, "guest returned, eax=%08x\n", r_eax);
    return (int)r_eax;
}
#endif
