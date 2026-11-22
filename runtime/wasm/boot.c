/* boot.c: wasm entry point. Maps the data image, binds the import sentinels and runs the OEP. */
#include "api.h"
#include "sys.h"
#include "project.h"
#include "wasm_config.h"
#include "wasm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rt_load_image(const char *path);
extern const ApiStatic api_static[];
extern const int api_static_n;

static u64 missing(u32 *a)
{
    (void)a;
    fprintf(stderr, "wasm: import %s!%s has no implementation\n",
            wasm_current ? wasm_current->module : "?", wasm_current ? wasm_current->name : "?");
    abort();
}

static void bind_imports(void)
{
    int missing_count = 0;
    for (int i = 0; i < api_static_n; ++i) {
        const ApiStatic *s = &api_static[i];
        if (!strcmp(s->name, "_acmdln")) {
            char *text = (char *)malloc(strlen(WASM_ORIGINAL_EXE) + 1);
            u32 cell = (u32)(uintptr_t)malloc(4);
            strcpy(text, WASM_ORIGINAL_EXE);
            W32(cell, (u32)(uintptr_t)text);
            W32(s->ea, cell);
            continue;
        }
        ApiEmu fn = wasm_lookup(s->module, s->name);
        if (!fn) {
            ++missing_count;
            fn = missing;
        }
        u32 sentinel = api_add_emu(s->module, s->name, fn, s->nargs, s->cdecl_);
        api_tab[(sentinel - 0xFE000000u) >> 4].special = api_special_id(s->name);
        W32(s->ea, sentinel);
    }
    if (missing_count)
        fprintf(stderr, "wasm: %d of %d imports have no implementation; they abort when called\n",
                missing_count, api_static_n);
}

int main(void)
{
    rt_trace = getenv("RECOMP_TRACE") != NULL;
    if (!rt_load_image(NULL)) {
        fprintf(stderr, "wasm: image load failed\n");
        return 77;
    }
    gil_init();
    strcpy(rt_guest_exe, WASM_ORIGINAL_EXE);
    bind_imports();

    u32 stack = rt_sys_alloc(WASM_GUEST_STACK);
    if (!stack) {
        fprintf(stderr, "wasm: cannot allocate the guest stack\n");
        return 77;
    }
    rt_main_thread(stack, stack + WASM_GUEST_STACK - 0x1000);

    fprintf(stderr, "wasm: image mapped, %d imports bound, entering %08x\n", api_static_n, WASM_OEP);
    r_esp -= 4;
    W32(r_esp, 0xDEAD0000u);
    call_ind(WASM_OEP);
    fprintf(stderr, "wasm: guest returned eax=%08x\n", r_eax);
    return (int)r_eax;
}
