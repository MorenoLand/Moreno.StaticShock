/* host_test.c: smoke test for the wasm host layer. Build and run with tests/run_wasm_test.py. */
#include "api.h"
#include "sys.h"
#include "wasm_config.h"
#include <stdio.h>
#include <string.h>

const NameArgs name_args[] = {{"test_emu", 2}};
const int name_args_n = 1;
const ApiStatic api_static[] = {{0, "TEST", "test_emu", 2, 0}};
const int api_static_n = 1;
const FnEnt fn_table[] = {{0, NULL}};
const unsigned fn_count = 0;

static int fails;

#define CHECK(cond, name) do { \
    if (cond) printf("[ok] %s\n", name); \
    else { printf("[fail] %s\n", name); ++fails; } \
} while (0)

static u64 emu_pair(u32 *a)
{
    return ((u64)a[1] << 32) | a[0];
}

int main(void)
{
    r_esp = 0x20000;
    W32(0x20000, 0xDEAD0000u);
    W32(0x20004, 0x11223344u);
    W32(0x20008, 0x55667788u);
    u32 s = api_add_emu("TEST", "test_emu", emu_pair, 2, 0);
    api_dispatch(s);
    CHECK(r_eax == 0x11223344u && r_edx == 0x55667788u, "stdcall returns eax/edx");
    CHECK(r_esp == 0x2000Cu, "stdcall removes arguments");

    r_esp = 0x20100;
    W32(0x20100, 0xDEAD0000u);
    W32(0x20104, 0xAABBBCCCu);
    W32(0x20108, 0xDDEEEFFFu);
    s = api_add_emu("TEST", "test_cdecl", emu_pair, 2, 1);
    api_dispatch(s);
    CHECK(r_eax == 0xAABBBCCCu && r_edx == 0xDDEEEFFFu, "cdecl returns eax/edx");
    CHECK(r_esp == 0x20104u, "cdecl leaves arguments for the caller");

    r_esp = 0x20200;
    W32(0x20200, 0xDEAD0000u);
    W32(0x20204, 0);
    s = api_add("TEST", "GetModuleHandleA", NULL, 1, 0);
    api_tab[(s - 0xFE000000u) >> 4].special = api_special_id("GetModuleHandleA");
    api_dispatch(s);
    CHECK(r_eax == WASM_IMAGE_BASE, "GetModuleHandleA returns the image base");
    CHECK(r_esp == 0x20208u, "special import removes its argument");

    CHECK(name_nargs("test_emu") == 2, "name_nargs finds the count");
    CHECK(rt_readable(0x1000, 16), "rt_readable accepts mapped memory");
    CHECK(!rt_readable(0xFFFFFF00u, 0x1000), "rt_readable rejects the end of memory");

    u32 teb = rt_new_teb(0x30000, 0x40000);
    CHECK(teb != 0 && R32(teb + 4) == 0x40000u && R32(teb + 8) == 0x30000u, "TEB stack fields");

    CHECK(rt_load_image(NULL) == 1, "image loads");
    CHECK(R32(WASM_IMAGE_BASE + 0x3000) == 0x12345678u, "image bytes land at their address");

    printf(fails ? "%d check(s) failed\n" : "all checks passed\n", fails);
    return fails ? 1 : 0;
}
