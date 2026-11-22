/* sys.c: linear-memory services and image loading for the wasm host. */
#include "sys.h"
#include "project.h"
#include "wasm_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static u32 memory_size(void)
{
    return (u32)__builtin_wasm_memory_size(0) * 65536u;
}

int rt_sys_map_fixed(u32 addr, u32 size)
{
    if (addr + size < addr) return 0;
    return addr + size <= WASM_GLOBAL_BASE;      /* the range reserved below the host's static data */
}

u32 rt_sys_alloc(u32 size)
{
    return (u32)(uintptr_t)malloc(size);
}

void rt_sys_free(u32 addr, u32 size)
{
    (void)size;
    free((void *)(uintptr_t)addr);
}

void rt_sys_noaccess(u32 addr, u32 size)
{
    (void)addr;
    (void)size;
}

int rt_readable(u32 addr, u32 n)
{
    u32 size = memory_size();
    return addr < size && n <= size - addr;
}

int rt_load_image(const char *path)
{
    (void)path;
    FILE *f = fopen("/image.bin", "rb");
    if (!f) {
        fprintf(stderr, "wasm: cannot open /image.bin\n");
        return 0;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *d = (unsigned char *)malloc((size_t)n);
    if (!d || fread(d, 1, (size_t)n, f) != (size_t)n) {
        fprintf(stderr, "wasm: cannot read /image.bin\n");
        return 0;
    }
    fclose(f);
    if (n < 4) return 0;
    u32 count;
    memcpy(&count, d, 4);
    for (u32 i = 0; i < count; ++i) {
        u32 va, len, off;
        memcpy(&va, d + 4 + 12 * i, 4);
        memcpy(&len, d + 8 + 12 * i, 4);
        memcpy(&off, d + 12 + 12 * i, 4);
        if (va + len <= WASM_GLOBAL_BASE && off + len <= (u32)n) memcpy((void *)(uintptr_t)va, d + off, len);
    }
    free(d);
    return 1;
}
