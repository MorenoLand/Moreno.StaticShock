/* imports.c: per-target Win32 emulation hook for the wasm host.
 *
 * The weak definition reports every import as unimplemented, so boot binds a function that aborts
 * with its module!name. A port implements wasm_lookup (strong definition) or replaces this file.
 */
#include "api.h"
#include "wasm.h"

__attribute__((weak)) ApiEmu wasm_lookup(const char *module, const char *name)
{
    (void)module;
    (void)name;
    return NULL;
}
