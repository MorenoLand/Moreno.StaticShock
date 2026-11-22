/* wasm.h: shared declarations of the wasm host. */
#ifndef WASM_HOST_H
#define WASM_HOST_H
#include "api.h"

extern ApiEnt *wasm_current;
extern u32 wasm_current_ecx;

ApiEmu wasm_lookup(const char *module, const char *name);

int wasm_peek_event(int *type, int *x, int *y, int *key);
int wasm_peek_event_ex(int *type, int *x, int *y, int *key, int consume);

#endif
