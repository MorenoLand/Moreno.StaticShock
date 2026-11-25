/* guest_pad.c: the host image owns the guest range so the loader cannot place the stack, the heap
 * or locale mappings there. The section is uninitialized (bss): the loader maps it zero-filled and
 * the file stores no bytes for it. rt_load_image writes the data pieces before the guest entry runs. */
#include "project.h"

#define SS_STR2(x) #x
#define SS_STR(x) SS_STR2(x)

__asm__(".section .guest,\"b\"\n"
        ".global rt_guest_pad\n"
        "rt_guest_pad:\n"
        ".space " SS_STR(SS_GUEST_SIZE) "\n");
