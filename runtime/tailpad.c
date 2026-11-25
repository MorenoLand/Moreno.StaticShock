/* tailpad.c: reserve the tail of the guest range. The linker places .tail at SS_IMAGE_BASE + 0x1000
 * + SS_GUEST_SIZE; .text follows it. The section is uninitialized (bss), so the file stores no bytes. */
#include "project.h"

#define SS_STR2(x) #x
#define SS_STR(x) SS_STR2(x)

__asm__(".section .tail,\"b\"\n"
        ".global rt_tail_pad\n"
        "rt_tail_pad:\n"
        ".space " SS_STR(SS_TAIL_SIZE) "\n");
