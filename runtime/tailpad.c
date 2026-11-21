/* tailpad.c: reserve the tail of the guest range. The linker places .tail at SS_IMAGE_BASE + 0x1000
 * + SS_GUEST_SIZE; .text follows it. The bytes are never used as data. */
#include "project.h"

char rt_tail_pad[SS_TAIL_SIZE] __attribute__((section(".tail"), aligned(0x1000)));
