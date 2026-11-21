/* guest_pad.c: the host image owns the guest range so the loader cannot place the stack, the heap
 * or locale mappings there. The section is written by rt_load_image before the guest entry runs. */
#include <stdint.h>
#include "project.h"

char rt_guest_pad[SS_TEXT_SECTION - (SS_IMAGE_BASE + 0x1000)]
    __attribute__((section(".guest"), aligned(0x1000)));
