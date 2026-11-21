/* preentry.c: reserve the guest address range before the C runtime starts.
 * The process stack and the CRT's locale mappings are created before main and can land in the
 * guest range; reserving it first keeps them out. mainCRTStartup then runs the normal startup. */
#include <windows.h>
#include "project.h"

void mainCRTStartup(void);

__attribute__((noinline)) void rt_preentry(void)
{
    VirtualAlloc((void *)(uintptr_t)SS_IMAGE_BASE,
                 (SIZE_T)(SS_TEXT_SECTION - SS_IMAGE_BASE),
                 MEM_RESERVE, PAGE_NOACCESS);
    mainCRTStartup();
}
