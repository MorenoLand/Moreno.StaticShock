/* sys.h: the few operating-system services the runtime itself needs (memory at fixed addresses, page protection, a
 * readability probe for crash reports).  rt.c implements them for Windows and for POSIX systems (Linux, macOS), so the
 * rest of the runtime does not include a platform header for these. */
#ifndef RT_SYS_H
#define RT_SYS_H
#include "rt.h"

int rt_sys_map_fixed(u32 addr, u32 size);      /* read/write memory at exactly addr (64 KB aligned); 0 when the range is taken */
u32 rt_sys_alloc(u32 size);                    /* read/write memory anywhere below 4 GB; 0 on failure */
void rt_sys_free(u32 addr, u32 size);
void rt_sys_noaccess(u32 addr, u32 size);      /* any access to these pages faults */
int rt_readable(u32 addr, u32 n);              /* 1 when n bytes at addr can be read without a fault */
int rt_load_image(const char *path);           /* path NULL: load the compiled data image; else read the PE file */
#endif
