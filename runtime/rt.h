/* rt.h: runtime model shared by all lifted functions (see lift.py). 32-bit build: a guest address is a host pointer. */
#ifndef RT_H
#define RT_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int8_t i8; typedef int16_t i16; typedef int32_t i32; typedef int64_t i64;

/* recomp links no API/override implementation. Give its fallbacks ordinary
 * definitions: PE/COFF weak externals do not satisfy other objects' strong
 * references. Client and calltest builds still allow the real overrides. */
#if defined(SS_RECOMP_DRIVER)
#define RT_FALLBACK
#else
#define RT_FALLBACK __attribute__((weak))
#endif

extern u32 r_eax, r_ecx, r_edx, r_ebx, r_esp, r_ebp, r_esi, r_edi;
extern long double fpr[8];
extern int ftop;
extern u16 fsw, fcw;

extern u32 rt_teb;
#define TEB rt_teb
#define R8(a)  (*(u8 *)(uintptr_t)(a))
#define R16(a) (*(u16 *)(uintptr_t)(a))
#define R32(a) (*(u32 *)(uintptr_t)(a))
#define R64(a) (*(u64 *)(uintptr_t)(a))
#define W64(a, v) (*(u64 *)(uintptr_t)(a) = (u64)(v))
#define W8(a, v)  (*(u8 *)(uintptr_t)(a) = (u8)(v))
#define W16(a, v) (*(u16 *)(uintptr_t)(a) = (u16)(v))
extern u32 rt_watch_lo, rt_watch_hi;                 /* debugging: report 32-bit writes into [lo, hi) (build with -DRT_WATCH) */
void rt_watch_hit(u32 addr, u32 value, const char *fn);
#ifdef RT_WATCH
#define W32(a, v) do { u32 w_a_ = (u32)(a), w_v_ = (u32)(v); if (w_a_ - rt_watch_lo < rt_watch_hi - rt_watch_lo) rt_watch_hit(w_a_, w_v_, __func__); *(u32 *)(uintptr_t)w_a_ = w_v_; } while (0)
#else
#define W32(a, v) (*(u32 *)(uintptr_t)(a) = (u32)(v))
#endif
#define R_F32(a) ((long double)*(float *)(uintptr_t)(a))
#define R_F64(a) ((long double)*(double *)(uintptr_t)(a))
#define W_F32(a, v) (*(float *)(uintptr_t)(a) = (float)(v))
#define W_F64(a, v) (*(double *)(uintptr_t)(a) = (v))
long double rt_r_f80(u32 a);
void rt_w_f80(u32 a, long double v);
#define R_F80(a) rt_r_f80(a)
#define W_F80(a, v) rt_w_f80((a), (v))

#define ST(i) fpr[(ftop + (i)) & 7]
#define FPUSH(x) do { long double fpv_ = (x); ftop = (ftop - 1) & 7; fpr[ftop] = fpv_; } while (0)
#define FPOP() (ftop = (ftop + 1) & 7)

long double fx_rint(long double v);
i16 fx_int16(long double v);
i32 fx_int32(long double v);
i64 fx_int64(long double v);
void fx_compare(long double a, long double b);
double fx_rint_mx(double v);
u16 fx_sw(void);

__attribute__((noreturn)) void rt_unsup(u32 addr, const char *msg);
#define UNSUP(a, msg) rt_unsup((a), (msg))
void call_ind(u32 target);
u32 gcall(u32 addr, u32 ecx_value, int cdecl_, int n, ...);   /* api.c: call the guest function at addr from native code; ecx for a thiscall, cdecl_ = 1 when the caller removes the n 32-bit arguments; returns eax.
                                                                  Declared here and not in api.h, which includes <windows.h> on Windows: the host bridges (src/host) must not. */

typedef struct { u32 addr; void (*fn)(void); } FnEnt;
extern const FnEnt fn_table[];
extern const unsigned fn_count;
void rt_shadow_dump(void);                           /* crash report: the guest call stack of a profile build */
void rt_prof_dump(void);                             /* prints the per-function call counts of a profile build; does nothing otherwise */
#ifdef RT_PROFILE
void rt_prof(u32 addr);                              /* debugging: log every function the first time it runs (build with -DRT_PROFILE) */
u32 rt_fn_addr(const void *f);                       /* the guest address of a function given the function (or the address itself) */
#define FN_ENTER(a) rt_prof(rt_fn_addr((const void *)(a)))
void rt_bb(u32 addr);                                 /* debugging: RECOMP_BBLOG=lo-hi (hex) prints every labelled block reached in that address range */
#define BB(a) rt_bb(a)
void rt_fn_ret(u32 fea);                             /* debugging: RECOMP_RETLOG=hex,hex prints eax when those functions return */
#define FN_RET(a) rt_fn_ret(rt_fn_addr((const void *)(a)))
#else
#define FN_ENTER(a) ((void)0)
#define BB(a) ((void)0)
#define FN_RET(a) ((void)0)
#endif
extern u32 rt_eflags_extra;
extern int rt_df;                                    /* direction flag */
void rt_cpuid(u32 leaf, u32 sub, u32 *a, u32 *b, u32 *c, u32 *d);
u64 rt_rdtsc(void);
typedef union { u8 b[16]; u16 w[8]; u32 d[4]; u64 q[2]; double f[2]; } XMM;
extern XMM xmm[8];
extern u32 mxcsr;
#endif
