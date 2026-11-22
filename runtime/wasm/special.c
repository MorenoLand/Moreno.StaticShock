/* special.c: imports whose arguments or results need guest memory, callbacks or x87. */
#include "api.h"
#include "project.h"
#include "wasm_config.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    S_NONE, S_INITTERM, S_INITTERM_E, S_QSORT, S_BSEARCH,
    S_GETMODULEHANDLE, S_GETPROCADDRESS, S_GETMODULEFILENAME,
    S_MATHFP, S_CIPOW, S_FTOL
};

static const struct { const char *name; int id; } specials[] = {
    {"_initterm", S_INITTERM}, {"_initterm_e", S_INITTERM_E},
    {"qsort", S_QSORT}, {"bsearch", S_BSEARCH},
    {"GetModuleHandleA", S_GETMODULEHANDLE}, {"GetModuleHandleW", S_GETMODULEHANDLE},
    {"GetProcAddress", S_GETPROCADDRESS}, {"GetModuleFileNameA", S_GETMODULEFILENAME},
    {"ldexp", S_MATHFP}, {"frexp", S_MATHFP}, {"modf", S_MATHFP}, {"fmod", S_MATHFP},
    {"atof", S_MATHFP}, {"ceil", S_MATHFP}, {"cos", S_MATHFP}, {"fabs", S_MATHFP},
    {"floor", S_MATHFP}, {"log10", S_MATHFP}, {"sin", S_MATHFP}, {"sqrt", S_MATHFP},
    {"pow", S_MATHFP}, {"exp", S_MATHFP}, {"log", S_MATHFP}, {"atan2", S_MATHFP},
    {"_CIpow", S_CIPOW}, {"_CIlog", S_CIPOW}, {"_CIexp", S_CIPOW}, {"_CIsqrt", S_CIPOW},
    {"_CIsin", S_CIPOW}, {"_CIcos", S_CIPOW}, {"_CItan", S_CIPOW}, {"_CIatan", S_CIPOW},
    {"_ftol", S_FTOL}
};

int api_special_id(const char *name)
{
    for (size_t i = 0; i < sizeof specials / sizeof *specials; ++i)
        if (!strcmp(specials[i].name, name)) return specials[i].id;
    return 0;
}

u64 api_special(int id, ApiEnt *e, u32 *a)
{
    switch (id) {
    case S_INITTERM:
    case S_INITTERM_E:
        for (u32 p = a[0]; p < a[1]; p += 4) {
            u32 fn = R32(p);
            if (fn) call_ind(fn);
        }
        return 0;
    case S_QSORT: {
        u32 base = a[0], n = a[1], sz = a[2], cmp = a[3];
        char *tmp = (char *)malloc(sz ? sz : 1);
        if (!tmp) return 0;
        for (u32 i = 1; i < n; ++i) {
            memcpy(tmp, (void *)(uintptr_t)(base + i * sz), sz);
            u32 j = i;
            while (j > 0) {
                u32 cargs[2] = { base + (j - 1) * sz, (u32)(uintptr_t)tmp };
                if ((int)rt_guest_callback(cmp, 2, cargs) <= 0) break;
                memcpy((void *)(uintptr_t)(base + j * sz), (void *)(uintptr_t)(base + (j - 1) * sz), sz);
                --j;
            }
            memcpy((void *)(uintptr_t)(base + j * sz), tmp, sz);
        }
        free(tmp);
        return 0;
    }
    case S_BSEARCH: {
        u32 key = a[0], base = a[1], num = a[2], width = a[3], cmp = a[4];
        u32 lo = 0, hi = num;
        while (lo < hi) {
            u32 mid = lo + (hi - lo) / 2;
            u32 cargs[2] = { key, base + mid * width };
            int c = (int)rt_guest_callback(cmp, 2, cargs);
            if (c == 0) return cargs[1];
            if (c < 0) hi = mid;
            else lo = mid + 1;
        }
        return 0;
    }
    case S_GETMODULEHANDLE:
        return a[0] == 0 ? WASM_IMAGE_BASE : 0;
    case S_GETPROCADDRESS: {
        const char *name = (const char *)(uintptr_t)a[1];
        if (!name) return 0;
        for (int i = 0; i < api_count; ++i)
            if (!strcmp(api_tab[i].name, name)) return 0xFE000000u + (u32)i * 16u;
        fprintf(stderr, "wasm: GetProcAddress(%s) not found\n", name);
        return 0;
    }
    case S_GETMODULEFILENAME: {
        if (a[0] != 0) return 0;
        char *dst = (char *)(uintptr_t)a[1];
        size_t len = strlen(rt_guest_exe);
        if (len >= a[2]) len = a[2] ? a[2] - 1 : 0;
        if (a[2]) { memcpy(dst, rt_guest_exe, len); dst[len] = 0; }
        return (u32)len;
    }
    case S_FTOL:
        return (u32)(long)ST(0);
    case S_MATHFP: {
        double d0, d1, r;
        memcpy(&d0, a, 8);
        memcpy(&d1, a + 2, 8);
        if (!strcmp(e->name, "ldexp")) r = ldexp(d0, (int)a[2]);
        else if (!strcmp(e->name, "frexp")) { int ex; r = frexp(d0, &ex); W32(a[2], (u32)ex); }
        else if (!strcmp(e->name, "modf")) { double ip; r = modf(d0, &ip); W_F64(a[2], ip); }
        else if (!strcmp(e->name, "fmod")) r = fmod(d0, d1);
        else if (!strcmp(e->name, "pow")) r = pow(d0, d1);
        else if (!strcmp(e->name, "atan2")) r = atan2(d0, d1);
        else if (!strcmp(e->name, "atof")) r = atof((const char *)(uintptr_t)a[0]);
        else if (!strcmp(e->name, "ceil")) r = ceil(d0);
        else if (!strcmp(e->name, "cos")) r = cos(d0);
        else if (!strcmp(e->name, "exp")) r = exp(d0);
        else if (!strcmp(e->name, "fabs")) r = fabs(d0);
        else if (!strcmp(e->name, "floor")) r = floor(d0);
        else if (!strcmp(e->name, "log")) r = log(d0);
        else if (!strcmp(e->name, "log10")) r = log10(d0);
        else if (!strcmp(e->name, "sin")) r = sin(d0);
        else r = sqrt(d0);
        FPUSH(r);
        return 0;
    }
    case S_CIPOW: {
        long double x = ST(0), y = ST(1), r;
        if (!strcmp(e->name, "_CIpow")) r = powl(y, x);
        else if (!strcmp(e->name, "_CIlog")) r = logl(x);
        else if (!strcmp(e->name, "_CIexp")) r = expl(x);
        else if (!strcmp(e->name, "_CIsqrt")) r = sqrtl(x);
        else if (!strcmp(e->name, "_CIsin")) r = sinl(x);
        else if (!strcmp(e->name, "_CIcos")) r = cosl(x);
        else if (!strcmp(e->name, "_CItan")) r = tanl(x);
        else r = atanl(x);
        if (!strcmp(e->name, "_CIpow")) FPOP();
        FPOP();
        FPUSH(r);
        return 0;
    }
    }
    return 0;
}
