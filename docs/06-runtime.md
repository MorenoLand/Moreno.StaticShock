# Runtime

`runtime/` is linked into every lift. It provides the machine model, the image loader, the import
dispatcher, threads and the boot path. It contains no target logic.

## Files

| File | Contents |
|---|---|
| `rt.h` | Register/Fpu/XMM model, memory macros, flags helpers, `call_ind`, profiling hooks. |
| `rt.c` | Image loader, x87 helpers, indirect dispatch, profile/shadow stacks, watchpoints. |
| `api.h` / `api.c` | Import table, `call_ind` dispatch, sentinel allocation, host call bridge. |
| `api_special.c` | Imports that need guest pointers, callbacks, FP returns or presentation. |
| `api_gen.c` | Generated: the static import table and argument-count list. |
| `boot.c` | `main`: maps the image, binds imports, sets the folder, runs the entry point. |
| `preentry.c`, `guest_pad.c` | Reserve the guest range before the CRT can place stack/heap there. |
| `driver.c` | Differential-test driver (optional build). |
| `project.h` | Generated from `project.toml`; addresses and names. |

## Memory

The original image is mapped at its own base. Data sections are copied from `src/image.bin`; the
code pages are not. The runtime can mark uncovered code pages `PAGE_NOACCESS` so a stale read
faults with a useful address. The guest stack, heap and TLS live in ordinary host memory; the
linker layout and preentry keep them out of the image range.

## Registers and flags

`r_eax` ... `r_edi` are globals. `fpr[8]`/`ftop`/`fsw`/`fcw` model the x87. `xmm[8]`/`mxcsr`
model SSE. The generated code reads and writes them directly. `call_ind` saves the C caller's
registers, looks the target up in `fn_table`, and calls the lifted function under a global lock.

## Threads and TLS

`CreateThread` is bound to a special that starts a host thread and gives it its own guest stack.
Only one guest thread runs at a time (the global lock); a blocking import releases it. The TEB is a
fake block with the fields the CRT and the program read. `FlsAlloc` is stubbed with a small array.

## Exceptions

SEH is not dispatched. A fault produces a host crash report with the guest registers, the last
lifted functions and candidate return addresses. Treat the first crash as the first correctness
bug, not as a reason to add a catch-all.

## CRT initialization

MSVC programs reach `WinMain` through `_initterm`/`_initterm_e`, the security cookie and the
command-line globals. The runtime special-cases `_initterm` to run the guest initializer table and
provides `_acmdln`, `__getmainargs` and the cookie seed. Without this, static constructors never
run and the program crashes before its first window.

## Profiling and tracing

Build with `-DRT_PROFILE` for `FN_ENTER`/`FN_RET`/`BB` hooks, the shadow call stack and per-function
counts. Build with `-DRT_WATCH` and set `RECOMP_WATCH=lo-hi` to log writes into a range. These
cost time; use them to find a bug, not as a permanent mode.
