# Overview

## What a static lift is

A static lift translates each machine instruction of the original executable into C. The result is
ordinary C that the host compiler turns into a native program. The original machine code is never
executed.

The lift is *not* a decompiler. It keeps the original control flow, register usage, flags and
stack discipline, so the output is verbose and address-annotated. Readable rewritten functions are
an optional later step, and every rewrite must be checked against the original.

## The model

- A guest virtual address is a host pointer. The 32-bit host maps the original image at its own
  image base, so `R32(0x401000)` reads guest address `0x401000`.
- Guest registers (`r_eax` ... `r_edi`) are global variables, as are the x87 stack (`fpr`, `ftop`)
  and the SIMD registers (`xmm`, `mxcsr`).
- Every lifted function has the signature `void f_XXXXXXXX(void)`. A call pushes the guest return
  address and calls the C function; `ret` pops it. Arguments and return values use the guest stack
  and `eax`, exactly as in the original.
- Condition flags are local variables (`fZ fS fC fO fP fA`) computed only where a later instruction
  can read them.
- An indirect call goes through `call_ind()`, which looks the target up in the function table and
  calls the lifted C function.

The data of the original is emitted into `src/image.bin`: PE headers, data sections and bytes of
the code range that no instruction covers (jump tables, constants, padding). Code pages are not
copied; the runtime can make them unreadable so a stale read is a crash instead of silent junk.

## Layers

| Layer | Responsibility |
|---|---|
| Lifter (`pipeline/lift.py`) | One x86 instruction to one or more C statements. No program knowledge. |
| Generator (`pipeline/gen.py`) | Groups functions into files, writes `protos.h`, `dispatch.c`, stubs and the data image. |
| Runtime (`runtime/`) | Registers, FPU, memory mapping, import dispatch, threads, crash reporting, boot. |
| Import bridge (`runtime/api*.c`) | Calls the real DLL function. Special entries translate guest pointers, callbacks, file paths and FP returns. |
| Host/platform | The Win32 APIs themselves, or the emulation layer supplied by a port. The wasm host ships the import hook, not a Win32 emulation. The lifted program creates its own window and message loop through `user32`. |

## What is not emulated

- The original code is not present; if a function is not lifted, it is a stub and will `UNSUP`.
- The x87 is modelled in software with `long double`; precision control and some save/restore
  forms are limited.
- `lock` prefixes are not atomic; a global lock serializes guest threads.
- SEH is not dispatched; a fault is a host crash with a guest register dump.
- Device drivers, kernel calls and anti-cheat are out of scope.

## Correctness loop

1. Build and run.
2. On a crash, map the host address with `bin/lift.map`, read the guest state, find the function.
3. Compare that function with the original using `pipeline/difftest.py` or a focused harness.
4. Fix the lifter or the runtime, regenerate, and repeat.
5. When behaviour matches, add a regression test or a documented differential case.
