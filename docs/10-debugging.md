# Debugging

## The crash report

The runtime installs a handler that prints:

- the host exception address
- the guest `esp`, `eax`, `ecx`, `ebp`, `esi`, `edi`, `edx`, `ebx`
- candidate guest return addresses found on the guest stack
- the live lifted functions (profile builds)

Map the host address with `bin/lift.map`:

```sh
python pipeline/addr2fn.py <map address>
```

The generated function name is `f_<guest address>`, so the same line tells you which original
function to open in IDA.

## Trace imports

```sh
RECOMP_TRACE=1 bin/host.exe
```

This logs every bound import and its arguments. It is expensive; use it to find the first wrong
call, then turn it off.

Log only selected calls:

```sh
RECOMP_LOGAPI=CreateFileA,GetProcAddress bin/host.exe
```

## Differential testing

`pipeline/difftest.py` runs a function in Unicorn against the original bytes and compares the
guest registers and memory with the lifted C. It is the strongest tool for instruction semantics.

- Build the driver (`runtime/driver.c`) for the target.
- Generate test cases from the original function's arguments.
- Start with one function; a mismatch is a lifter bug, not a game bug.
- The driver output is line-oriented: `OK`, `UNSUP`, `CRASH`.

If a function cannot be tested in isolation, add a runtime trace and compare a full run.

## Watchpoints

Build with `-DRT_WATCH`, then:

```sh
RECOMP_WATCH=6d9d00-6d9d40 bin/host.exe
```

The runtime prints every 32-bit write in the range with the writing function. This finds the code
that overwrites a flag or a vtable.

## Profiling

Build with `-DRT_PROFILE` and set `RECOMP_PROF_SECONDS=10`. The runtime prints the functions that
executed and where time went. `RECOMP_ENTLOG` logs the first instructions of selected functions.

## First divergence discipline

Do not fix the first visible symptom. Find the first *incorrect value* in the chain:

1. Which API is called with wrong arguments?
2. Which function produced that value?
3. Which instruction produced it?
4. Compare that instruction with the original.

A crash at `mov eax,[edx]` is usually not an instruction bug; `edx` was wrong earlier.

## Common crashes

| Symptom | Likely cause |
|---|---|
| `UNSUP ... instruction` | Missing lifter case. Implement it; do not stub. |
| Crash at a data address | A pointer is a guest address but the API expected a host pointer, or vice versa. |
| Crash in `call_ind` | An indirect target is not in `fn_table`: missed function, bad vtable, or wrong register. |
| `map guest range failed` | The guest range is occupied. Check the base, the stack/heap reserves and the preentry. |
| Window opens but no input | Mouse coordinates are in the wrong space, or the active flag is zero. |
| Garbage audio | The guest's PCM, not the device. Dump before the API call. |
