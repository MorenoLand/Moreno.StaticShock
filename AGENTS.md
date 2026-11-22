# Agent guide

This repository is a template for a static recompilation: the original machine code is translated
instruction by instruction into C, and the result is linked with a small runtime that provides the
guest registers, memory and Win32 imports. Your job is to make that lift correct and runnable for
one target, then keep improving it.

Read the docs in this order:

1. `docs/00-overview.md`
2. `docs/01-prerequisites.md`
3. `docs/02-target-analysis.md`
4. `docs/03-ida-export.md`
5. `docs/04-function-table.md`
6. `docs/05-lifting.md`
7. `docs/06-runtime.md`
8. `docs/07-imports.md`
9. `docs/08-host.md`
10. `docs/09-build.md`
11. `docs/10-debugging.md`
12. `docs/11-porting-checklist.md`
13. `docs/12-wasm.md`
14. `docs/13-lessons.md`

## Non-negotiables

- Work only with software you own and may reverse engineer. Never commit the original executable,
  its assets or extracted copyrighted data. `bin/`, `build/` and `ida/` are ignored for this reason.
- Correctness first. Do not replace unknown instructions with guesses, no-op stubs or host
  workarounds that hide the defect. Record it in `src/unsupported.txt` and fix the lifter or the
  runtime.
- Do not fake a result. A build that compiles or a window that opens is not evidence that the
  original behaviour works. Verify the actual behaviour, preferably against the original.
- Keep generated code and hand-written fixes separate. Generated files are regenerated; overrides
  belong in `runtime/override.c` or a documented host bridge.

## Accuracy rules for reverse engineering

These override convenience. A lift that compiles but is less correct is a regression.

- Correctness percentage is the top priority, and correctness is tracked per function.
- Size comes second. Never lower correctness to clear a linker blocker.
- If correctness drops, revert or rework the change.
- No assembly hacks, no inline assembly and no assembly shims or fake patches.
- No stubbing or shimming a function just so the build looks complete.
- Never invent logic, functions or structure that is not in the original binary. The only allowed
  shared helper is an inline one that serves several functions, adds no extra calls and raises the
  measured correctness.
- Avoid `goto` as a source-cleanup or control-flow-reshaping device.
- Generated C must stay instruction-faithful. Readable rewrites are separate, must keep the
  original address and behaviour, and must be verified against the original bytes.
- A fix is only accepted after runtime evidence: differential output, a trace, or a reproducible
  behavioural comparison. A successful build or a 200 response is not evidence.

## Evidence rules

- Every non-trivial claim says how it is known: `observed`, `derived` or `inferred`, with an
  authority and a location. See `docs/17-evidence.md` and `schemas/evidence.schema.json`.
- Keep `recomp/data/target.json` and `recomp/data/inventory.json` current. `static_shock.py
  verify` must pass before a milestone is called done.
- A name is not a fact because it fits. Names need a string, RTTI, vtable, property table or trace.
- State limitations. An unsupported instruction or an untested path is `partial`, not complete.
- Never present a guess as an observation, in code, docs or a commit message.

## Workflow

1. Fill `project.toml`. Verify every address against the PE headers and the IDA database.
2. Export with `pipeline/ida_export.py`. Check `functions.tsv`, `imports.txt`, `segments.txt`.
3. Run `pipeline/make_functions.py` and `pipeline/classify.py`.
4. Run `pipeline/gen.py --regenerate`. Read `src/unsupported.txt`; run `static_shock.py asm` for the x86 listing.
5. Run `pipeline/make_api.py` and `pipeline/gen_api.py`.
6. Write the identity records: `pipeline/manifest.py` and `pipeline/inventory.py`; run
   `static_shock.py verify` and `static_shock.py readiness`.
7. Build with `build.py`; fix compile errors without changing semantics.
7. Run; use the crash report, `bin/lift.map`, `RECOMP_TRACE`, `RECOMP_PROFILE` and the differential
   tester to find the first divergence.
8. Fix one layer at a time: lifter semantics, runtime, import ABI, then platform/front-end.
9. When a function becomes readable C, keep its address comment or name and add a differential
   test; never silently change behaviour.

## Debugging order

- First crash: map the host address through `bin/lift.map`, then inspect the guest state printed
  by the crash handler.
- Wrong values: compare the lifted function against the original with `pipeline/difftest.py` or a
  small harness, not by staring at the C.
- Missing window/input: check that the guest's `RegisterClass`/`CreateWindow` imports are bound and
  that mouse coordinates are converted from client space to the guest canvas before dispatch.
- Wrong audio: dump the PCM the guest hands to the audio API before changing the device or mixer.
- Import returns: a `double` return lives in the emulated x87 `ST(0)`, not in `eax:edx`. Route every
  FP-returning import through `S_MATHFP`.
- Hangs: check `RECOMP_TRACE`, thread creation and waits before adding timeouts.

## Definition of done

The program starts from a clean checkout, maps its data, runs the lifted code, and reproduces the
target behaviour you set out to preserve. The build is reproducible, the unsupported list is empty
or explained, and no original binary or asset is committed.
