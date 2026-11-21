# Porting checklist

Use this for every new target. Do not skip a step because the program is "simple"; the failures
are almost always in the skipped step.

## 1. Legal and scope

- [ ] You own a legal copy and may reverse engineer it.
- [ ] The original binary is outside the repository or in an ignored folder.
- [ ] You know what behaviour you are preserving.

## 2. PE facts

- [ ] Image base, entry point, image size.
- [ ] Executable section range (`code_lo`, `code_hi`).
- [ ] Image end (`image_end`).
- [ ] Imports and their DLLs.
- [ ] Resources and data files the program needs at run time.

Put the values in `project.toml`.

## 3. Export

- [ ] IDA auto-analysis completed.
- [ ] Signatures applied.
- [ ] `functions.tsv`, `segments.txt`, `imports.txt`, `strings.tsv` produced.
- [ ] Entry point matches `project.entry`.
- [ ] Hex-Rays chunks exist for the functions you will read.

## 4. Function table

- [ ] `make_functions.py` output has no duplicate addresses.
- [ ] `classify.py` categories are sane; CRT and libraries separated.
- [ ] `skip_categories` does not remove real code.

## 5. Lift

- [ ] `gen.py --regenerate` completes.
- [ ] `src/unsupported.txt` is empty or every entry is understood.
- [ ] Spot-check 10 functions against IDA.
- [ ] Data-referenced callbacks were lifted (vtables, initializers).
- [ ] `src/image.bin` exists and contains the data sections.

## 6. API table

- [ ] `make_api.py` found every import.
- [ ] cdecl/stdcall/thiscall counts are correct.
- [ ] FP-returning imports are in the `S_MATHFP` list.
- [ ] Callback imports use `rt_tramp`.
- [ ] Guest-pointer structures have specials.

## 7. Build

- [ ] 32-bit compiler.
- [ ] Section layout matches `project.toml`.
- [ ] `rt_preentry` is the entry and reserves the range.
- [ ] Stack/heap do not overlap the guest.
- [ ] `bin/lift.map` was produced.

## 8. Boot

- [ ] Image maps at the expected base.
- [ ] Imports bind; no required DLL is missing.
- [ ] CRT initializers run (`_initterm`).
- [ ] The program reaches its own window/message loop.

## 9. Behaviour

- [ ] Window appears at the right size.
- [ ] Input coordinates are correct (click and hover).
- [ ] Presentation is correct at the target aspect ratio.
- [ ] Audio PCM is correct before the device layer.
- [ ] File paths and the working folder match the original.
- [ ] No crash after several minutes of interaction.

## 10. Hardening

- [ ] Unsupported list is empty or documented.
- [ ] Crash report includes a usable map.
- [ ] Differential tests cover the functions you rewrote.
- [ ] No original binary, assets or keys are committed.
- [ ] README records the SHA-256 of the original and the supported scope.
