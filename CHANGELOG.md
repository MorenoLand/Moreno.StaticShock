# Changelog

All notable changes to this template are recorded here. The format follows Keep a Changelog and
the project uses semantic versioning for the pipeline.

## [Unreleased]

### Added

- wasm32 host layer: linear-memory services, sentinel dispatch, x87 special imports, browser input
  queue, chunked preload shell, Emscripten build and a Node host test.
- Delphi/VCL support: SEH continuations and `pop reg; jmp reg` returns in the lifter, optional IDA
  code map, shared flag state, `fbstp` BCD, TLS block setup, window-procedure identity translation,
  MakeObjectInstance thunks, a guest SEH bridge (`RaiseException`/`RtlUnwind`), exception landings
  with `jmp_ind`/`LandRec`, Delphi exception reporting and `docs/22-delphi.md`.
- Build embeds `src/image.bin` as `rt_image_blob` and links extracted `.res` resources; `windres`
  fallback no longer treats an empty path as a compiler; `.guest`/`.tail` are bss-only.
- Console hosts keep stdout/stderr clean: boot diagnostics are behind `RECOMP_BOOT_LOG`, arguments
  are passed through and `RECOMP_DIR` selects a data folder.
- `[lift].extra` registers jump-only continuations; `[lift].data` keeps IDA functions that are data
  in the image without lifting them.
- `pipeline/split_pseudo.py` writes one pseudocode file per function; `asm/` and `pseudo/` are kept
  in the workspace.
- Dispatcher drops skipped functions; the code map accepts unaligned VMT thunks; `gen_api.py`
  honours `[imports.nargs]`; continuation discovery accepts argument pushes and stays inside the
  code map; file-dialog hooks and heap MakeObjectInstance thunks are trampolined.
- `docs/23-wasm-imports.md` records the wasm import patterns: dynamic imports, memory MMIO, WAV and
  Web Audio, child windows and diagnostics.

## [0.1.0] - 2026-11-21

### Added

- PE32 analysis export, function table, instruction lifter, dispatch generation and data image.
- C runtime: guest registers, x87/SSE, image mapping, import sentinels, threads, boot, crash map.
- 32-bit MinGW build with explicit `.guest`/`.tail`/`.text` layout and pre-CRT range reservation.
- Optional external-analyzer backend for procedure and import discovery.
- RTTI inventory: type descriptors, complete object locators, vtables, base classes and vfunc slots.
- Target manifest, machine-readable inventory, evidence schema, unknowns registry and fail-closed
  readiness report.
- Work queue and self-contained HTML progress dashboard.
- Documentation for the model, lifting, imports, host, build, debugging, porting, WASM, x86-64,
  naming, evidence, verification and analysis backends.
- Community files: contributing guide, code of conduct, security policy, support, governance,
  authors, issue forms and pull request template.
- MIT license.

### Notes

- The shipped backend is x86-32. x86-64 is documented as a separate backend.
- The template ships no target binary, game assets or keys.
