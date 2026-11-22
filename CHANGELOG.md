# Changelog

All notable changes to this template are recorded here. The format follows Keep a Changelog and
the project uses semantic versioning for the pipeline.

## [Unreleased]

### Added

- wasm32 host layer: linear-memory services, sentinel dispatch, x87 special imports, browser input
  queue, chunked preload shell, Emscripten build and a Node host test.

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
