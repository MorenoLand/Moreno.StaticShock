# Documentation index

| File | Read it for |
|---|---|
| [00-overview.md](00-overview.md) | The model: what is lifted, what the runtime does, what is not emulated. |
| [01-prerequisites.md](01-prerequisites.md) | Tools, Python packages, MinGW, IDA and environment. |
| [02-target-analysis.md](02-target-analysis.md) | Reading the PE, choosing ranges, identifying CRT and libraries. |
| [03-ida-export.md](03-ida-export.md) | Running the headless IDA export and checking its output. |
| [04-function-table.md](04-function-table.md) | Building and classifying the function list. |
| [05-lifting.md](05-lifting.md) | Instruction semantics, flags, control flow, x87 and SSE, unsupported cases. |
| [06-runtime.md](06-runtime.md) | Registers, guest memory, stack, threads, TLS, SEH, CRT. |
| [07-imports.md](07-imports.md) | Sentinel imports, calling conventions, pointer arguments, callbacks, FP returns. |
| [08-host.md](08-host.md) | Window, message loop, input mapping, stretched presentation, audio. |
| [09-build.md](09-build.md) | Image base, section layout, linker flags, stack and heap, reproducible builds. |
| [10-debugging.md](10-debugging.md) | Crash maps, traces, profiling, differential testing. |
| [11-porting-checklist.md](11-porting-checklist.md) | A step-by-step checklist for a new target. |
| [12-wasm.md](12-wasm.md) | wasm32 host layer, Emscripten build, per-target imports and limits. |
| [13-lessons.md](13-lessons.md) | Failure modes seen in real lifts and how to avoid them. |
| [14-x64.md](14-x64.md) | The x86-64 backend design; the shipped backend is x86-32. |
| [15-naming.md](15-naming.md) | Evidence-based naming and readable rewrites without inventing behaviour. |
| [16-tooling.md](16-tooling.md) | Script and orchestrator reference, environment variables, adding a backend. |
| [17-evidence.md](17-evidence.md) | Claims, confidence, authority, limitations and the machine-readable records. |
| [18-verification.md](18-verification.md) | Identity, inventory, fixtures, differential tests, replay and clean-checkout checks. |
| [19-readiness.md](19-readiness.md) | Fail-closed readiness report and the evidence-backed unknowns registry. |
| [20-analysis-backends.md](20-analysis-backends.md) | IDA vs external analyzer backends, per-function dossiers and the work dashboard. |
| [21-rtti.md](21-rtti.md) | MSVC RTTI classes, vtables, base classes and vfunc slots. |
| [22-delphi.md](22-delphi.md) | Delphi/VCL detection, VMT and dynamic methods, SEH, DFM resources, thunks and verification. |
| [23-wasm-imports.md](23-wasm-imports.md) | Per-port wasm import patterns: dynamic imports, MMIO, audio, child windows, diagnostics. |
| [24-porting-fidelity.md](24-porting-fidelity.md) | Taking a checked C lift to another language at 1:1 fidelity. |

Start with the overview and the checklist. Everything else is reference material.
