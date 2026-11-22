# WebAssembly port

**Status: host layer implemented and tested; imports are per target.** The same lifted C and the
same `image.bin` build for wasm32. `runtime/wasm/` replaces the Win32 host; the lifter and the
guest model do not change.

No Win32 emulation is shipped. A port implements `wasm_lookup()` in `runtime/wasm/imports.c`;
imports without an implementation abort with their `module!name`.

## What the repository provides

| File | Purpose |
|---|---|
| `runtime/wasm/sys.c` | Fixed-range checks, heap allocation, `rt_readable`, image blob loader. |
| `runtime/wasm/api.c` | Sentinel dispatch, stdcall/cdecl stack cleanup, TEB/TLS, guest callbacks. |
| `runtime/wasm/special.c` | `_initterm`, qsort/bsearch, GetProcAddress/GetModuleHandle/GetModuleFileName, x87 math returns. |
| `runtime/wasm/boot.c` | Binds every import, allocates the guest stack and runs the OEP. |
| `runtime/wasm/imports.c` | Weak `wasm_lookup()`; the per-target Win32 implementation point. |
| `runtime/wasm/input.c` | Browser event queue filled by `web.js`. |
| `build_wasm.py` | Emscripten build: incremental objects, `GLOBAL_BASE`, Asyncify, data preload. |
| `web/` | Canvas shell, input mapping, chunked data loader and development server. |
| `tests/run_wasm_test.py` | Builds and runs the host smoke test under Node. |

## Memory

The guest image keeps its original base. Everything below `GLOBAL_BASE` is reserved linear memory:

- `GLOBAL_BASE` defaults to `image_base + guest_size + tail_size`, rounded up to 64 KB.
  Override it with `[wasm].global_base`.
- Host static data, the C stack and `malloc` start at `GLOBAL_BASE`, so they cannot overlap the
  guest image or the guest heap.
- The guest stack is a host allocation (`[wasm].guest_stack`, 8 MiB by default).
- `[wasm].initial_memory` defaults to 256 MiB and growth is enabled.
- `src/image.bin` is preloaded as `/image.bin` and copied to its recorded virtual addresses.

`doctor` checks that the image ends below `GLOBAL_BASE` and that `INITIAL_MEMORY` leaves room above
it.

## Dispatch

A lifted import call goes through `api_dispatch(sentinel)`. The wasm version reads the arguments
from the guest stack, calls the C emulation directly, writes `eax`/`edx`, then removes the return
address and, for stdcall, the arguments. cdecl leaves its arguments to the caller. No host
trampolines and no machine code are involved.

## Build

```sh
python build_wasm.py --preload-data
python web/serve.py bin/wasm 8080
```

Configuration in `project.toml`:

```toml
[wasm]
emcc           = ""          # empty: SS_EMCC, build/emsdk/upstream/emscripten, then PATH
global_base    = 0           # 0: computed from the image layout
initial_memory = 0x10000000
stack_size     = 0x1000000
guest_stack    = 0x800000
width          = 640
height         = 480
data_dir       = ""
data_parts     = 4
```

The build writes `bin/wasm/host.js`, `host.wasm` and, when a data directory is preloaded,
`host.data.partN`. `web/index.html` is rendered with the title, canvas size and part count.

## Per-port imports

`wasm_lookup(module, name)` returns an `ApiEmu` or `NULL`. Implement the functions the target
actually calls; do not return fake successes for the rest, because a missing import aborts with its
name. Typical groups:

- `kernel32`: files through the Emscripten FS, time, critical sections, module and command line.
- `user32`: one canvas window, a `WNDPROC`, and a message queue drained by `PeekMessageA`.
- `gdi32`: `SetDIBitsToDevice` / `StretchDIBits` into an `ImageData` and `putImageData`.
- `winmm`/OpenAL: Web Audio, created on a user gesture.
- CRT: `_initterm`, qsort/bsearch, printf-family shims; the runtime covers the specials it knows.

Blocking loops (`GetMessage`) need Asyncify, which the build enables. Do not busy-wait.

## Validation

```sh
python tests/run_wasm_test.py
```

The test builds `runtime/rt.c`, the wasm host and `tests/wasm/host_test.c` with emcc, preloads a
one-piece image, runs under Node and checks stdcall/cdecl cleanup, specials, TEB fields,
`rt_readable` bounds and image placement. It is a host test, not a game boot.

## Limits

- No Win32 import emulation is included; every port supplies its own.
- No threads, DirectX, native DLLs or raw sockets.
- Audio needs a user gesture; headless tests must simulate it.
- x86-64 is a separate backend; wasm64 is not x86-64.
- The wasm package contains the original program's data. Build it only from a copy you legally own
  and do not publish the package.
