# WebAssembly port

wasm32 is a good fit for the 32-bit lift: a guest address is a 32-bit offset into linear memory,
which is the same shape as the native "guest address is a host pointer" model. The port is still
real work, because every operating-system edge changes.

## What stays the same

- The lifted C, the register model and the x87 emulation.
- The import sentinel table and `call_ind`.
- The data image (`src/image.bin`) and the function table.
- The rule that unimplemented calls fail loudly.

## Memory layout

Emscripten places its own static data, stack and heap in linear memory. The guest image must be
reserved at a fixed offset:

- Set a fixed `INITIAL_MEMORY` and, if possible, a `GLOBAL_BASE` above the guest range, or
- reserve the guest range first (`emscripten_resize_heap` / a custom allocator) and keep the
  host's static data above it.

Guest address `A` becomes `HEAPU8[A]` only if the image base is mapped at that exact offset. Pick
an image base that does not collide with Emscripten's static data (for example `0x10000000` if the
original's base is free, or shift the whole guest image and translate addresses). Keep the
translation in one place (`guest_ptr`).

The `.guest`/`.tail` linker sections do not exist in wasm. Reserve the range in the module's
memory and treat it as the guest heap.

## Build

```sh
emcc -O2 -sINITIAL_MEMORY=268435456 -sALLOW_MEMORY_GROWTH=1 \
     -sSTACK_SIZE=1048576 -sFORCE_FILESYSTEM=1 \
     --preload-file data@/data \
     -o bin/host.html \
     src/*.c runtime/*.c \
     --js-library runtime/wasm/w32.js
```

- `-sASSERTIONS=2` and `-gsource-map` for debugging; drop them for release.
- `-sEXPORTED_FUNCTIONS=_main,_guest_call` for the glue.
- `-sEXPORTED_RUNTIME_METHODS=ccall,cwrap,HEAPU8`.
- `-pthread` only with `SharedArrayBuffer` and COOP/COEP headers.

## Imports

Replace the Windows import bridge with a JavaScript/WASI layer. `runtime/wasm/w32.js` provides the
same names the API table expects:

- `user32`: window creation is a canvas; `RegisterClass`/`CreateWindow` return handles; the guest
  WndProc is called from DOM event listeners with the message and `lParam`.
- `gdi32`: `SetDIBitsToDevice` copies the guest DIB to a canvas `ImageData`; `StretchDIBits`,
  `BitBlt` and `CreateCompatibleDC` are no-ops or canvas operations.
- `kernel32`: files through Emscripten FS, time, threads, critical sections, `GetModuleFileName`.
- `winmm`/OpenAL: Web Audio. Queue guest PCM buffers into `AudioBufferSourceNode`; decode only if
  the guest asks for a compressed format.
- `shell32`/`ole32`: return the minimal values the program checks.

The import table is generated exactly as for native; only `api_call_real`/`host_call` changes.

## Window and message loop

The guest expects a blocking message loop (`GetMessage`/`DispatchMessage`). In a browser:

- Run the loop from `emscripten_set_main_loop` with a simulated `MSG` queue, or
- Use Asyncify to suspend the guest when it waits and resume on an event.

Do not busy-wait. DOM events should enqueue messages; `PeekMessage` drains them.

## Input

Map `mousemove`, `mousedown`, `mouseup`, `wheel`, `keydown`, `keyup` to the Windows messages the
guest already handles. Convert canvas coordinates to guest canvas coordinates with the same
client-to-canvas function the native host uses, including the origin subtraction. Test hover and
click separately; they are different paths in most engines.

## Presentation

The guest's `SetDIBitsToDevice` hook already caches the full canvas. In wasm:

1. Copy the cached DIB into an `ImageData`.
2. Draw it to an offscreen canvas at the guest canvas size.
3. Draw the offscreen canvas to the visible canvas with `drawImage`, scaled to the page.

Use `requestAnimationFrame`; never present from inside the guest's tight loop more than once per
frame.

## Files

`--preload-file data@/data` puts the legally obtained data in MEMFS. The guest's file paths are
Windows-style; translate separators and map the game folder to `/data` in the `CreateFile`/`fopen`
bridge. Writes go to MEMFS unless you add IndexedDB persistence.

## Audio

Web Audio needs a user gesture to start. Create the `AudioContext` on the first click and resume it.
Guest PCM is signed 16-bit; create an `AudioBuffer` with the guest's channel count and sample rate.
If the guest streams, keep a ring of `AudioBufferSourceNode`s and drop the oldest when the queue is
full.

## Threads and blocking

The browser main thread cannot block. Options:

- Single-threaded: Asyncify around blocking imports.
- Worker: run the guest in a worker, communicate with the main thread for input/canvas; requires
  `SharedArrayBuffer` and cross-origin isolation.
- Emulate the guest's threads cooperatively; a `CreateThread` that only waits can be a task.

Keep the runtime's global guest lock; it already serializes guest threads.

## Debugging

- `-sASSERTIONS=2`, `-gsource-map`, and the browser console for host errors.
- Print guest `eip`, registers and the last function on a fault; map addresses with
  `bin/lift.map` (keep the map next to the wasm build).
- Use `emscripten_get_callstack` for host stacks.
- For a headless check, run the page in Playwright, take a screenshot, and compare with the native
  reference.

## Limits

- No DirectX, no native DLLs, no raw sockets. Every such import needs a web implementation or a
  documented failure.
- Audio and input require user interaction; a headless test must simulate it.
- 64-bit targets are a separate backend; wasm64 is not the same as x86-64.
