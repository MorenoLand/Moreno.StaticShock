# WebAssembly import layer notes

`runtime/wasm/imports.c` is a weak hook; a port supplies `wasm_lookup()`. These notes come from a
real wasm port of a 1999 Windows game and record the patterns that made its audio, dialogs and
input work. The DLL and structure layouts below are evidence from that target; verify offsets in
your own binary before using them.

## Dynamic imports

Some engines resolve their whole audio API at run time:

- `LoadLibraryA("sos9503.dll")` plus roughly 100 `GetProcAddress` calls.
- Return a non-null fake module handle for the name and register every requested function.
- Keep the name-to-argument-count table generated from the original import table (and from strings
  in the image when the name is built at run time). The local DLL's export table is not a reliable
  source: the program may ask for names that build does not export.
- `GetProcAddress` must be permissive and log misses loudly. One truncated name silently disables a
  whole feature with no other symptom.

## Memory MMIO for WAV resources

Engines load WAV resources with `mmioOpenA(NULL, &info, MMIO_READ)` where `info.fccIOProc` is
`'MEM '` and `pchBuffer`/`cchBuffer` point at guest memory. A stub that returns 0 leaves the format
and chunk sizes as stack garbage.

Implement a small in-memory MMIO layer:

| Call | Behaviour |
|---|---|
| `mmioOpenA` | Slot with `base = info->pchBuffer` (`+0x18`), `size = info->cchBuffer` (`+0x14`), `pos = 0`; return a handle. |
| `mmioDescend` | `MMIO_FINDRIFF` (`0x20`) validates `RIFF`/size/form; `MMIO_FINDCHUNK` (`0x10`) walks chunks; fill `MMCKINFO` (`ckid`, `cksize`, `fccType`, `dwDataOffset`, `dwFlags`). |
| `mmioRead` | Copy `min(len, size - pos)` to guest memory, advance, return the byte count. |
| `mmioAscend` | `pos = dwDataOffset + cksize`, rounded up to even. |
| `mmioClose` | Free the slot. |

`MMIOINFO` fields used: `fccIOProc +4`, `cchBuffer +0x14`, `pchBuffer +0x18`.

## waveOut fallback

If the same engine also has a `waveOut*` path:

- `WAVEHDR.lpData` is at `+0`, `dwBufferLength` at `+4`.
- Track the `WAVEFORMATEX` from `waveOutOpen`: channels `+2`, rate `+4`, bits `+14`.
- `waveOutPrepareHeader` sets `WHDR_PREPARED` (`+0x10 |= 2`); `waveOutWrite` sets `WHDR_DONE` and
  queues the PCM; `waveOutGetPosition` advances monotonically if polled.

## Web Audio

- Create or resume the `AudioContext` inside the user-gesture call chain; browsers start it
  suspended. One shared context is enough.
- Decode unsigned 8-bit as `(byte - 128) / 128` and signed 16-bit little-endian; interleaved mono
  and stereo.
- One-shot samples: decode synchronously before returning; the guest reuses its buffers.
- Streams: keep one slot per stream id with `{nodes, end}`. At `Start`, schedule all queued buffers
  back-to-back on the context timeline; later `AddBuffer` calls append at `end`. `Stop`/`Release`
  cancels scheduled sources.
- Do not log every `UserService`-style poll; it drowns the console while audio plays.

## Case study: Sierra SOS

The target's audio DLL uses these layouts; they are recorded as an example, not as a template API.

- `sosDIGIStartSample(driver, descriptor, &handle)`: data `+0x00`, length `+0x10`, rate `+0x38`
  (`u16`), bits `+0x3c` (`u32`), channels `+0x40` (`u32`).
- `sosDIGIStreamAcquire(driver, fmt, &stream)` copies `0xfc` bytes from `fmt + 2`; rate is at
  `fmt + 0x3a` (`u16`), bits `+0x3e`, channels `+0x42`.
- Stream buffer descriptors: PCM pointer `+2`, byte length `+0xe`.
- `sosDIGIDetectFindFirst` must fill the caps structure; zero caps disable the driver.
- Streams call `StartSample` internally in the real DLL; emulating only `StartSample` covers direct
  SFX but not voice or music.

## Child windows and input

Returning the full framebuffer rect for every window breaks dialog hit-testing.

- Record `CreateWindowExA` position/size per window and update it in `MoveWindow`.
- Answer `GetClientRect`/`GetWindowRect` per window.
- Route a click to the topmost child containing the point and send window-relative
  `lParam = ((y - win.y) << 16) | (x - win.x)`.
- Never translate coordinates for the main game window: engines that draw into a fixed framebuffer
  use absolute canvas coordinates in their own `WndProc`. Track a real child list; a recreated main
  window keeps the full-canvas rect.
- Keep `GetCursorPos` and `ScreenToClient` on the same origin model; mixing absolute and relative
  coordinates opens menus that never select.

## Diagnostics

- Log calls as `module!name(args)` and filter by subsystem.
- Print the engine's own formatted debug strings when they pass through a no-op logging import;
  filtering for `Sample`, `Sound`, `wave`, `MIDI` surfaces the real failure.
- Temporary guest-side prints at the entry points separate "not triggered" from "triggered but
  silent".
- Verified end-to-end in the reference port: a WAV resource reached `StartSample` with 5,600 bytes
  at 11,025 Hz, 8-bit mono, and the Web Audio path produced audible output.
