# Build and link layout

## Why the layout is not the default

The runtime assumes a guest address is a host pointer. The host executable must therefore reserve
the guest image range and keep its own text, stack, heap and CRT mappings out of it.

`build.py` computes:

```
guest = image_base + 0x1000
tail  = guest + guest_size
text  = align_up(tail + tail_size, 0x1000)
```

and links with:

```
--image-base <image_base>
--section-start=.guest=<guest>
--section-start=.tail=<tail>
--section-start=.text=<text>
--disable-reloc-section
--disable-dynamicbase
--large-address-aware
-e rt_preentry
```

- `.guest` is the reserved guest range. `guest_pad.c` expands it to the start of `.text`, and
  `rt_load_image` fills the data pieces.
- `.tail` covers the rest of the guest address space the program may allocate.
- `.guest`, `.tail` and `guest_pad.c` are bss: the loader maps them zero-filled and the file stores
  no bytes. `.guest` reserves exactly `guest_size`, `.tail` exactly `tail_size`; do not let one
  include the other or the linker reports overlapping LMAs.
- `.text` is the host code; it must start after the guest range.
- `rt_preentry` reserves the range before the CRT creates its stack and locale mappings, then calls
  `mainCRTStartup`.

If the image base or image size changes, change `project.toml`; do not hand-edit linker flags.

## Stack and heap

`--stack` and `--heap` reserve host memory for the guest's own stack/heap and for the host CRT.
They must not overlap the guest range. The defaults (256 MB each) are generous; a small target can
use less, a large one may need more. This is host address space, not committed RAM.

## 32-bit

The model requires a 32-bit host build. Check:

```sh
i686-w64-mingw32-gcc -dumpmachine
```

It must print an `i686` target. A 64-bit compiler will produce host pointers that do not fit the
guest's 32-bit registers.

## WebAssembly

`build_wasm.py` compiles the same `src/` and `image.bin` with Emscripten. The guest range is reserved
below `GLOBAL_BASE`; the native linker layout above does not apply. See `docs/12-wasm.md` for the
memory layout, build flags and the per-target import hook.

## Image and resources

`build.py` writes `build/image_blob.c`, which embeds `src/image.bin` in `.rodata` as
`rt_image_blob`, so the host can map the data image at its original addresses. If
`recomp/data/*.res` exists (or `[build].resources` names one), it is linked with `windres -J res`,
so `FindResource`/`LoadResource` see the original forms, icons and string tables.
`pipeline/extract_res.py` writes that `.res` from the PE resource directory.

## Reproducibility

- Keep `project.toml` under version control; it is the build description.
- Do not commit `bin/`, `build/`, `ida/` or `src/image.bin`.
- The generated C is deterministic for a given IDA export and lifter version.
- Record the original binary's SHA-256 in the project README, not the binary itself.
- `bin/lift.map` is generated; keep it with a release if you publish crash reports.

## Icon and manifest

`project.icon` is optional. `build.py` generates a resource script with the manifest and, when an
icon is set, compiles it with `windres`. Without `windres` the build continues without a resource.
