# Target analysis

Before touching the lifter, establish these facts. They go into `project.toml`.

## From the PE headers

- `ImageBase` (DOS header -> PE -> optional header +28)
- `AddressOfEntryPoint` (optional header +16), absolute = image base + RVA
- `SizeOfImage`, section table, and which section is executable
- imports: module, IAT slot, name or ordinal
- resources and the data you must embed

Use `pipeline/pe_image.py` or:

```sh
python -c "import sys; sys.path.insert(0,'pipeline'); from pe_image import Image; im=Image('target.exe'); print(hex(im.base), hex(im.entry)); [print(s[:5]) for s in im.secs]"
```

## Choosing ranges

`project.code_lo` / `code_hi` should cover the executable section that contains the program. The
lifter uses this range when deciding whether an immediate operand is a code address. If the range
is too wide, data is mistaken for code; if too narrow, callbacks are missed.

`project.image_end` is the end of the mapped image. The runtime uses it for the data map and the
profile array.

`project.guest_size` is the size of the linker's `.guest` section; it must cover the original
image and leave room for heap, stack and locale mappings. Sixteen megabytes is a good default for
small programs; large programs need more.

## Identify the runtime

- MSVC 8.0/9.0 programs import `msvcr80`/`msvcr90` and `msvcp80`/`msvcp90`.
- A statically linked CRT appears as a large block of functions near the end of `.text`.
- MFC/ATL names are mangled and can be recognized from RTTI and the import names.
- Third-party libraries (zlib, libjpeg, OpenAL, FreeType) are easier to replace with native
  libraries than to lift. Keep the executable's own copies only for analysis.

## What to lift

Lift the program's code and the CRT functions it calls. Do not lift code that is never reached.
The generator's data-referenced call detection finds function pointers (vtables, callbacks,
initializer tables) that the function list may have missed.

## What not to lift

- Packed/obfuscated regions that must be unpacked at runtime; unpack them first, then use the
  unpacked image.
- Kernel drivers and privileged code.
- Code you do not have the right to reverse engineer.
