# IDA export

The export is the only step that needs IDA. Everything after it is plain Python.

## Running it

Headless:

```sh
idat.exe -A -S"pipeline/ida_export.py" -Lida/ida.log target.exe
```

Or from the IDA console:

```python
exec(open("pipeline/ida_export.py").read())
```

Set `SS_IDA_OUT` to the output directory (default: `project.toml` -> `ida.out`).

## What it writes

| File | Contents |
|---|---|
| `functions.tsv` | `address`, `name`, `size`, `lib` for every function. |
| `segments.txt` | Section name and range, plus `entry`. |
| `imports.txt` | `module`, IAT address, import name, ordinal. |
| `strings.tsv` | Address and text of every string IDA recognizes. |
| `chunk_*.c` | Hex-Rays pseudocode in chunks. Reading material, never compiled. |
| `index.tsv` | Function -> chunk map. |

## Signatures

The exporter applies the usual MSVC runtime/MFC/ATL signatures. Named library functions make the
lift easier to read and let `classify.py` separate CRT/library code from application code. If sig
files are missing, the export continues and logs a skip.

## Verify

- `functions.tsv` has no duplicate addresses and covers the executable section.
- `segments.txt` entry equals `project.entry`.
- `imports.txt` contains every module the program actually loads; a missing DLL is a runtime
  warning, not a lift failure.
- The pseudocode chunks include the functions you care about; `hexrays available: True`.

## Assembly listings

`python static_shock.py asm` disassembles every lifted function from the original bytes and writes
`asm/` in the same layout as `src/`, plus `asm/index.tsv`. It needs `recomp/data/functions.tsv` and
the original PE.

## Do not commit

The `.i64` database and any pseudocode that embeds original strings or assets are analysis output.
`ida/*.i64` is ignored. Review before publishing chunks.
