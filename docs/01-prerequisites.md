# Prerequisites

## Host

- Windows 10/11 x64 for the native host. The wasm32 host layer is in the repository; Linux is not a
  shipped backend.
- 32-bit MinGW-w64 on Windows: `i686-w64-mingw32-gcc` must be on `PATH`.
  The default `project.toml` points at `D:/msys64/mingw32`; change it.
- Python 3.11 or newer.
- `capstone` for the lifter: `pip install capstone`.

## Analysis

- IDA Pro with Hex-Rays is the reference exporter. The pipeline consumes plain TSV/JSON, so a
  Ghidra export or a custom disassembler can be adapted; the lifter itself only needs Capstone.
- The original executable, legally obtained. Keep it outside the repository or in an ignored
  folder. Never commit it.

## Toolchain check

```sh
i686-w64-mingw32-gcc --version
python --version
python -c "import capstone; print(capstone.__version__)"
```

The runtime must be compiled as a 32-bit program. A 64-bit build breaks the "guest address is a
host pointer" model immediately.

## Environment variables

| Variable | Meaning |
|---|---|
| `SS_EXE` | Original PE path (overrides `project.exe`). |
| `SS_IDA_OUT` | IDA export directory (overrides `ida.out`). |
| `SS_MINGW32` | MinGW root (overrides `build.mingw32`). |
| `RECOMP_TRACE=1` | Log every bound import call. Expensive; use it briefly. |
| `RECOMP_IMAGE=<exe>` | Map the original executable instead of the embedded data image, for comparison. |
| `RECOMP_NOACCESS=1` | Make code pages without data unreadable. |
| `RECOMP_PROFILE` | Build-time flag for per-function profiling. |
| `RECOMP_WATCH=lo-hi` | Build-time flag to trace writes into a guest range. |

## First build

The template has no target. Fill `project.toml` and follow `docs/11-porting-checklist.md`.
