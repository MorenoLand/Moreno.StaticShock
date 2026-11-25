# Tooling reference

## Orchestrator

```sh
python static_shock.py ida         # headless IDA export
python static_shock.py analyze     # external analyzer procedure inventory (alternative)
python static_shock.py functions   # make_functions + classify
python static_shock.py rtti        # MSVC RTTI classes, vtables and vfunc slots
python static_shock.py lift        # gen.py --regenerate
python static_shock.py api         # make_api + gen_api
python static_shock.py manifest    # write the target identity record
python static_shock.py inventory   # write the machine-readable function/import map
python static_shock.py verify      # verify the records and Python syntax
python static_shock.py readiness   # fail-closed readiness report
python static_shock.py progress    # work status + HTML dashboard
python static_shock.py unknowns    # list / add / resolve open questions
python static_shock.py build       # build.py
python static_shock.py all         # functions + api + lift + build
python static_shock.py run -- <args>
```

`[ida].idat` in `project.toml` (or `SS_IDAT`) points at `idat.exe`. The other steps use
`project.toml` for every path and range.

## Scripts

| Script | Input | Output |
|---|---|---|
| `pipeline/ida_export.py` | the PE, inside IDA | `ida/functions.tsv`, `segments.txt`, `imports.txt`, `strings.tsv`, chunks |
| `pipeline/make_functions.py` | `ida/functions.tsv` | `recomp/data/functions.tsv` |
| `pipeline/classify.py` | function table + ranges | classified function table |
| `pipeline/gen.py` | PE + classified table | `src/*.c`, `protos.h`, `dispatch.c`, `stubs.c`, `image.bin` |
| `pipeline/make_api.py` | `ida/imports.txt` + MinGW libs | `recomp/data/api_table.json` |
| `pipeline/gen_api.py` | `api_table.json` | `runtime/api_gen.c` |
| `pipeline/manifest.py` | target PE | `recomp/data/target.json` |
| `pipeline/inventory.py` | function/import tables | `recomp/data/inventory.json` |
| `pipeline/pe_image.py` | any PE32 | section/address reader |
| `pipeline/lift.py` | PE + function starts | C for one function |
| `pipeline/extract_asm.py` | `src/` layout + `functions.tsv` | `asm/` listing and `asm/index.tsv` (optional) |
| `pipeline/extract_res.py` | PE resource directory | `recomp/data/<exe>.res` for the linker |
| `pipeline/split_pseudo.py` | `ida/chunk_*.c` | `pseudo/<ea>_<name>.c` and `pseudo/index.tsv` |
| `tests/difftest_cli.py` | original + host + cases | exit/stdout/stderr/files per case |
| `tests/diff_corpus.py` | original + host + corpus | the same comparison over a folder |
| `pipeline/rtti_names.py` | PE data | RTTI/vtable name proposals |
| `pipeline/addr2fn.py` | `bin/lift.map` | function for a crash address |
| `pipeline/difftest.py` | original bytes + driver | differential results |

## Build flags

`build.py`:

- `--driver` builds the differential driver (`bin/recomp.exe`) instead of the client.
- `--jobs N` is accepted; the current build compiles sequentially.

The linker layout is computed from `project.toml`; do not hand-edit it. The map is
`bin/lift.map`.

## Environment

| Variable | Use |
|---|---|
| `SS_EXE`, `SS_IDA_OUT`, `SS_MINGW32`, `SS_IDAT` | input overrides |
| `RECOMP_TRACE=1` | log every import |
| `RECOMP_LOGAPI=Name,...` | log selected imports |
| `RECOMP_IMAGE=<exe>` | map the original instead of the data image |
| `RECOMP_NOACCESS=1` | fault on uncovered code pages |
| `RECOMP_WATCH=lo-hi` | watch writes (build with `-DRT_WATCH`) |
| `RECOMP_PROFILE` / `RECOMP_PROF_SECONDS` | profile build |
| `RECOMP_ENTLOG=hex,...` | log selected function entries |

## Adding a backend

1. Add `arch` to `project.toml`.
2. Add a lifter for that ISA; do not overload the x86-32 lifter.
3. Add a runtime model with the same file boundaries (`rt`, `api`, `boot`, platform).
4. Add a build layout for the target pointer size and image base.
5. Keep `gen.py`/`classify.py`/`make_api.py` independent of the ISA where possible.
6. Document the exact differences in `docs/`, as `14-x64.md` does for x86-64.

The 32-bit backend must keep working while a second backend is developed.
