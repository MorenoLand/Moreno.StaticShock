# Analysis backends and the work dashboard

## IDA backend

The default path uses IDA's function table and imports:

```sh
idat.exe -A -S"pipeline/ida_export.py" -Lida/ida.log target.exe
python pipeline/make_functions.py
python pipeline/classify.py
```

It produces the most complete function boundaries and names. Use it when IDA is available.

## External analyzer backend

An external native analyzer can supply the local procedure list and the PE import table instead
of the IDA export script. The lifter decodes the actual instructions itself, so the analyzer only
has to provide reliable function starts and names.

```toml
[analyzer]
command  = ""          # the analyzer executable; SS_ANALYZER overrides it
provider = "ghidra"    # passed through to the analyzer
timeout  = 900
```

```sh
python static_shock.py analyze --provider ghidra
python pipeline/make_functions.py
python pipeline/classify.py
```

The expected command is:

```sh
<analyzer> search <target> ".*" --kind procedures --mode regex --provider <provider> --format json
```

and the expected JSON is an evidence object whose `raw_result` (or `normalized_result`) is a list
of `{ "address": "0x...", "value": "name" }`. If your analyzer uses a different CLI or schema,
adapt `call()` in `pipeline/analyzer_export.py`; the parser only needs addresses and names.

`analyzer_export.py` writes:

- `ida/functions.tsv` - local procedure addresses, names and approximate sizes
- `ida/imports.txt` - module, IAT slot and name from the PE
- `recomp/data/analyzer.json` - evidence id, subject digest, provider, operation and limitations
- `analysis/provider/procedures.json` - the full evidence record

Per-function dossier on demand:

```sh
python static_shock.py analyze --function 0x401000 --provider ghidra
```

It writes `analysis/provider/functions/<address>.json` with assembly, pseudocode, callers, callees,
references and basic blocks. Use it for the function you are working on, not for a bulk export.

Limitations:

- Sizes are approximated from the next local procedure; the lifter's recursive decode is the
  authority on the body.
- Names come from the provider. Treat them as observations with provider authority, not as
  original symbols.
- The analyzer must be installed and its provider configured.
- Preserve the provider's limitations in the evidence record.

## Why not the ROM decompiler for this

The ROM-oriented decompiler is archived and targets console images with their original compilers,
where a byte-for-byte rebuild is possible. A PE x86 lift does not have that compiler/flags pair, so
its byte-match judge is not a valid acceptance test here. What does transfer is the workflow:

- claim one function at a time
- keep a status per function
- show progress as a function map
- treat a match as evidence, never as a guess

That workflow is implemented directly in `progress.py`.

## Work dashboard

`recomp/data/work.json` holds per-function status:

```json
{
  "schema": 1,
  "functions": {
    "0x00401000": {"status": "in_progress", "owner": "agent-a", "note": "decoding the switch"}
  }
}
```

Statuses: `unclaimed`, `in_progress`, `lifted`, `verified`, `blocked`, `unsupported`.

```sh
python static_shock.py progress
python static_shock.py progress --set 0x00401000 --status in_progress --owner agent-a --note "switch"
```

It writes `reports/progress.md` and `reports/progress.html`. The HTML is self-contained: counts per
status, a searchable table, and a clear `unsupported`/`blocked` view. `verified` is refused in
practice for a function with unsupported instructions: the report downgrades it to `blocked`.

The dashboard is a work aid, not evidence. A function is verified only when the differential or
behavioural evidence exists (`18-verification.md`).
