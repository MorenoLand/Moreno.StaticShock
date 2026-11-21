# Readiness and open questions

A project can compile, open a window and still be far from correct. Readiness is a fail-closed
summary of what is actually known; it is not a claim of equivalence.

## Statuses

| Status | Meaning |
|---|---|
| `pass` | The check has direct evidence and no known limitation. |
| `fail` | The check was run and did not pass. |
| `unknown` | There is not enough evidence either way. |
| `unsupported` | A required capability is missing (for example an unsupported instruction). |
| `skipped` | The check does not apply. |

Only `pass` satisfies a required check. `unknown`, `unsupported`, `skipped` and `fail` never
aggregate to ready.

## Report

```sh
python static_shock.py readiness
```

Writes `recomp/data/readiness.json`:

```json
{
  "schema": 1,
  "ready": false,
  "status": "partial",
  "counts": {"pass": 4, "unknown": 2, "unsupported": 1},
  "checks": [
    {
      "id": "lift.unsupported",
      "required": true,
      "status": "unsupported",
      "detail": "12 unsupported instruction site(s)",
      "evidence": ["src/unsupported.txt"]
    }
  ],
  "limitations": ["Readiness is not behavioural equivalence."]
}
```

Required checks are identity, inventory, unsupported instructions, generated prototypes, imports,
and the host build. Optional checks record the linker map and behavioural tests. A missing optional
record is `unknown`, not a failure, but it keeps the report honest.

The command exits 0 only when every required check is `pass`.

## Open questions

Unresolved questions are data, not comments:

```sh
python static_shock.py unknowns add --question "Which import provides the memory allocator?" \
    --evidence ida/imports.txt --authority-needed controlled-replay
python static_shock.py unknowns list
python static_shock.py unknowns resolve --id U1 --evidence traces/alloc.log
python static_shock.py unknowns check
```

`recomp/data/unknowns.json` stores the question, supporting and contradicting locations, the
authority still needed, and the resolution evidence. `resolve` requires evidence. `check` rejects
duplicate IDs, empty questions and resolutions without evidence.

Use unknowns for naming, ABI, structure layout and behaviour that the artifact does not settle.
An unknown with no owner is a to-do; an unknown resolved by a guess is a defect.

## Relationship to the inventory

`inventory.json` records what exists and how it is known. `readiness.json` records whether the
required parts are complete. `unknowns.json` records what is still not settled. Keep the three
consistent:

```sh
python static_shock.py inventory
python static_shock.py readiness
python static_shock.py verify
```

A `pass` covers only the declared check. Behavioural equivalence needs the differential and
behavioural evidence described in `18-verification.md`.
