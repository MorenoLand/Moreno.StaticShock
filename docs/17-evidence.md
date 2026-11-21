# Evidence and claims

A recompilation is a chain of claims: this address is a function, this name is real, this import
uses that calling convention, this instruction does that. Each claim must say how it is known.
Without that, an agent cannot tell an observation from a guess.

## Confidence

| Level | Meaning |
|---|---|
| `observed` | Directly read from the shipped artifact or executed in a controlled run. |
| `derived` | Follows mechanically from recorded observations, with the steps written down. |
| `inferred` | A judgement or a hypothesis. It needs a test before it becomes a claim of behaviour. |

Never present `inferred` as `observed`. A plausible class name is not a fact because it fits the
strings.

## Authority

| Authority | Source |
|---|---|
| `shipped-artifact` | The original PE, its sections, imports, strings and data. |
| `controlled-replay` | A recorded run, trace, differential test or screenshot produced for this project. |
| `historical-reference` | A prior version, a patch, a public symbol file or a specification. |
| `external-service` | A disassembler or decompiler result. It is evidence, not truth. |
| `analyst-inference` | Reasoning. Useful, but never the only support for a behavioural claim. |

## Evidence records

`schemas/evidence.schema.json` defines a record:

```json
{
  "claim": "0x401000 is the entry point",
  "confidence": "observed",
  "authority": "shipped-artifact",
  "evidence": [{"kind": "pe-bytes", "location": "optional header +16"}],
  "limitations": []
}
```

Use records for naming decisions, ABI conclusions, structure layouts and non-obvious instruction
semantics. Keep them next to the thing they support (a comment, a TSV row, an issue) or in the
project's evidence file. The schema is deliberately small.

## Project records

- `recomp/data/target.json` - the target's identity: SHA-256, PE layout, imports, tool versions.
  Generate with `python static_shock.py manifest`; verify with `manifest --verify`.
- `recomp/data/inventory.json` - every function with size, category, name confidence, evidence
  kind, limitations and the unsupported-instruction count. Generate with
  `python static_shock.py inventory`; check with `inventory --check`.
- `src/unsupported.txt` - every instruction the lifter did not model, grouped by function. It is
  a to-do list, not a place to hide defects.
- `bin/lift.map` - host address to lifted function, for crash reports.

## Limitations and coverage

Every record may carry `limitations` and a `coverage` status (`complete`, `partial`, `unknown`).
A function with an unsupported instruction is `partial` even if it has a name. A naming claim
without a string/RTTI/trace is `inferred` with the limitation "no evidence found".

Coverage is not "functions lifted / total". It is the set of behaviours that were exercised and
compared. State what was not tested.

## Naming claims

A name is `observed` only when the original provides it: a string, RTTI, a vtable order, a
property table, a trace. Otherwise keep the address name. See `15-naming.md`.

## Review rule

When a change claims to fix behaviour, attach the evidence that distinguishes before from after:
a dumped buffer, a trace, a differential test, a screenshot, a register value. "It builds" and
"the window opens" are not evidence of the claim.
