# Naming and readability

The lifted code is correct before it is readable. Naming is the first readability step and the
easiest place to invent something that is not in the original.

## Evidence only

A name is allowed only when the original establishes it:

- a string, message or resource name
- RTTI, a vtable order or a C++ mangled symbol
- a property table, INI key, script command or registry value
- an imported API whose use identifies the wrapper
- a trace or debug log that prints the name
- a sequence of operations that maps one-to-one onto a documented API

If none of these exists, keep the address name (`f_00401234`) and wait. Do not invent a plausible
class, field or method name.

## Alias, do not rewrite

The safe form is an alias:

```c
#define f_00401234 GameSelectDialog__onHover
```

The generated function stays byte-for-byte instruction-faithful. The alias changes only how the
name reads. Keep aliases in one header (`src/aliases.h`), grouped by class, and record the evidence
in a comment or a TSV next to it.

## Proposal workflow

1. Collect candidates from RTTI, strings, imports and traces (`pipeline/rtti_names.py` helps with
   RTTI and vtables).
2. Write them to a proposal table: `address`, `proposed`, `evidence`, `status`.
3. Review; only `approved` rows become aliases.
4. For a struct, add fields only when the original's layout and types are established. Fields are
   offsets first, names later.
5. Never change a function's semantics as part of naming.

## Readable rewrites

A rewritten function is a separate change:

- keep the original address and the exact input/output behaviour
- write it in the `src/<area>/<Class>.c` file for its class
- cover it with a differential test or a recorded replay
- never delete the original lifted function until the rewrite is verified

Correctness per function is the metric. A prettier function that behaves differently is a
regression.
