# Delphi and VCL targets

StaticShock lifts Delphi Win32 executables with the same model as any other PE. Delphi adds a few
compiler and VCL conventions that the lifter and runtime must know about; this page records them.

The proven reference is a Delphi 2003 VCL application: 4,784 lifted functions, no unsupported
instructions, form and controls working, generated files byte-identical to the original.

## Detection

- Imports from `rtl*.bpl`, `vcl*.bpl`, `vclx*.bpl` or `coreide*.bpl`, and symbols named
  `@System@...`, `@Classes@...`, `@Forms@...`.
- A `DVCLAL` resource, and form resources stored as `RT_RCDATA` beginning with `TPF0`.
- `PACKAGEINFO` resources and Borland/Embarcadero version strings.
- IDA signatures: `delphi`, `d3vcl`, `d4vcl`, `b32vcl`, then the generic `pe`/`exe` signatures.

Set them in `project.toml`:

```toml
[ida]
signatures = ["delphi", "d3vcl", "d4vcl", "b32vcl", "pe", "exe"]
```

Named runtime functions make the lift readable and let `classify.py` separate VCL/CRT code from
application code.

## Names and calling convention

Delphi exports and RTTI names are mangled: `@Unit@Class@Method$...`. Keep the mangled name in the
evidence and use the readable form only when the signature is verified.

Internal Delphi methods use the `register` convention (EAX, EDX, ECX; extra arguments on the stack).
Internal calls are lifted directly, so the lifter does not need a special call ABI. Imported BPL
functions still need the right argument count and cleanup rule; record them in `[imports.nargs]` and
`[imports].cdecl_modules` as the import table requires.

## VMT and dynamic methods

A Delphi object points at its class VMT. The negative offsets the runtime uses:

| Offset | Field |
|---|---|
| `-0x24` | parent class reference (its first dword is the parent VMT) |
| `-0x30` | dynamic-method table |
| `-0x10` | default message handler |

The dynamic table is `Word count; Word indexes[count]; Pointer methods[count]`. `TObject.Dispatch`
and `@@CallDynaInst` walk it by message id; if the id is absent they call the default handler.
Those helpers are usually small assembly routines whose result depends on flags across a call. When
the lifted C cannot reproduce that, replace the two helpers in `runtime/override.c` with a direct
table walk, as the reference target does. Keep the override narrow and record why.

Class names and published method names can be recovered from the VMT and RTTI; verify each candidate
against the class-name pointer and the method table before using it in `src/`.

## SEH and continuations

Delphi uses compiler-generated `FS:[0]` exception frames. A typical epilogue is:

```asm
push continuation
call cleanup
ret
```

The `ret` jumps to the pushed continuation rather than returning to the caller. The lifter detects
these pushes, decodes the continuation as part of the function and checks it when emitting `ret`.
Without that, the first form-streaming frame fails.

String helpers also return with:

```asm
pop eax
jmp eax
```

That is a return, not an indirect call. The lifter recognises a register that was just popped and
emits `FN_RET`/`return` instead of `call_ind`.

Flags must stay live across calls and returns: Delphi code branches on flags left by a callee, which
a C function cannot carry implicitly. The generated function keeps the flag variables live and
materialises them at every return.

## DFM resources

Forms are streamed from `RT_RCDATA` (`TPF0`), not from a menu or dialog template. The original
`.res`/`.dcr` data is part of the image; keep it in the data image and let `classes` stream it. Use
the DFM text (an external viewer or a resource dump) to name forms, controls and event handlers, not
to generate code: the streaming path stays the original one.

Do not rewrite the DFM. If a control is missing, the resource or the streaming code is wrong.

## MakeObjectInstance thunks

VCL allocates a small thunk for every window method:

```
E8 rel32     call block
block: 59    pop ecx
       E9 rel32  jmp StdWndProc
```

The 8-byte `TMethod` record (`method`, `instance`) sits at `thunk+5`, and `StdWndProc` expects that
address in ECX. The thunk is in guest heap, not in the lifted image, so `call_ind` recognises the
pattern and dispatches it. Keep the check before the "not a lifted function" failure.

## Exceptions

Unhandled Delphi exceptions raise `0x0eedfade`. Exception information 1 is the exception object;
its message pointer is at `+4` (a Delphi string with its length at `-4`). `boot.c` prints that
message before the register and stack report.

## Message loop

VCL blocks in `GetMessage`/`MsgWaitForMultipleObjects`. The host must present the same top-level
window, class and controls; do not replace the loop with a timer or a polling thread. The reference
target waits one millisecond per turn, which Windows rounds up to the timer tick.

## Lifter requirements

The generic lifter covers the Delphi patterns above, plus:

- optional `ida/code.txt` code ranges, so a jump-table entry that points at data is not decoded;
- `loop`, `loope`, `loopne`, `jecxz`, `bswap`;
- byte/word/dword string operations and their `rep` forms;
- `fninit` and `fbstp`;
- jump tables bounded to the function's neighbourhood.

Run `python static_shock.py asm` after `lift` and compare the listing with `src/` when a function
looks wrong.

## Verification

- The form appears with the expected class and controls.
- Each event handler runs from the real message loop.
- Behavioural output matches the original (files, bytes, exit code), not just "it starts".
- `readiness` is `ready` with the behavioural checks recorded.

## Limits

- Static imports only; a target that loads BPLs or plugins at run time needs those modules supplied
  and analysed as well.
- Old Delphi versions use ANSI strings; newer ones use `UnicodeString`. Read the string layout from
  the binary, do not assume.
- COM/OLE, database and third-party packages are ordinary imports; each needs a host implementation
  or a documented failure.
