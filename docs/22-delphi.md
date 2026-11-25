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
a C function cannot carry implicitly. The flag variables are shared guest state in `rt.c` and are
materialised at every return. `fbstp` writes packed BCD through `fx_bcd_store`.

## Window procedure identity

VCL stores and retrieves the window procedure through `SetWindowLongA`/`GetWindowLongA` with index
`-4`, and `GetClassInfoA`/`CallWindowProcA` also carry it. The host trampoline is a different
pointer from the guest address. Translate both directions through `rt_tramp`/`rt_tramp_guest`, or
the next `WndProc` comparison fails and the form stops receiving messages. Font enumeration
callbacks (`EnumFontFamiliesEx`, `EnumFonts`, `EnumDisplayMonitors`) need the same trampoline wrap.

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

The `RaiseException`/`RtlUnwind` imports must not reach kernel32: Windows would walk the host TEB and
never see the guest's frames. The runtime walks the guest `fs:[0]` chain, builds the record and
context on the guest stack, and calls each handler with `gcall`. `SetUnhandledExceptionFilter` stores
the guest filter and the raise path calls it when no frame matches.

## Exception landings

A `try/except` frame installs a 5-byte `jmp` stub to the RTL dispatcher; the code at `stub + 5` is
the landing. The generator resolves the dispatcher by name, scans `.text` for those stubs, lifts the
landing as a block and records `landing -> owner`. The owner function is renamed to
`f_XXXX_body` and wrapped:

```c
LandRec lr0_;
rt_land_enter(&lr0_, 0xOWNER);
if (__builtin_setjmp(lr0_.jb)) { call_ind(rt_land_target); }
else { f_XXXX_body(); }
rt_land_leave(&lr0_);
```

`jmp_ind` longjmps to the innermost active owner instead of tail-calling the landing, so the owner's
epilogue runs once. `[lift].extra` registers continuations reached only by a register or memory
jump in the same table; without it, such a continuation runs its epilogue twice with the wrong EBP.

`@@ClassCreate` installs a frame for its caller, so every function whose text calls it is wrapped
with the `@@ClassCreate` group id.

## Console hosts

A console target must match stdout, stderr and the exit code. Gate host diagnostics behind
`RECOMP_BOOT_LOG`; a recompiled console tool that prints `boot: image mapped` fails every
differential case. Do not consume `argv[1]` as a data folder: keep the working directory and pass
all arguments through. Use `RECOMP_DIR` when a folder is genuinely required.

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
