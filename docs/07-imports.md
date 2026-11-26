# Imports and the ABI boundary

Every imported function is bound to a sentinel address in `0xFE000000 + 16*i`. The guest's IAT
slot is overwritten with that sentinel, and `call_ind` dispatches through `api_tab`. The real DLL
function is called by `host_call`, which reads the arguments from the guest stack.

## Calling conventions

| Convention | Who cleans | Notes |
|---|---|---|
| `stdcall` | callee (`ret N`) | Win32 API; argument count from `name@N` in the import library. |
| `cdecl` | caller | CRT and many third-party APIs; the caller pops the bytes. |
| `thiscall` | callee | `ecx` is `this`; the runtime passes it explicitly. |
| varargs | caller | `cdecl`; the format string tells the callee how many stack words to read. |

`pipeline/make_api.py` fills `api_table.json` with `nargs` and `conv`; `gen_api.py` turns it into
`api_gen.c`. Unknown cdecl counts must be set in `[imports].nargs` in `project.toml`.

## Data imports

An IAT slot can point at a variable rather than a function (`_acmdln`, `c_dfDIKeyboard`, format
tables). Binding it to a call sentinel makes the guest read `0xC3C3C3C3` and fault. List those names
in `[imports].data`; `gen_api.py` emits `api_data_names`, and the binder writes the real address of
the variable instead of a sentinel. A missing data import is fatal, not a warning.

```toml
[imports]
data = ["c_dfDIKeyboard"]
```

## Host COM objects

DirectX 8/9 objects do not fit the function-sentinel model:

- their methods are C functions with `this` as the **first stack argument** and callee cleanup; a
  normal `thiscall` bridge does not match;
- the guest needs a guest-side vtable, so each interface is a proxy whose slots are sentinels with
  their own argument counts;
- proxy arguments passed back to the real DLL must be translated proxy→host;
- `CreateDevice`, `CreateTexture`, `CreateSoundBuffer`, `GetBackBuffer`, `QueryInterface` and the
  other out-parameters return new interfaces, which must be wrapped before returning to the guest.

`QueryInterface` needs a GUID→interface table generated from the SDK headers. This layer is a
per-target bridge (`runtime/com.c`, `pipeline/gen_com.py` in ports that need it); the template does
not ship one. Document the interfaces the target actually uses and generate the slot table from the
headers rather than typing argument counts by hand.

## Guest pointers

A guest pointer is a host pointer in the 32-bit build, but the function may still expect a
different layout. Special handlers cover:

- functions that return a pointer the guest will call (`GetProcAddress`, `SHGetMalloc`)
- callbacks (`qsort`, `bsearch`, `EnumWindows`, `RegisterClass`, thread entry points)
- structures with guest pointers (`STARTUPINFO`, `WNDCLASSA`, `MSG`, `NOTIFYICONDATA`)
- file paths where the game prepends its own folder
- presentation (`SetDIBitsToDevice`, `SwapBuffers`)

When in doubt, write a special and document why. A wrong argument count or convention corrupts
the guest stack silently.

## Floating-point returns

A DLL function returning `double` returns it in `ST(0)`, not in `eax:edx`. The generic
`host_call` cannot represent that. `S_MATHFP` calls the real function with a proper prototype and
pushes the result into the emulated x87 stack.

The same rule applies to `_CIpow`, `_CIsin`, `_CIcos`, `_CIsqrt`, `_CIlog`, `_CIexp`, `_CItan`
and `_CIatan`: they take and return values on the x87 stack and must run as specials, never as
normal stack-argument imports.

If a value derived from an import is wrong by a huge factor, suspect a missing FP return first.

## Callbacks

`rt_tramp(guest_fn, nargs)` builds a small host trampoline that loads the guest registers,
pushes the arguments and calls `call_ind`. Use it for every function pointer passed to Windows.
Free the trampoline only when the API guarantees the callback is no longer reachable.

## Missing imports

If `GetProcAddress` fails, the binder logs a warning and leaves the slot calling a function that
returns 0. If the program requires the DLL, copy the correct 32-bit DLL next to the executable or
provide a special/emulation. Do not silently skip a required API and call the result a fix.
