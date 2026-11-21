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
