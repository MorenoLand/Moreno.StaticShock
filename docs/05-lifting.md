# The instruction lift

`pipeline/lift.py` translates one x86 function at a time with Capstone. The output is C with the
original addresses in comments, so every line can be checked against `asm/` or IDA.

## Output shape

```c
void f_00401060(void)
{
    int fZ = 0, fS = 0, fC = 0, fO = 0, fP = 0, fA = 0;
    FN_ENTER(0x00401060);
    /* 00401060: push ebp */ { u32 v = r_ebp; r_esp -= 4; W32(r_esp, v); }
    ...
    /* 0040107a: ret */ FN_RET(0x00401060); r_esp += 4; return;
}
```

`FN_ENTER`/`FN_RET`/`BB` compile to nothing unless a profile build is enabled.

## Registers, flags, stack

- Guest registers are globals. `r_eax` etc. are 32-bit unsigned.
- Sub-register writes preserve the rest of the register (`al`, `ah`, `ax`).
- The flags are six locals: `fZ` zero, `fS` sign, `fC` carry, `fO` overflow, `fP` parity,
  `fA` auxiliary. They are computed only where a later instruction can read them; the liveness
  pass keeps the generated code small.
- `r_esp` is the guest stack pointer. A call pushes the return address; a `ret N` pops 4+N. The
  guest stack lives in ordinary guest memory and is read/written with `R32`/`W32`.
- `rt_df` is the direction flag for string operations.

## Memory

`addr_expr()` builds `(u32)(base + index*scale + disp)`. Segment prefixes use the Windows
user-mode selectors; `fs:` maps to the guest TEB. Addresses are host pointers, so the generated C
can dereference them directly.

## Control flow

- Direct `jmp`/`jcc` become `goto L_...`.
- A direct `call` becomes a C call to `f_XXXXXXXX()`.
- An indirect call goes through `call_ind(target)`, which looks up the target in `fn_table`.
- Jump tables are lifted as a `switch` over the table entries. The table bytes are kept in the
  data image.
- Calls to blocks inside a function (SEH `__finally`, shared locking helpers) are lifted as
  separate functions that end in `ret`; they are registered in the table like any other function.

## Arithmetic

- `add/sub/and/or/xor` update the flags exactly as the original.
- `imul` uses 64-bit intermediates; `div/idiv` use 64-bit division and raise `UNSUP` on divide by
  zero or overflow.
- `shl/shr/sar/rol/ror` mask the count to 5 bits (32-bit operands).
- `inc/dec` update all flags except carry, as the original does.
- `cmp/test` only set flags.
- `cmovcc`, `setcc`, `bsf/bsr`, `bt/bts/btr/btc`, `bswap`, `xadd`, `xchg`, `lea`, `nop`, `int3`,
  `hlt` are covered; see the source for the exact subset.

## x87

The FPU is a software stack of eight `long double` values (`fpr`, `ftop`), plus `fsw`/`fcw`.
`ST(i)` resolves through `ftop`.

- Loads/stores: `fld`, `fild`, `fst`, `fstp`, `fist`, `fistp`, `fstcw`, `fldcw`.
- Arithmetic: `fadd`, `fsub`, `fmul`, `fdiv`, `fchs`, `fabs`, `fsqrt`, `fprem`, `fscale`.
- Comparisons: `fcom`, `fcomp`, `fucom`, `fucomp`, `ftst`, `fxam`; `fx_compare` sets the emulated
  status word and `fx_sw()` exports it.
- Transcendentals: `fsin`, `fcos`, `fptan`, `fpatan`, `f2xm1`, `fyl2x`, `fyl2xp1`.
- Integer conversion: `fx_int32` rounds with the current x87 rounding mode and clamps to the
  indefinite integer on overflow. The original `fistp` behaviour is preserved.
- `fnsave`/`frstor`/`fnstenv`/`fldenv` and precision control are not fully modelled; the lifter
  emits `UNSUP` rather than guessing.

**Import returns:** a DLL function returning `double` leaves it in `ST(0)`, not in `eax:edx`.
The import bridge must call the real function with the correct prototype and `FPUSH` the result.
The runtime does this for `ldexp`, `frexp`, `modf`, `fmod`, `atof`, `ceil`, `cos`, `fabs`,
`floor`, `log10`, `sin` and `sqrt`. A missing entry here silently corrupts every value derived
from the call.

## SSE

The subset used by MSVC 8/9 code is covered: moves, scalar and packed arithmetic, conversions,
shuffles, comparisons, `andps/orps/xorps`, `movmskps`, `pxor`, etc. `mxcsr` is a global; rounding
and flush-to-zero are best-effort. Add missing mnemonics to the `sse` table with a differential
test.

## Strings

`movs`, `stos`, `lods`, `cmps`, `scas` honour `rt_df` and the `rep`/`repe`/`repne` prefixes. The
`repe cmps` form is used by vendor checks and must compare exactly.

## Unsupported instructions

The lifter never guesses. It emits:

```c
UNSUP(0x00401234, "instruction text");
```

and appends the address to `src/unsupported.txt`. The runtime prints the address, message and
guest registers, then exits. Work through the list:

1. Read the original bytes and the Intel manual.
2. Implement the semantics in the lifter with a small generated snippet.
3. Add a focused test comparing the lifted result with a reference (Unicorn, a small assembly
   harness, or the original under a debugger).
4. Regenerate and rebuild.

Do not replace an unsupported instruction with a no-op to make a build pass.

## Extending the lifter

- Operand helpers (`read`, `write`, `addr_expr`) handle registers, immediates and memory.
- `lift()` dispatches on `i.mnemonic`, then on operand forms.
- Flags are tracked by `uses`/`defs`/`live_out`; a new instruction must declare them.
- Add a comment format `/* %08x: %s */` so the generated file stays traceable.
