# Porting a C lift to another language at 1:1 fidelity

This is the method that takes a faithful C reconstruction of a program's machine code and produces a
second implementation in a managed or higher-level language without losing behaviour. It is written
for a port where the second language is idiomatic (classes, references, strings), not an emulator.

The accuracy comes from three independent controls, not from careful reading alone:

1. the C lift is itself checked against the machine code;
2. every ported function is compared with the original machine code through golden vectors;
3. the whole program is compared with the original on real inputs, and every branch is mutation-checked.

## 1. Freeze the reference

Before the first line of the new language:

- The C lift is instruction-faithful: one machine instruction becomes one or more C statements, the
  flags, x87/SSE state and calling convention are preserved, and unsupported instructions fail loudly.
- Every function carries its original address, and the disassembly and pseudocode for that address are
  available next to it.
- The data image and the original executable are available for reading constants, tables and initial
  values.
- The C is not edited during the port. If the C and the machine code disagree, the machine code is
  right; record the C defect separately.

Tag or archive the C reference and the tooling before starting. The port must be able to answer, for
every function, "what did the original do at this address?" without guessing.

## 2. Define the runtime contract

Decide what the new language provides and what the port must preserve:

| Machine concept | Idiomatic mapping |
|---|---|
| Guest pointer | Object reference, nullable where the original allows nil |
| Structure offset | Named field at the same logical position |
| Global variable | Static member with the original's initial value from the data image |
| Virtual table slot | `virtual`/`override` in the same slot order; never a hidden or renamed method |
| Integer width and signedness | The language type of the same width; arithmetic wraps; casts stay where the original truncates |
| Floating point | Keep the original's intermediate width; narrow only where the original stores |
| Byte string | An immutable byte-string type with the original's edge cases, not the language string |
| Function pointer | Delegate or an address-to-function table |
| Win32/OS call | A platform interface, implemented once per host; never a P/Invoke inside the portable code |

If the program relies on self-modifying code, raw pointers into a flat image, or byte-level aliasing,
keep a flat memory model instead of references. Choose per target, not per function.

## 3. Build the address-to-symbol inventory

Every original function and global gets exactly one home:

- An attribute on the ported member recording the original address (and the original name when known).
- A tracker that reads the C reference and the port, and reports ported, absorbed and missing
  functions, weighted by the original machine-code bytes.
- An "absorbed" list for functions the target runtime replaces (memory allocation, reference
  counting, string primitives, CRT scaffolding), each with the reason it needs no counterpart.
- A check that no address has two homes and no function is silently absent.

The target is 100% of the original code bytes accounted for: ported or absorbed with a reason. A
byte-weighted percentage is the only honest progress metric; function counts hide large functions.

## 4. Translation rules that preserve behaviour

- **Integers.** Use the exact width and signedness of every operation. Division, modulo, shifts,
  sign extension and comparison differ between signed and unsigned. Keep wrap-around; disable checked
  arithmetic. Put a cast exactly where the original truncates.
- **Floating point.** If the original computes on the x87, intermediates are wider than `float`. Keep
  that width and store a `float` only where the original writes four bytes. NaN comparisons and
  conversion overflow values must match.
- **Strings.** Character sets, lengths and terminators are observable. Use a byte-string type for the
  original's strings; convert to the language string only at the edge. Comparisons are ordinal.
- **Objects.** One original member is one member. A constructor that overwrites a base default must do
  so after the base constructor, in the same order. A destructor that only frees memory is absorbed; a
  destructor with side effects is a method called at the original's destruction point.
- **Control flow.** Jump tables become `switch`; no new `goto`. Preserve the order of calls and side
  effects, including calls whose result is unused.
- **Globals.** Initial values come from the data image, not from the language's zero values. Every
  global needs a reset path for tests.
- **Callbacks and threads.** Callbacks keep their original argument order and calling convention at
  the boundary. Threads become explicit round functions or workers with the same locking order.
- **Names.** Use evidence for names: script/property strings, error text, imports, RTTI. Never keep
  decompiler names (`sub_`, `dword_`, `field_`, `a1`, `v1`) in the port.

## 5. Port in dependency layers

Work bottom-up, so each layer can be tested before the next uses it:

1. integer/float helpers, flags, memory accessors and CRT edge cases;
2. byte strings, arrays, lists, hash tables, files and paths;
3. math, compression, image and data-format libraries;
4. platform seams (window, input, OpenGL, audio, registry, sockets, time);
5. GUI controls and the message loop;
6. networking, script engine, game logic;
7. start-up and command line.

For each function: read the C, the pseudocode and the disassembly; port it; add its golden test; make
it pass before moving on. Do not port a subsystem and test it at the end.

## 6. Golden vectors from the original machine code

This is the control that catches a plausible-but-wrong translation.

- Run individual original functions in a CPU emulator with synthesized register, stack and memory
  inputs.
- Capture the return registers, the memory the function wrote, and any output buffers.
- Write those vectors to compressed fixtures; a test loads them and runs the ported function with the
  same inputs and compares the full result, including memory.
- Generate vectors for every function that can run in isolation; for the rest, write behaviour tests
  from the C's branches and comments.
- Prefer vectors produced by running the machine code. A generator that parses the C source can share
  the same misreading as the port and will agree with it while both are wrong.

A mismatch is a port bug until proven otherwise.

## 7. Whole-program differential testing

Function vectors do not cover start-up, globals set before the first call, or interactions between
subsystems.

- Run the original and the port on the same inputs in separate fresh folders.
- Compare exit code, stdout, stderr and every output file by name, size and hash.
- Use a small fixed case list for CLI paths (no arguments, valid input, missing input, bad switch) and
  a corpus for data paths.
- For interactive programs, drive both with the same scripted input on a private display and compare
  screenshots, state dumps and protocol bytes.
- Bisect the first divergence; fix that function, not the symptom.

Live comparison is the final word for behaviour a fixture cannot reach. Keep the original's own
output nondeterminism documented instead of "fixing" it.

## 8. Mutation testing

A branch is tested only when breaking it makes a test fail.

- Change a comparison, a constant, a branch or a call order; run the covering test; confirm failure.
- Undo the change and rebuild before the next run.
- A surviving mutant means the test does not execute that branch, not that the branch is correct.

This is the difference between "the suite is green" and "the suite would notice".

## 9. Test isolation with original global state

A faithful port keeps the original's globals, so tests interfere through them.

- Reset every global to its data-image value around each test.
- Run tests single-threaded, or serialize the ones that touch shared state.
- Fix the random test order with a seed when hunting an order dependence.
- Keep the platform seams on do-nothing defaults so unit tests need no display, audio device or
  network; the program's entry point must install the real implementations.

## 10. Validation gates

Before calling a function or a subsystem done:

- Build with warnings as errors; no `TODO`, stub, `NotImplementedException` or skipped branch.
- Address tracker: no missing functions; every absorbed entry has a reason.
- Golden and behaviour tests pass; mutation checks were run for new branches.
- Lint: banned decompiler names, missing documentation, raw host paths.
- Whole-program differential cases pass.
- Live test on a private display/folder/account when the program is interactive.

## 11. Failure classes to look for first

These pass unit tests and still break the program:

- **A seam left on its stand-in.** Files never opened, sound silent, messages dropped.
- **A test that shares the port's misreading.** The generator and the port agree and are both wrong.
- **A virtual method hidden or bypassed.** `new` instead of `override`, or calling a virtual where the
  original reads a field.
- **A call missing from a rebuilt function.** Startup and hand-rebuilt functions are the usual place.
- **A class description never made.** Reflective object systems lose every property.
- **An assumed global initial value.** The image says 1; the language default says 0.
- **A derived constructor's override of a base default.** Order of assignments differs.
- **A comment trusted over the bytes.** Names and comments in the C can be wrong; check strings and
  offsets in the data image.
- **A float stored too early.** x87 intermediates narrowed to `float` change results.

## 12. Definition of done

- 100% of original code bytes are ported or absorbed with a reason.
- Every ported function has an address attribute and at least one test.
- The whole-program differential corpus matches, or every difference is documented with evidence.
- Mutation checks cover the branches that matter.
- The port reads as idiomatic code with meaningful names; the address attribute is the link back to
  the machine code, not a comment explaining it.

The property that makes this 1:1 is not the language. It is the chain of evidence: C checked against
machine code, function fixtures generated from machine code, whole-program comparisons against the
original, and mutation checks that prove the tests can fail.
