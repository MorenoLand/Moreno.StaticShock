# Lessons from real lifts

These are the failures that cost the most time. They are generic; the names are gone, the causes
are not.

## A wrong value is usually an ABI boundary

A decoder produced values scaled by roughly 2^20. The lifted arithmetic was correct; the import
that unpacked its constants returned a `double` in `ST(0)`, and the generic bridge read
`eax:edx`. Every derived value was wrong, and the output looked like a decoder bug.

Rule: every FP-returning import needs a special. Dump the raw return before suspecting the math.

## Do not fix the output layer first

A stream played as a full-scale square wave. Replacing the audio device, changing formats and
adjusting gains changed nothing, because the bytes handed to the device were already a square
wave. Dump the buffer at the API boundary: if it is wrong there, the bug is upstream.

## Clicks and hover are different coordinate paths

Buttons accepted clicks while hover highlighted nothing. The click path converted client
coordinates to canvas coordinates and subtracted the canvas origin; the hover path omitted the
subtraction. One missing `sub` made the hit test look at the wrong place.

Rule: one conversion function, used by every mouse message.

## Partial updates are not full frames

A full-frame `SetDIBitsToDevice` can be cached and stretched. A partial update must not be treated
as a full frame: it reads outside the canvas or shows stale pixels. Check the source rectangle and
the bitmap dimensions before caching.

## The CRT is part of the program

Static constructors run through `_initterm`; the security cookie, command line and locale are set
up before `main`. A lift that skips the CRT boundary runs no constructors and crashes before its
first window. Bind the CRT imports and special-case `_initterm`.

## The guest range collides with the loader

The process stack and CRT mappings are created before `main` and can land in the image range.
Reserve the range before the CRT starts (`rt_preentry`) and keep the linker sections explicit.
If the range is occupied, the image load fails with a cryptic allocation error.

## A stub is a lie

A stub that returns 0 makes the next function fail somewhere else, often after a long detour. The
lifter's `UNSUP` is better: it names the address and stops. Implement the instruction or the
import, or leave the lift incomplete and documented.

## Threaded code needs more than CreateThread

TLS, the TEB, thread entry points and blocking imports must agree. A global lock is acceptable for
a first run, but a blocking call must release it or the program deadlocks. Do not busy-wait with
the lock held.

## SEH is not a stack chain on x64

x64 uses table-driven unwind. If the target relies on exceptions, implement the unwinder; do not
assume the 32-bit frame-chain code will work.

## Readable rewrites are a second project

The instruction lift is the source of truth. A readable rewrite is only correct if it is checked
against the original, function by function, with the same inputs. Never replace a lifted function
with a guess because the C "looks right".

## Measure, then change

Every successful fix in these projects started with a measurement: a dumped buffer, a register
value, a mapped address, a differential test. Every failed fix started with a plausible story.
