# Host, window, input and presentation

The guest creates its own window through `user32`. The host does not run a second UI loop; it
provides the real Win32 calls, the message pump the guest asks for, and the presentation hook.

## Window creation

`RegisterClassA` stores the guest `WndProc` and turns it into a host trampoline. `CreateWindowExA`
passes the trampoline to Windows. Every message the guest receives is a real message; the guest's
window procedure is lifted C.

## Coordinates

There are three coordinate spaces:

1. **Screen** - `GetCursorPos`, `SetCursorPos`.
2. **Client** - the window's client area; `WM_MOUSEMOVE`/`WM_LBUTTONDOWN` `lParam`.
3. **Guest canvas** - the logical size the game renders to (often 640x480).

If the window is stretched, convert client coordinates to canvas coordinates before dispatching a
mouse message. Do it once, at the entry to the guest's window procedure, and subtract the canvas
origin. The click and hover paths must use the same conversion; a hover that is offset by the
canvas origin will highlight nothing while clicks still work.

For a fullscreen borderless window, keep the client rect and the canvas rect in one struct and
scale with 64-bit intermediates:

```c
x = (u32)(((u64)client_x * canvas_w) / client_w) + canvas_x;
y = (u32)(((u64)client_y * canvas_h) / client_h) + canvas_y;
```

## Presentation

Games often render into a DIB and call `SetDIBitsToDevice` or `StretchDIBits`. A full-window blit
can be intercepted:

- cache the canvas pointer and dimensions from the full-frame call
- for every later call, stretch the cached canvas to the client rect with `StretchDIBits`
- leave non-full calls to the real function if they target a different DC

Do not assume every `SetDIBitsToDevice` is a full frame. Cache only when the source rect covers the
whole bitmap, and never read past the canvas allocation.

## Timing

`timeBeginPeriod(1)` before the message loop makes `MsgWaitForMultipleObjects(1)` actually wait
about 1 ms; without it the loop runs at the 15.6 ms timer tick. This is a host-side quality fix,
not a game logic change.

## Audio

The guest usually calls OpenAL, DirectSound or waveOut. Let it call the real API. If the output is
wrong, dump the PCM the guest hands to the API before changing the device. A square wave in the
PCM is a guest decoder bug; a clean PCM that sounds wrong is a device/mixer bug.

## Input focus

Hover messages are often gated on an "active" flag set by `WM_ACTIVATE`. Check that the flag is
initialized when the window is created; a zero flag silently disables all hover.
