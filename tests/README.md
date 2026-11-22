# Tests

Correctness is measured, not assumed. Put tests here that can run without the original binary
committed:

- unit tests for the runtime (FPU rounding, flag helpers, string ops)
- differential cases with recorded inputs and expected outputs
- replay files for a lifted function, with the original bytes referenced by hash, not stored
- smoke tests for the build and the data image

Do not commit the original executable, its assets or recorded proprietary content. A test that
needs the original may generate its inputs from a path supplied by `SS_EXE` and skip when it is
absent.

`python tests/run_wasm_test.py` builds the wasm host and `tests/wasm/host_test.c` with Emscripten and
runs it under Node. It needs emcc (`[wasm].emcc`, `SS_EMCC` or `build/emsdk`) and Node.
