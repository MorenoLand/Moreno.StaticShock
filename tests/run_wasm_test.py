#!/usr/bin/env python3
"""Build and run the wasm host smoke test under Node."""
import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "pipeline"))
import cfg
import build as native
import build_wasm

OUT = ROOT / "build" / "wasm_test"


def node_path():
    found = shutil.which("node")
    if found:
        return found
    for p in sorted((ROOT / "build" / "emsdk" / "node").glob("*/node.exe")):
        return str(p)
    sys.exit("node not found")


def main():
    native.write_project_header()
    build_wasm.write_headers()
    OUT.mkdir(parents=True, exist_ok=True)
    va = cfg.IMAGE_BASE + 0x3000
    blob = struct.pack("<I", 1) + struct.pack("<III", va, 4, 16) + struct.pack("<I", 0x12345678)
    image = OUT / "image.bin"
    image.write_bytes(blob)

    cc = build_wasm.emcc_path()
    files = [ROOT / "runtime" / "rt.c", ROOT / "runtime" / "wasm" / "api.c",
             ROOT / "runtime" / "wasm" / "special.c", ROOT / "runtime" / "wasm" / "sys.c",
             ROOT / "tests" / "wasm" / "host_test.c"]
    cmd = [str(cc), "-O1", "-g", "-w",
           "-I" + str(ROOT / "runtime"), "-I" + str(ROOT / "runtime" / "wasm"),
           "-I" + str(ROOT / "build" / "wasm")]
    cmd += [str(f) for f in files]
    cmd += ["-sGLOBAL_BASE=%d" % build_wasm.GLOBAL_BASE,
            "-sINITIAL_MEMORY=%d" % build_wasm.INITIAL_MEMORY,
            "-sSTACK_SIZE=%d" % build_wasm.STACK_SIZE,
            "-sENVIRONMENT=node",
            "-sALLOW_MEMORY_GROWTH=0",
            "-sASYNCIFY=1",
            "-sASYNCIFY_STACK_SIZE=1048576",
            "-sFORCE_FILESYSTEM=1",
            "-sEXIT_RUNTIME=1",
            "-sEXPORTED_FUNCTIONS=_main",
            "--preload-file=%s@/image.bin" % image,
            "-o", str(OUT / "host_test.js")]
    r = subprocess.run(cmd)
    if r.returncode:
        return r.returncode
    return subprocess.run([node_path(), "host_test.js"], cwd=str(OUT)).returncode


if __name__ == "__main__":
    sys.exit(main())
