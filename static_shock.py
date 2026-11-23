#!/usr/bin/env python3
"""StaticShock orchestrator: run the pipeline steps for the project in project.toml."""
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "pipeline"))
import cfg


def run(*cmd, cwd=ROOT):
    print("+ " + " ".join(str(c) for c in cmd))
    r = subprocess.run([str(c) for c in cmd], cwd=str(cwd))
    if r.returncode:
        sys.exit(r.returncode)


def ida():
    idat = cfg.IDA_CFG.get("idat") or os.environ.get("SS_IDAT")
    if not idat:
        for name in ("idat64.exe", "idat.exe"):
            found = shutil.which(name)
            if found:
                idat = found
                break
    if not idat:
        sys.exit("IDAT not found; set [ida].idat in project.toml or SS_IDAT")
    log = ROOT / "ida" / "ida.log"
    log.parent.mkdir(exist_ok=True)
    run(idat, "-A", "-S" + str(ROOT / "pipeline" / "ida_export.py"), "-L" + str(log), cfg.game_exe())


def functions():
    run(sys.executable, ROOT / "pipeline" / "make_functions.py")
    run(sys.executable, ROOT / "pipeline" / "classify.py")


def lift():
    run(sys.executable, ROOT / "pipeline" / "gen.py", "--regenerate")


def api():
    run(sys.executable, ROOT / "pipeline" / "make_api.py")
    run(sys.executable, ROOT / "pipeline" / "gen_api.py")


def build():
    run(sys.executable, ROOT / "build.py")


def verify():
    import py_compile
    for path in sorted((ROOT / "pipeline").glob("*.py")):
        py_compile.compile(str(path), doraise=True)
    if (ROOT / "recomp" / "data" / "target.json").exists():
        run(sys.executable, ROOT / "pipeline" / "manifest.py", "--verify")
    if (ROOT / "recomp" / "data" / "inventory.json").exists():
        run(sys.executable, ROOT / "pipeline" / "inventory.py", "--check")
    print("verify: python and records are consistent")


def doctor():
    import importlib.util
    from pathlib import Path
    from pe_image import Image

    problems = 0

    def ok(label):
        print("[ok]      " + label)

    def warn(label):
        print("[todo]    " + label)

    def wip(label):
        print("[wip]     " + label)

    def fail(label):
        nonlocal problems
        problems += 1
        print("[missing] " + label)

    print("project: %s (%s)" % (cfg.NAME, cfg.ARCH))
    exe = Path(cfg.game_exe())
    if not exe.exists():
        fail("original PE: %s" % exe)
    else:
        ok("original PE: %s" % exe)
        try:
            im = Image(exe)
            ok("PE: %s, base 0x%x, entry 0x%x, %d sections" % (im.arch, im.base, im.entry, len(im.secs)))
            if im.arch != cfg.ARCH:
                fail("project.arch %r != PE architecture %r" % (cfg.ARCH, im.arch))
            if cfg.ARCH == "x64":
                wip("x64 backend: PE32+ parsing/config only; lifter, runtime ABI and build are not implemented")
            if im.base != cfg.IMAGE_BASE:
                fail("project.image_base 0x%x != PE base 0x%x" % (cfg.IMAGE_BASE, im.base))
            if im.entry != cfg.OEP:
                fail("project.entry 0x%x != PE entry 0x%x" % (cfg.OEP, im.entry))
            if not (im.base <= cfg.CODE_LO < cfg.CODE_HI <= im.base + im.image_size):
                fail("code_lo/code_hi are outside the PE image")
            if cfg.IMAGE_END < im.base + im.image_size:
                fail("image_end 0x%x is before the end of the PE image 0x%x" % (cfg.IMAGE_END, im.base + im.image_size))
        except Exception as error:
            fail("PE parse: %s" % error)

    if cfg.ARCH == "x86":
        base = cfg.wasm_global_base()
        if cfg.IMAGE_END <= base:
            ok("wasm: image end 0x%x fits below GLOBAL_BASE 0x%x" % (cfg.IMAGE_END, base))
        else:
            fail("wasm: image end 0x%x is above GLOBAL_BASE 0x%x" % (cfg.IMAGE_END, base))
        if cfg.wasm_initial_memory() >= base + 0x4000000:
            ok("wasm: INITIAL_MEMORY 0x%x leaves room above GLOBAL_BASE" % cfg.wasm_initial_memory())
        else:
            fail("wasm: INITIAL_MEMORY 0x%x is too small for GLOBAL_BASE 0x%x" % (cfg.wasm_initial_memory(), base))
        emcc = cfg.wasm_emcc() or str(ROOT / "build" / "emsdk" / "upstream" / "emscripten" / "emcc.exe")
        if Path(emcc).exists() or shutil.which(emcc):
            ok("wasm: emcc")
        else:
            warn("wasm: emcc not found; set [wasm].emcc or SS_EMCC")

    if importlib.util.find_spec("capstone"):
        ok("capstone is installed")
    else:
        fail("capstone is missing: pip install -r requirements.txt")
    gcc = Path(cfg.mingw32()) / "bin" / "i686-w64-mingw32-gcc.exe"
    if gcc.exists() or shutil.which("i686-w64-mingw32-gcc"):
        ok("32-bit MinGW compiler")
    else:
        fail("i686-w64-mingw32-gcc not found; set build.mingw32")

    for path, label in ((ROOT / "ida" / "functions.tsv", "IDA function table"),
                        (ROOT / "ida" / "imports.txt", "IDA import table"),
                        (ROOT / "recomp" / "data" / "functions.tsv", "classified function table"),
                        (ROOT / "runtime" / "api_gen.c", "generated import table"),
                        (ROOT / "src" / "protos.h", "lifted prototypes"),
                        (ROOT / "bin" / cfg.HOST_EXE, "built host")):
        (ok if path.exists() else warn)(label + ": " + str(path))
    print("doctor: %d fatal problem(s)" % problems)
    return 0 if problems == 0 else 1


def main():
    ap = argparse.ArgumentParser(description="StaticShock pipeline")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("ida", help="run the headless IDA export")
    a = sub.add_parser("analyze", help="use an external native analyzer for the function and import tables")
    a.add_argument("--provider")
    a.add_argument("--function")
    a.add_argument("--no-write", action="store_true")
    sub.add_parser("doctor", help="check the project, toolchain and pipeline state")
    sub.add_parser("functions", help="build and classify the function table")
    sub.add_parser("rtti", help="recover MSVC RTTI classes, vtables and vfunc slots")
    sub.add_parser("lift", help="lift the image to C")
    p = sub.add_parser("asm", help="write the x86 listing of every lifted function to asm/")
    p.add_argument("--exe", default="", help="original PE (default: project.exe or SS_EXE)")
    sub.add_parser("api", help="build the import table")
    sub.add_parser("manifest", help="write or verify the target manifest")
    sub.add_parser("inventory", help="write or check the machine-readable inventory")
    sub.add_parser("verify", help="verify the manifest and inventory")
    sub.add_parser("readiness", help="write the fail-closed readiness report")
    p = sub.add_parser("progress", help="work queue and HTML progress dashboard")
    p.add_argument("args", nargs=argparse.REMAINDER)
    u = sub.add_parser("unknowns", help="record or resolve open questions")
    u.add_argument("args", nargs=argparse.REMAINDER)
    sub.add_parser("build", help="compile and link the host")
    sub.add_parser("all", help="functions + api + lift + build")
    r = sub.add_parser("run", help="run the built host")
    r.add_argument("args", nargs=argparse.REMAINDER)
    args = ap.parse_args()

    if args.cmd == "ida":
        ida()
    elif args.cmd == "analyze":
        cmd = [sys.executable, ROOT / "pipeline" / "analyzer_export.py"]
        if args.provider:
            cmd += ["--provider", args.provider]
        if args.function:
            cmd += ["--function", args.function]
        if args.no_write:
            cmd += ["--no-write"]
        run(*cmd)
    elif args.cmd == "doctor":
        sys.exit(doctor())
    elif args.cmd == "functions":
        functions()
    elif args.cmd == "rtti":
        run(sys.executable, ROOT / "pipeline" / "rtti_names.py")
    elif args.cmd == "lift":
        lift()
    elif args.cmd == "asm":
        cmd = [sys.executable, ROOT / "pipeline" / "extract_asm.py"]
        if args.exe:
            cmd += ["--exe", args.exe]
        run(*cmd)
    elif args.cmd == "api":
        api()
    elif args.cmd == "manifest":
        run(sys.executable, ROOT / "pipeline" / "manifest.py")
    elif args.cmd == "inventory":
        run(sys.executable, ROOT / "pipeline" / "inventory.py")
    elif args.cmd == "verify":
        verify()
    elif args.cmd == "readiness":
        run(sys.executable, ROOT / "pipeline" / "readiness.py")
    elif args.cmd == "progress":
        run(sys.executable, ROOT / "pipeline" / "progress.py", *args.args)
    elif args.cmd == "unknowns":
        run(sys.executable, ROOT / "pipeline" / "unknowns.py", *args.args)
    elif args.cmd == "build":
        build()
    elif args.cmd == "all":
        functions()
        api()
        lift()
        build()
    elif args.cmd == "run":
        host = ROOT / "bin" / cfg.HOST_EXE
        if not host.exists():
            sys.exit("host not built: %s" % host)
        run(host, *args.args, cwd=ROOT / "bin")


if __name__ == "__main__":
    main()
