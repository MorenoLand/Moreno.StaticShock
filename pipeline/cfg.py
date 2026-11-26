"""Project configuration shared by every pipeline script.

All paths are resolved relative to the repository root. Values come from
project.toml; the command line and environment can override the input paths.
"""
import os
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "project.toml"
if not CONFIG_PATH.exists():
    sys.exit("project.toml is missing; copy the template and edit it first")
CFG = tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def section(name):
    return CFG.get(name, {})


def _int(value, default=0):
    if value is None:
        return default
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def _path(value):
    p = Path(value)
    return p if p.is_absolute() else ROOT / p


PROJECT = section("project")
BUILD_CFG = section("build")
IMPORT_CFG = section("imports")
IDA_CFG = section("ida")
LIFT_CFG = section("lift")
WASM_CFG = section("wasm")

NAME = PROJECT.get("name", "target")
ARCH = PROJECT.get("arch", "x86")
HOST_EXE = PROJECT.get("host_exe", "host.exe")
HOST_NAME = PROJECT.get("host_name", NAME)
IMAGE_BASE = _int(PROJECT.get("image_base"), 0x400000)
OEP = _int(PROJECT.get("entry"), IMAGE_BASE + 0x1000)
PE_ENTRY = _int(PROJECT.get("pe_entry"), OEP)
CODE_LO = _int(PROJECT.get("code_lo"), IMAGE_BASE + 0x1000)
CODE_HI = _int(PROJECT.get("code_hi"), IMAGE_BASE + 0x100000)
IMAGE_END = _int(PROJECT.get("image_end"), IMAGE_BASE + 0x1000000)
GUEST_SIZE = _int(PROJECT.get("guest_size"), 0x1000000)
TAIL_SIZE = _int(PROJECT.get("tail_size"), 0x23F000)
ICON = PROJECT.get("icon", "")

BIN = ROOT / "bin"
BUILD = ROOT / "build"
SRC = ROOT / "src"
DATA = ROOT / "recomp" / "data"
RT = ROOT / "runtime"
IDA = ROOT / "ida"

BIN.mkdir(exist_ok=True)
BUILD.mkdir(exist_ok=True)
SRC.mkdir(exist_ok=True)
DATA.mkdir(parents=True, exist_ok=True)


def need(env, what, flag):
    """Return a path from --flag, the environment, or project.toml, in that order."""
    if flag in sys.argv:
        i = sys.argv.index(flag)
        value = sys.argv[i + 1]
        del sys.argv[i:i + 2]
        return value
    value = os.environ.get(env)
    if value:
        return value
    sys.exit("missing input: %s.\n  pass %s <path> or set %s" % (what, flag, env))


def game_exe():
    if "--exe" in sys.argv:
        i = sys.argv.index("--exe")
        value = sys.argv[i + 1]
        del sys.argv[i:i + 2]
        return str(_path(value))
    value = os.environ.get("SS_EXE") or PROJECT.get("exe")
    if not value:
        sys.exit("missing input: the original PE.\n  set project.exe in project.toml, pass --exe <path>, or set SS_EXE")
    return str(_path(value))


def ida_dump():
    if "--ida" in sys.argv:
        i = sys.argv.index("--ida")
        value = sys.argv[i + 1]
        del sys.argv[i:i + 2]
        return str(_path(value))
    value = os.environ.get("SS_IDA_OUT") or IDA_CFG.get("out") or "ida"
    return str(_path(value))


def mingw32():
    if "--mingw32" in sys.argv:
        i = sys.argv.index("--mingw32")
        value = sys.argv[i + 1]
        del sys.argv[i:i + 2]
        return value
    value = os.environ.get("SS_MINGW32") or BUILD_CFG.get("mingw32")
    if not value:
        sys.exit("missing input: the 32-bit MinGW root.\n  set build.mingw32 in project.toml, pass --mingw32 <path>, or set SS_MINGW32")
    return value


def ida_project():
    return IDA_CFG.get("project", NAME.lower())


def signatures():
    return IDA_CFG.get("signatures", [])


def cflags():
    return BUILD_CFG.get("cflags", ["-O1", "-w"])


def host_libs():
    return BUILD_CFG.get("libs", ["psapi", "winmm", "ole32", "gdi32", "user32",
                                  "shell32", "advapi32", "comdlg32", "winspool"])


def wasm_emcc():
    return WASM_CFG.get("emcc", "")


def wasm_data_dir():
    return WASM_CFG.get("data_dir", "")


def wasm_data_parts():
    return max(1, int(WASM_CFG.get("data_parts", 4)))


def wasm_width():
    return int(WASM_CFG.get("width", 640))


def wasm_height():
    return int(WASM_CFG.get("height", 480))


def wasm_guest_stack():
    return _int(WASM_CFG.get("guest_stack"), 0x800000)


def wasm_initial_memory():
    return _int(WASM_CFG.get("initial_memory"), 0x10000000)


def wasm_stack_size():
    return _int(WASM_CFG.get("stack_size"), 0x1000000)


def wasm_global_base():
    value = _int(WASM_CFG.get("global_base"), 0)
    if value:
        return value
    end = IMAGE_BASE + GUEST_SIZE + TAIL_SIZE
    return (end + 0xFFFF) & ~0xFFFF


def import_libs():
    return IMPORT_CFG.get("libs", ["libkernel32.a", "libuser32.a", "libgdi32.a",
                                   "libshell32.a", "libole32.a", "libwinmm.a",
                                   "libcomdlg32.a", "libadvapi32.a", "libwinspool.a"])


def cdecl_modules():
    return [m.lower() for m in IMPORT_CFG.get("cdecl_modules", ["msvcr80", "msvcp80"])]


def import_nargs():
    return IMPORT_CFG.get("nargs", {})


def import_data():
    return {str(x) for x in IMPORT_CFG.get("data", [])}


def skip_categories():
    return set(LIFT_CFG.get("skip_categories", ["other"]))


def skip_functions():
    return {_int(x) for x in LIFT_CFG.get("skip", [])}


def wrap_functions():
    return {_int(x) for x in LIFT_CFG.get("wrap", [])}


def extra_functions():
    """Code blocks that are neither IDA functions nor discovered call targets (continuations reached by a register jump)."""
    return {_int(x) for x in LIFT_CFG.get("extra", [])}


def data_ranges():
    return [(_int(lo), _int(hi)) for lo, hi in LIFT_CFG.get("data", [])]


def chunk_size():
    return int(LIFT_CFG.get("chunk", 120))


def max_functions_per_file():
    return int(LIFT_CFG.get("max_functions_per_file", 150))


def areas():
    return [(name, pattern) for name, pattern in section("layout").get("areas", [])]


def classify_ranges():
    return [(_int(lo), _int(hi), cat) for lo, hi, cat in section("classify").get("ranges", [])]
