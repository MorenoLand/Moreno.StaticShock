# make_api.py: build recomp/data/api_table.json from the IDA imports.
# stdcall argument counts come from the MinGW import libraries (nm); cdecl functions have no @N
# and the caller pops. Per-project overrides live in project.toml -> [imports].nargs.
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cfg

MINGW = cfg.mingw32()
MINGW_LIB = os.path.join(MINGW, "lib")
NM = os.path.join(MINGW, "bin", "nm.exe")
IMPORTS = os.path.join(cfg.ida_dump(), "imports.txt")
OUT = os.path.join(cfg.DATA, "api_table.json")
CDECL_MODULES = cfg.cdecl_modules()
OVERRIDES = {str(k): v for k, v in cfg.import_nargs().items()}

syms = {}
env = dict(os.environ)
env["PATH"] = os.path.join(MINGW, "bin") + os.pathsep + env.get("PATH", "")
for lib in cfg.import_libs():
    path = os.path.join(MINGW_LIB, lib)
    if not os.path.exists(path):
        continue
    out = subprocess.run([NM, "-A", path], capture_output=True, text=True, env=env).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        kind, sym = parts[-2], parts[-1]
        if sym.startswith("__imp__"):
            sym = sym[len("__imp__"):]
        if sym.startswith("_"):
            sym = sym[1:]
        m = re.match(r"^(.+)@(\d+)$", sym)
        if m and int(m.group(2)) % 4 == 0:
            syms.setdefault(m.group(1), ("stdcall", int(m.group(2)) // 4))
        elif kind in ("T", "I") and "@" not in sym:
            syms.setdefault(sym, ("cdecl", None))

def import_rows():
    if os.path.exists(IMPORTS):
        for line in open(IMPORTS, encoding="utf-8"):
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 3:
                yield parts[0], parts[1], parts[2], parts[3] if len(parts) > 3 else ""
    else:
        from pe_image import Image
        for module, ea, name in Image(cfg.game_exe()).imports():
            yield module, "%08x" % ea, name, name[1:] if name.startswith("#") else ""


rows = []
for module, ea, name, ordinal in import_rows():
    module = module[:-4] if module.lower().endswith(".dll") else module
    if name.startswith("__imp_"):
        name = name[6:]
    if name.startswith("#") and name[1:].isdigit():
        ordinal = name[1:]
    if (name.startswith("ord") or name.startswith(module.lower() + "_")) and ordinal.isdigit():
        name = "#" + ordinal
    conv, nargs = syms.get(name, (None, None))
    if module.lower() in CDECL_MODULES:
        conv = "cdecl"
    if module == "MSVCP80" and "@@Q" in name:
        conv = "thiscall"
        nargs = 0 if name.endswith("XZ") else 1
    if conv is None:
        conv = "stdcall"
    if nargs is None and conv == "cdecl":
        nargs = OVERRIDES.get(name, 4)
    rows.append({"module": module, "name": name, "ea": "0x" + ea, "nargs": nargs,
                 "conv": conv, "source": "nm", "confidence": "high" if nargs is not None else "low"})

with open(OUT, "w", encoding="utf-8") as f:
    json.dump(rows, f, indent=1)
known = sum(1 for r in rows if r["nargs"] is not None)
print("imports %d, nargs known %d -> %s" % (len(rows), known, OUT))
