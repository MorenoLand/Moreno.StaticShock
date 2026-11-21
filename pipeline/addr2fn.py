# addr2fn.py: find the lifted function that contains a host address printed by a crash of the host executable.
# usage: python -I scripts/addr2fn.py <map address in hex, as printed after "map address">
# The linker map (bin/lift.map) lists every f_xxxxxxxx symbol; the name is the guest address of the function.
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cfg

target = int(sys.argv[1], 16)
best = None
pat = re.compile(r"^\s+0x([0-9a-f]+)\s+(\S+)\s*$")
for line in open(os.path.join(cfg.BIN, "lift.map"), encoding="utf-8", errors="replace"):
    m = pat.match(line)
    if not m:
        continue
    addr, name = int(m.group(1), 16), m.group(2)
    if addr <= target and (best is None or addr > best[0]):
        best = (addr, name)
print("%s (+0x%x)" % (best[1], target - best[0]) if best else "not found")
