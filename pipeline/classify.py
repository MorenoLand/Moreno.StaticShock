# classify.py: turn the exported function list into recomp/data/functions.tsv.
# Optional address ranges in project.toml ([classify].ranges) label application, CRT and libraries.
import csv
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cfg

D = cfg.ida_dump()
OUT = os.path.join(cfg.DATA, "functions.tsv")
RANGES = cfg.classify_ranges()


def category(ea):
    for lo, hi, name in RANGES:
        if lo <= ea < hi:
            return name
    return "app"


rows = []
fn_json = os.path.join(D, "functions.json")
if os.path.exists(fn_json):
    fn = json.load(open(fn_json, encoding="utf-8"))
    facts_path = os.path.join(D, "facts.json")
    names_path = os.path.join(D, "current_names.json")
    facts = json.load(open(facts_path, encoding="utf-8")) if os.path.exists(facts_path) else {}
    names = json.load(open(names_path, encoding="utf-8")) if os.path.exists(names_path) else {}
    for f in fn:
        ea = int(f["ea"], 16)
        key = "0x%x" % ea
        fa = facts.get(key, {})
        cat = category(ea)
        if cat == "app" and f.get("lib"):
            cat = "lib:crt"
        rows.append((ea, names.get(key, f.get("name", "sub_%x" % ea)), int(f.get("size", 0)),
                     cat, len(fa.get("callers", [])), fa.get("callees", []), fa.get("apis", [])))
else:
    src = os.path.join(D, "functions.tsv")
    for r in csv.DictReader(open(src, encoding="utf-8"), delimiter="\t"):
        ea = int(r["address"], 16)
        cat = r.get("category") or category(ea)
        rows.append((ea, r["name"], int(r["size"]), cat, 0, [], []))

rows.sort()
with open(OUT, "w", encoding="utf-8", newline="") as o:
    o.write("ea\tname\tsize\tcategory\tncallers\tcallees\tapis\n")
    for ea, name, size, cat, nc, ce, ap in rows:
        o.write("%08x\t%s\t%d\t%s\t%d\t%s\t%s\n" % (
            ea, name, size, cat, nc,
            ",".join(x[2:] if isinstance(x, str) else str(x) for x in ce),
            ",".join(ap)))

cnt = Counter(r[3] for r in rows)
size = Counter()
for r in rows:
    size[r[3]] += r[2]
for c in sorted(cnt):
    print("%-28s %6d functions %9d bytes" % (c, cnt[c], size[c]))
app = [r for r in rows if r[3] == "app"]
named = sum(1 for r in app if not r[1].startswith("sub_"))
print("app functions still named sub_: %d of %d" % (len(app) - named, len(app)))
print("wrote %s (%d functions)" % (OUT, len(rows)))
