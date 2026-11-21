# make_functions.py: ida/functions.tsv (address, name, size, lib) -> recomp/data/functions.tsv (ea, name, size, category).
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cfg

src = os.path.join(cfg.ida_dump(), "functions.tsv")
out = os.path.join(cfg.DATA, "functions.tsv")
os.makedirs(cfg.DATA, exist_ok=True)
rows = list(csv.DictReader(open(src, encoding="utf-8"), delimiter="\t"))
with open(out, "w", encoding="utf-8", newline="") as f:
    w = csv.writer(f, delimiter="\t")
    w.writerow(["ea", "name", "size", "category"])
    for r in rows:
        w.writerow([r["address"], r["name"], r["size"], "lib:crt" if r["lib"] == "1" else "app"])
print("wrote %s (%d functions)" % (out, len(rows)))
