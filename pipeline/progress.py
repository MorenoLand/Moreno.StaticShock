# progress.py: work queue, status map and a self-contained HTML dashboard.
# statuses: unclaimed, in_progress, lifted, verified, blocked, unsupported
import argparse
import html
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cfg

WORK = os.path.join(cfg.DATA, "work.json")
INV = os.path.join(cfg.DATA, "inventory.json")
OUT = os.path.join(cfg.ROOT, "reports")
STATUSES = ("unclaimed", "in_progress", "lifted", "verified", "blocked", "unsupported")


def load(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_work(data):
    os.makedirs(cfg.DATA, exist_ok=True)
    with open(WORK, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.write("\n")


def rows():
    inv = load(INV, None)
    if not inv:
        sys.exit("inventory.json is missing; run: python static_shock.py inventory")
    work = load(WORK, {"schema": 1, "functions": {}})["functions"]
    out = []
    for f in inv["functions"]:
        addr = f["address"]
        entry = work.get(addr, {})
        base = "unsupported" if f.get("limitations") else "lifted"
        status = entry.get("status") or base
        if status == "verified" and f.get("limitations"):
            status = "blocked"
        out.append({
            "address": addr,
            "name": f["name"],
            "size": f["size"],
            "category": f["category"],
            "status": status,
            "owner": entry.get("owner", ""),
            "note": entry.get("note", ""),
        })
    return out


def write_reports(items):
    os.makedirs(OUT, exist_ok=True)
    counts = {s: 0 for s in STATUSES}
    for r in items:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    total = len(items) or 1
    done = counts["verified"]
    md = ["# Work progress", "",
          "| Status | Count |", "|---|---:|"]
    for s in STATUSES:
        md.append("| %s | %d |" % (s, counts[s]))
    md += ["", "Verified: %.1f%% of %d functions." % (100.0 * done / total, len(items)), "",
           "| Address | Name | Size | Category | Status | Owner | Note |",
           "|---|---|---:|---|---|---|---|"]
    for r in sorted(items, key=lambda x: x["address"]):
        md.append("| %s | %s | %d | %s | %s | %s | %s |" % (
            r["address"], r["name"], r["size"], r["category"], r["status"], r["owner"], r["note"]))
    with open(os.path.join(OUT, "progress.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(md) + "\n")

    colors = {"verified": "#1f7a3a", "lifted": "#2f6f9f", "in_progress": "#9a6b00",
              "blocked": "#8a1f1f", "unsupported": "#6b3f8a", "unclaimed": "#555"}
    trs = []
    for r in sorted(items, key=lambda x: x["address"]):
        e = lambda v: html.escape(str(v))
        trs.append("<tr data-status=\"%s\"><td>%s</td><td>%s</td><td>%d</td><td>%s</td>"
                   "<td><span class=st style=background:%s>%s</span></td><td>%s</td><td>%s</td></tr>"
                   % (e(r["status"]), e(r["address"]), e(r["name"]), r["size"], e(r["category"]),
                      colors.get(r["status"], "#555"), e(r["status"]), e(r["owner"]), e(r["note"])))
    doc = """<!doctype html>
<meta charset="utf-8"><title>Work progress</title>
<style>
body{font:14px system-ui,sans-serif;margin:24px;background:#111;color:#ddd}
h1{margin:0 0 4px;font-size:20px} .sub{color:#999;margin-bottom:16px}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.card{background:#1b1b1b;border:1px solid #333;border-radius:6px;padding:8px 12px;min-width:90px}
.card b{display:block;font-size:20px}
input{background:#1b1b1b;border:1px solid #333;color:#ddd;padding:7px 10px;width:320px;border-radius:5px}
table{border-collapse:collapse;width:100%%;margin-top:12px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid #262626;vertical-align:top}
th{position:sticky;top:0;background:#111}
.st{color:#fff;border-radius:4px;padding:1px 6px;font-size:12px}
</style>
<h1>Work progress</h1>
<div class=sub>%d functions; verified %d (%.1f%%)</div>
<div class=cards>%s</div>
<input id=q placeholder="filter by address, name, category, owner...">
<table><thead><tr><th>Address</th><th>Name</th><th>Size</th><th>Category</th><th>Status</th><th>Owner</th><th>Note</th></tr></thead>
<tbody id=t>%s</tbody></table>
<script>
const q=document.getElementById('q'),t=document.getElementById('t');
q.addEventListener('input',()=>{const v=q.value.toLowerCase();
 for(const r of t.rows) r.style.display=r.textContent.toLowerCase().includes(v)?'':'none';});
</script>""" % (len(items), done, 100.0 * done / total,
              "".join("<div class=card><b>%d</b>%s</div>" % (counts[s], s) for s in STATUSES),
              "".join(trs))
    with open(os.path.join(OUT, "progress.html"), "w", encoding="utf-8", newline="\n") as f:
        f.write(doc)
    print("wrote reports/progress.md and reports/progress.html")
    print("  " + ", ".join("%s=%d" % (s, counts[s]) for s in STATUSES))


def set_status(addr, status, owner, note):
    inv = load(INV, None)
    if not inv:
        sys.exit("inventory.json is missing; run inventory first")
    known = {f["address"].lower() for f in inv["functions"]}
    addr = addr.lower()
    if addr not in known:
        sys.exit("address not in inventory: %s" % addr)
    if status not in STATUSES:
        sys.exit("status must be one of: %s" % ", ".join(STATUSES))
    data = load(WORK, {"schema": 1, "functions": {}})
    data.setdefault("functions", {}).setdefault(addr, {})
    data["functions"][addr].update({"status": status, "owner": owner, "note": note})
    save_work(data)
    print("%s -> %s" % (addr, status))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--set")
    ap.add_argument("--status", choices=STATUSES)
    ap.add_argument("--owner", default="")
    ap.add_argument("--note", default="")
    args = ap.parse_args()
    if args.set:
        if not args.status:
            sys.exit("--set needs --status")
        set_status(args.set, args.status, args.owner, args.note)
    write_reports(rows())


if __name__ == "__main__":
    main()
