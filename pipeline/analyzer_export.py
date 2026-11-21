# analyzer_export.py: use an external native analyzer for the function/import tables.
# The analyzer is configured in project.toml -> [analyzer].command (or SS_ANALYZER).
# Expected interface: `COMMAND search TARGET ".*" --kind procedures --mode regex
# --provider PROVIDER --format json`, returning an evidence object whose raw_result or
# normalized_result is a list of {address, value}. Adapt call() for a different CLI.
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cfg
from pe_image import Image

ANALYZER_CFG = cfg.section("analyzer")
ANALYZER = os.environ.get("SS_ANALYZER") or ANALYZER_CFG.get("command", "")
PROVIDER = ANALYZER_CFG.get("provider", "ghidra")
TIMEOUT = int(ANALYZER_CFG.get("timeout", 900))


def decode(raw):
    for enc in ("utf-8-sig", "utf-16", "utf-8"):
        try:
            return json.loads(raw.decode(enc))
        except Exception:
            continue
    sys.exit("analyzer returned output that is not JSON")


def call(args, write_path=None):
    if not ANALYZER:
        sys.exit("set [analyzer].command in project.toml or SS_ANALYZER to the analyzer executable")
    exe = shutil.which(ANALYZER) or ANALYZER
    cmd = [exe] + args + ["--format", "json"]
    print("+ " + " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, timeout=TIMEOUT)
    if r.returncode != 0:
        text = r.stderr.decode("utf-8", "replace") or r.stdout.decode("utf-8", "replace")
        sys.exit("analyzer failed (%d): %s" % (r.returncode, text[:2000]))
    data = decode(r.stdout)
    if isinstance(data, dict) and "data" in data and "meta" in data:
        data = data["data"]
    if write_path:
        os.makedirs(os.path.dirname(write_path), exist_ok=True)
        with open(write_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(data, f, indent=1, sort_keys=True)
            f.write("\n")
    if isinstance(data, dict) and data.get("ok") is False:
        sys.exit("analyzer error: %s" % json.dumps(data.get("error", {}))[:2000])
    return data


def procedures(data):
    rows = data.get("raw_result") or data.get("normalized_result") or []
    out = {}
    for row in rows:
        addr = str(row.get("address", ""))
        name = str(row.get("value", "")).replace("\t", " ").replace("\n", " ")
        if not addr.lower().startswith("0x"):
            continue
        try:
            ea = int(addr, 16)
        except ValueError:
            continue
        if not (cfg.CODE_LO <= ea < cfg.CODE_HI):
            continue
        out.setdefault(ea, name or ("sub_%08x" % ea))
    return out


def write_tables(funcs):
    ida = Path(cfg.ida_dump())
    ida.mkdir(parents=True, exist_ok=True)
    ordered = sorted(funcs)
    with open(ida / "functions.tsv", "w", encoding="utf-8", newline="\n") as f:
        f.write("address\tname\tsize\tlib\n")
        for i, ea in enumerate(ordered):
            nxt = ordered[i + 1] if i + 1 < len(ordered) else cfg.CODE_HI
            f.write("%08x\t%s\t%d\t0\n" % (ea, funcs[ea], max(1, nxt - ea)))
    im = Image(cfg.game_exe())
    with open(ida / "imports.txt", "w", encoding="utf-8", newline="\n") as f:
        for module, slot, name in im.imports():
            f.write("%s\t%08x\t%s\t\n" % (module[:-4] if module.lower().endswith(".dll") else module, slot, name))
    print("wrote %s/functions.tsv (%d functions) and imports.txt" % (ida, len(ordered)))


def main():
    provider = None
    function = None
    no_write = False
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--provider" and i + 1 < len(args):
            provider = args[i + 1]
        if a == "--function" and i + 1 < len(args):
            function = args[i + 1]
        if a == "--no-write":
            no_write = True
    provider = provider or PROVIDER

    if function:
        data = call(["function", cfg.game_exe(), function, "--provider", provider],
                    os.path.join(cfg.ROOT, "analysis", "provider", "functions",
                                 function.replace("0x", "") + ".json"))
        print("saved function dossier; evidence=%s" % data.get("evidence_id"))
        return

    data = call(["search", cfg.game_exe(), ".*", "--kind", "procedures", "--mode", "regex",
                 "--provider", provider],
                os.path.join(cfg.ROOT, "analysis", "provider", "procedures.json"))
    funcs = procedures(data)
    if not funcs:
        sys.exit("analyzer returned no local procedures; check the provider and the target")
    if no_write:
        for ea in sorted(funcs)[:20]:
            print("%08x %s" % (ea, funcs[ea]))
        print("... %d functions" % len(funcs))
        return
    write_tables(funcs)
    record = {
        "schema": 1,
        "evidence_id": data.get("evidence_id"),
        "subject": data.get("subject"),
        "provider": data.get("provider"),
        "predicate_type": data.get("predicate_type"),
        "operation": data.get("operation"),
        "confidence": data.get("confidence"),
        "authority": data.get("authority"),
        "limitations": data.get("limitations"),
        "procedure_count": len(funcs),
    }
    path = os.path.join(cfg.DATA, "analyzer.json")
    os.makedirs(cfg.DATA, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(record, f, indent=1, sort_keys=True)
        f.write("\n")
    print("wrote %s" % path)


if __name__ == "__main__":
    main()
