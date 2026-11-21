# readiness.py: fail-closed readiness report for the current project.
# statuses are pass/fail/unknown/unsupported/skipped; unknown and unsupported never count as pass.
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cfg
from manifest import sha256

OUT = os.path.join(cfg.DATA, "readiness.json")


def check(check_id, required, status, detail, evidence=None):
    return {"id": check_id, "required": required, "status": status,
            "detail": detail, "evidence": evidence or []}


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def build():
    checks = []
    manifest_path = os.path.join(cfg.DATA, "target.json")
    target = load(manifest_path)
    digest = None
    if not target:
        checks.append(check("target.manifest", True, "fail", "target.json is missing", [manifest_path]))
    else:
        exe = cfg.game_exe()
        digest = target.get("target", {}).get("sha256")
        actual = sha256(exe) if os.path.exists(exe) else None
        if actual and actual == digest:
            checks.append(check("target.identity", True, "pass", "target digest matches", [manifest_path]))
        else:
            checks.append(check("target.identity", True, "fail", "target digest does not match", [manifest_path]))

    inventory = load(os.path.join(cfg.DATA, "inventory.json"))
    if not inventory:
        checks.append(check("inventory.present", True, "fail", "inventory.json is missing"))
    elif digest and inventory.get("target_sha256") and inventory["target_sha256"] != digest:
        checks.append(check("inventory.identity", True, "fail", "inventory was built for another target"))
    else:
        checks.append(check("inventory.identity", True, "pass", "inventory matches the target"))

    unsupported = os.path.join(cfg.SRC, "unsupported.txt")
    count = 0
    if not os.path.exists(unsupported):
        checks.append(check("lift.unsupported", True, "fail", "unsupported.txt is missing; lift has not run",
                            [unsupported]))
    else:
        with open(unsupported, encoding="utf-8") as f:
            count = sum(1 for line in f if line.strip())
        if count == 0:
            checks.append(check("lift.unsupported", True, "pass", "no unsupported instructions", [unsupported]))
        else:
            checks.append(check("lift.unsupported", True, "unsupported",
                                "%d unsupported instruction site(s)" % count, [unsupported]))

    protos = os.path.join(cfg.SRC, "protos.h")
    checks.append(check("lift.prototypes", True, "pass" if os.path.exists(protos) else "fail",
                        "generated prototypes", [protos]))

    api_table = load(os.path.join(cfg.DATA, "api_table.json"))
    api_gen = os.path.join(cfg.RT, "api_gen.c")
    checks.append(check("imports.table", True, "pass" if os.path.exists(api_gen) else "fail",
                        "generated import table", [api_gen]))
    if isinstance(api_table, list):
        unknown = [e for e in api_table if e.get("nargs") is None]
        if unknown:
            checks.append(check("imports.arg_counts", True, "unknown",
                                "%d import(s) have no argument count" % len(unknown),
                                [os.path.join(cfg.DATA, "api_table.json")]))
        else:
            checks.append(check("imports.arg_counts", True, "pass", "all import argument counts are known"))
    else:
        checks.append(check("imports.arg_counts", True, "fail", "api_table.json is missing"))

    host = os.path.join(cfg.BIN, cfg.HOST_EXE)
    checks.append(check("build.host", True, "pass" if os.path.exists(host) else "fail",
                        "host executable", [host]))
    checks.append(check("build.map", False, "pass" if os.path.exists(os.path.join(cfg.BIN, "lift.map")) else "unknown",
                        "linker map for crash reports", [os.path.join(cfg.BIN, "lift.map")]))

    for name in ("differential", "behavior"):
        result = load(os.path.join(cfg.ROOT, "tests", "results", name + ".json"))
        if result and result.get("status") == "pass":
            checks.append(check("verify." + name, False, "pass", "recorded pass",
                                [os.path.join("tests", "results", name + ".json")]))
        else:
            checks.append(check("verify." + name, False, "unknown", "no recorded pass",
                                [os.path.join("tests", "results", name + ".json")]))

    counts = {}
    for c in checks:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    ready = all(c["status"] == "pass" for c in checks if c["required"])
    report = {
        "schema": 1,
        "project": cfg.NAME,
        "target_sha256": digest,
        "ready": ready,
        "status": "ready" if ready else ("blocked" if not target else "partial"),
        "counts": counts,
        "checks": checks,
        "limitations": [
            "Readiness is not behavioural equivalence.",
            "A pass covers only the declared checks; unknown and unsupported never aggregate to pass.",
        ],
    }
    os.makedirs(cfg.DATA, exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, indent=1, sort_keys=True)
        f.write("\n")
    print("readiness: %s (%s)" % (report["status"], ", ".join("%s=%d" % (k, v) for k, v in sorted(counts.items()))))
    for c in checks:
        if c["status"] != "pass":
            print("  %-22s %-11s %s" % (c["id"], c["status"], c["detail"]))
    return 0 if ready else 1


if __name__ == "__main__":
    sys.exit(build())
