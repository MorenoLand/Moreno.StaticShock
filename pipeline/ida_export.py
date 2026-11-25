# ida_export.py: headless IDA pass. Applies signatures, writes the function table,
# segments, imports and strings, and (when Hex-Rays loads) pseudocode chunks.
import os
import sys
import time

import ida_auto
import ida_bytes
import ida_funcs
import ida_ida
import ida_name
import ida_nalt
import ida_segment
import idaapi
import idautils
import idc

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cfg

out = os.environ.get("SS_IDA_OUT") or cfg.ida_dump()
os.makedirs(out, exist_ok=True)
log = open(os.path.join(out, "run.log"), "w", encoding="utf-8")


def say(text):
    log.write(text + "\n")
    log.flush()


def named_count():
    total = named = lib = 0
    for ea in idautils.Functions():
        total += 1
        name = ida_name.get_name(ea)
        if not (name.startswith("sub_") or name.startswith("nullsub_") or name.startswith("j_sub_")):
            named += 1
        func = ida_funcs.get_func(ea)
        if func and (func.flags & ida_funcs.FUNC_LIB):
            lib += 1
    return total, named, lib


start = time.time()
ida_auto.auto_wait()
say("auto analysis done after %.0fs" % (time.time() - start))
say("functions before signatures: total=%d named=%d lib=%d" % named_count())

for sig in cfg.signatures():
    try:
        result = idc.plan_to_apply_idasgn(sig)
    except Exception as error:
        say("signature %s skipped: %s" % (sig, error))
        continue
    ida_auto.auto_wait()
    say("signature %s -> %s; functions total=%d named=%d lib=%d" % ((sig, result) + named_count()))

total, named, lib = named_count()
say("after signatures: total=%d named=%d lib=%d (%.0fs)" % (total, named, lib, time.time() - start))

with open(os.path.join(out, "functions.tsv"), "w", encoding="utf-8") as table:
    table.write("address\tname\tsize\tlib\n")
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        table.write("%08x\t%s\t%d\t%d\n" % (ea, ida_name.get_name(ea),
                                            func.end_ea - func.start_ea,
                                            1 if func.flags & ida_funcs.FUNC_LIB else 0))

with open(os.path.join(out, "segments.txt"), "w", encoding="utf-8") as seg:
    for s in idautils.Segments():
        seg.write("%s %08x-%08x\n" % (idc.get_segm_name(s), s, idc.get_segm_end(s)))
    seg.write("entry %08x\n" % ida_ida.inf_get_start_ea())

with open(os.path.join(out, "code.txt"), "w", encoding="utf-8") as code:
    begin = None
    for ea in range(cfg.CODE_LO, cfg.CODE_HI):
        if ida_bytes.is_code(ida_bytes.get_flags(ea)):
            if begin is None:
                begin = ea
        elif begin is not None:
            code.write("%08x %08x\n" % (begin, ea))
            begin = None
    if begin is not None:
        code.write("%08x %08x\n" % (begin, cfg.CODE_HI))

with open(os.path.join(out, "imports.txt"), "w", encoding="utf-8") as imports:
    for index in range(ida_nalt.get_import_module_qty()):
        module = ida_nalt.get_import_module_name(index)

        def callback(ea, name, ordinal):
            imports.write("%s\t%08x\t%s\t%s\n" % (module, ea, name or "", ordinal))
            return True

        ida_nalt.enum_import_names(index, callback)

with open(os.path.join(out, "strings.tsv"), "w", encoding="utf-8", errors="replace") as strings:
    for item in idautils.Strings():
        strings.write("%08x\t%s\n" % (item.ea, str(item).replace("\t", " ").replace("\n", "\\n")))

try:
    import ida_hexrays
    available = ida_hexrays.init_hexrays_plugin()
except Exception as error:
    available = False
    say("hexrays import failed: %s" % error)

say("hexrays available: %s" % available)
decompile_start = time.time()
if available:
    chunk_size = 200
    count = failed = chunk = 0
    handle = None
    index = open(os.path.join(out, "index.tsv"), "w", encoding="utf-8")
    index.write("address\tname\tsize\tchunk\tstatus\n")
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if func.flags & ida_funcs.FUNC_LIB:
            continue
        if count % chunk_size == 0:
            if handle:
                handle.close()
            chunk += 1
            handle = open(os.path.join(out, "chunk_%04d.c" % chunk), "w", encoding="utf-8", errors="replace")
        status = "ok"
        try:
            text = str(ida_hexrays.decompile(ea))
        except Exception as error:
            status = "failed"
            failed += 1
            text = "// decompile failed: %s\n" % error
        handle.write("//" + "=" * 70 + "\n// %s\n// entry %08x  size %d  status %s\n//" % (
            ida_name.get_name(ea), ea, func.end_ea - func.start_ea, status) + "=" * 70 + "\n\n" + text + "\n\n")
        index.write("%08x\t%s\t%d\tchunk_%04d.c\t%s\n" % (ea, ida_name.get_name(ea),
                                                          func.end_ea - func.start_ea, chunk, status))
        count += 1
        if count % 100 == 0:
            say("decompiled %d (failed %d) %.0fs" % (count, failed, time.time() - decompile_start))
    if handle:
        handle.close()
    index.close()
    say("decompiled %d functions, failed %d, chunks %d" % (count, failed, chunk))

say("done %.0fs" % (time.time() - start))
log.close()
idc.save_database(os.path.join(out, cfg.ida_project() + ".i64"), 0)
idc.qexit(0)
