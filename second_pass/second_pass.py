# ultrafixup_second_pass_ida92_structified_vtables_fix7.py
# IDA 9.2: second-pass fixer with REAL vtable structs
# Prolog detection is now manual-bytes scan using ida_bytes.get_bytes (portable, no missing APIs)

import sys, traceback
import idaapi
import ida_ida
import ida_funcs
import ida_bytes
import ida_ua
import ida_segment
import ida_kernwin
import ida_nalt
import ida_name
import ida_auto
import idc

try:
    import ida_typeinf
except Exception:
    ida_typeinf = None

# ---------------- configuration ----------------
MAX_PASSES               = 6
MAKE_CODE_BLOCK_MIN_LEN  = 8
STRING_MIN_ASCII         = 5
STRING_MIN_UTF16_CHARS   = 4
VTABLE_MIN_PTRS          = 3
VERBOSE_LOG              = True
RESPECT_EXISTING_NAMES   = True

VT_STRUCT_PREFIX         = "VT_"
VT_ENTRY_PREFIX          = "vt_entry_"
VT_TARGET_PREFIX         = "sub_"

# ---------------- utilities --------------------
def log(msg):
    if VERBOSE_LOG:
        ida_kernwin.msg(str(msg) + "\n")

def warn(msg):
    ida_kernwin.msg("[warn] " + str(msg) + "\n")

def err(msg):
    ida_kernwin.msg("[error] " + str(msg) + "\n")

def is_64bit():
    try:
        return ida_ida.inf_is_64bit()
    except Exception:
        return False

def PS():
    return 8 if is_64bit() else 4

def ptr_mask():
    return 0xFFFFFFFFFFFFFFFF if is_64bit() else 0xFFFFFFFF

def iter_segments():
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        if s:
            yield s

def seg_name(s):
    try:
        return ida_segment.get_segm_name(s) or ""
    except Exception:
        return ""

def seg_is_exec(s):
    return bool(s.perm & ida_segment.SEGPERM_EXEC)

def seg_is_ro(s):
    r = bool(s.perm & ida_segment.SEGPERM_READ)
    w = bool(s.perm & ida_segment.SEGPERM_WRITE)
    x = bool(s.perm & ida_segment.SEGPERM_EXEC)
    return r and not w and not x

def seg_is_dataish(s):
    r = bool(s.perm & ida_segment.SEGPERM_READ)
    w = bool(s.perm & ida_segment.SEGPERM_WRITE)
    x = bool(s.perm & ida_segment.SEGPERM_EXEC)
    return r and w and not x

def is_unknown(ea):
    return ida_bytes.is_unknown(ida_bytes.get_full_flags(ea))

def is_code(ea):
    return ida_bytes.is_code(ida_bytes.get_full_flags(ea))

def next_item(ea):
    return ida_bytes.next_not_tail(ea)

def auto_wait_safe():
    try:
        ida_auto.auto_wait()
    except Exception:
        pass

# ---------------- phase 1: decode code ----------------
def insn_len_at(ea):
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) > 0:
        return insn.size
    return 0

def try_make_code_at(ea):
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) > 0:
        return bool(ida_ua.create_insn(ea))
    return False

def flow_decode_from(ea, max_steps=200000):
    made = 0
    cur  = ea
    steps = 0
    while steps < max_steps:
        steps += 1
        if is_code(cur):
            l = insn_len_at(cur)
            if l <= 0:
                break
            cur += l
            continue
        if try_make_code_at(cur):
            made += 1
            l = insn_len_at(cur)
            if l <= 0:
                break
            cur += l
        else:
            break
    return made

def decode_undef_in_exec_segments():
    made_insns = 0
    for s in iter_segments():
        if not seg_is_exec(s):
            continue
        log(f"[decode] exec seg {seg_name(s)} {hex(s.start_ea)}..{hex(s.end_ea)}")
        ea = s.start_ea
        while ea < s.end_ea:
            if is_unknown(ea) and try_make_code_at(ea):
                made_insns += 1
                made_insns += flow_decode_from(ea + insn_len_at(ea))
            ea = next_item(ea)
    return made_insns

# ---------------- phase 2: create functions ----------------
# Manual prolog bytes (no binary-search APIs)
PROLOGS_32 = [b"\x55\x8B\xEC", b"\x55\x89\xE5"]
PROLOGS_64 = [b"\x55", b"\x40\x55"]

def find_prologs_in_seg(s):
    pats = PROLOGS_64 if is_64bit() else PROLOGS_32
    max_pat = max(len(p) for p in pats)
    ea = s.start_ea
    end = s.end_ea
    while ea < end:
        # Quick skip if undefined
        if is_unknown(ea):
            ea = next_item(ea)
            continue
        # Grab up to longest pattern
        chunk = ida_bytes.get_bytes(ea, max_pat) or b""
        if chunk:
            for p in pats:
                plen = len(p)
                if plen <= len(chunk) and chunk[:plen] == p:
                    yield ea
                    break
        ea += 1

def make_function_at(ea):
    if ida_funcs.get_func(ea):
        return False
    flow_decode_from(ea)
    ok = ida_funcs.add_func(ea)
    if ok:
        auto_wait_safe()
    return bool(ok)

def create_functions_from_undef_blocks():
    made = 0
    for s in iter_segments():
        if not seg_is_exec(s):
            continue

        # heuristic 1: recognisable prologs
        for ea in find_prologs_in_seg(s):
            if ida_funcs.get_func(ea):
                continue
            if make_function_at(ea):
                log(f"[func] + prolog @ {hex(ea)}")
                made += 1

        # heuristic 2: long runs of code with no function header
        run_start = idaapi.BADADDR
        run_len = 0
        ea = s.start_ea
        while ea < s.end_ea:
            if is_code(ea) and not ida_funcs.get_func(ea):
                if run_start == idaapi.BADADDR:
                    run_start = ea
                    run_len = 0
                run_len += 1
            else:
                if run_start != idaapi.BADADDR and run_len >= MAKE_CODE_BLOCK_MIN_LEN:
                    if make_function_at(run_start):
                        log(f"[func] + code-run @ {hex(run_start)} len={run_len}")
                        made += 1
                run_start = idaapi.BADADDR
                run_len = 0
            ea = next_item(ea)
        if run_start != idaapi.BADADDR and run_len >= MAKE_CODE_BLOCK_MIN_LEN:
            if make_function_at(run_start):
                log(f"[func] + code-run @ {hex(run_start)} len={run_len}")
                made += 1
    return made

# -------- phase 3: reanalyze for SP/prolog/epilog --------
def reanalyze_all_functions():
    """
    IDA 9.2 bindings differ by build. Valid overloads are:
      reanalyze_function(func_t *)
      reanalyze_function(func_t *, ea_t)
      reanalyze_function(func_t *, ea_t, ea_t)
      reanalyze_function(func_t *, ea_t, ea_t, bool)
    We?ll try them in that order and count successes.
    """
    fixed = 0
    q = ida_funcs.get_func_qty()
    for i in range(q):
        f = ida_funcs.getn_func(i)
        if not f:
            continue

        ok = False
        # try each overload without exploding the run
        try:
            ok = bool(ida_funcs.reanalyze_function(f))
        except Exception:
            try:
                ok = bool(ida_funcs.reanalyze_function(f, f.start_ea))
            except Exception:
                try:
                    ok = bool(ida_funcs.reanalyze_function(f, f.start_ea, f.end_ea))
                except Exception:
                    try:
                        ok = bool(ida_funcs.reanalyze_function(f, f.start_ea, f.end_ea, True))
                    except Exception:
                        ok = False

        if ok:
            fixed += 1
            log(f"[reanalyze] {hex(f.start_ea)}..{hex(f.end_ea)}")
        auto_wait_safe()
    return fixed

# ---------------- phase 4: missed strings ----------------
PRINTABLE = set(range(0x20, 0x7F))

def looks_ascii_run(ea, seg_end, min_len):
    n, cur = 0, ea
    while cur < seg_end:
        b = ida_bytes.get_byte(cur)
        if b in PRINTABLE:
            n += 1
            cur += 1
        else:
            break
    return n >= min_len

def looks_utf16le_run(ea, seg_end, min_chars):
    n, cur = 0, ea
    while cur + 1 < seg_end:
        w = ida_bytes.get_word(cur)
        lo, hi = (w & 0xFF), (w >> 8)
        if hi == 0 and lo in PRINTABLE:
            n += 1
            cur += 2
        else:
            break
    return n >= min_chars

def define_strings_in_segment(s):
    created = 0
    ea = s.start_ea
    while ea < s.end_ea:
        if is_unknown(ea):
            if looks_ascii_run(ea, s.end_ea, STRING_MIN_ASCII):
                if ida_bytes.create_strlit(ea, 0, ida_nalt.STRTYPE_C) != idaapi.BADADDR:
                    created += 1
                    log(f"[str] ASCII @ {hex(ea)}")
                    skip = ida_bytes.get_max_strlit_length(ea, ida_nalt.STRTYPE_C, ida_bytes.ALOPT_IGNHEADS)
                    ea += max(1, skip)
                    continue
            elif looks_utf16le_run(ea, s.end_ea, STRING_MIN_UTF16_CHARS):
                if ida_bytes.create_strlit(ea, 0, ida_nalt.STRTYPE_C_16) != idaapi.BADADDR:
                    created += 1
                    log(f"[str] UTF16 @ {hex(ea)}")
                    skip = ida_bytes.get_max_strlit_length(ea, ida_nalt.STRTYPE_C_16, ida_bytes.ALOPT_IGNHEADS)
                    ea += max(2, skip)
                    continue
        ea = next_item(ea)
    return created

def define_missed_strings():
    total = 0
    for s in iter_segments():
        name = seg_name(s).lower()
        if name.startswith(".rsrc"):
            continue
        if seg_is_ro(s) or seg_is_dataish(s):
            total += define_strings_in_segment(s)
    return total

# --------------- phase 5: vtable STRUCTS ----------------
def read_ptr(ea):
    v = ida_bytes.get_qword(ea) if is_64bit() else ida_bytes.get_dword(ea)
    if v == idaapi.BADADDR:
        return None
    return v & ptr_mask()

def is_func_start(ea):
    f = ida_funcs.get_func(ea)
    return bool(f and f.start_ea == ea)

def contiguous_fnptr_run(start_ea, end_ea):
    cnt = 0
    step = PS()
    ea = start_ea
    while ea + step <= end_ea:
        tgt = read_ptr(ea)
        if tgt is None or not is_func_start(tgt):
            break
        cnt += 1
        ea += step
    return cnt

def safe_set_name(ea, base, idx=None):
    if RESPECT_EXISTING_NAMES and ida_name.get_name(ea):
        return False
    nm = f"{base}" if idx is None else f"{base}{idx}"
    nm = ida_name.validate_name(nm, 0)
    return bool(ida_name.set_name(ea, nm, ida_name.SN_NOCHECK | ida_name.SN_NOWARN))

def sanitize_ident(s):
    if not s:
        return ""
    out = []
    for ch in s:
        out.append(ch if (ch.isalnum() or ch == "_") else "_")
    r = "".join(out)
    if r and r[0].isdigit():
        r = "_" + r
    return r

def ensure_data_span(ea, size):
    step = PS()
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
    flag = ida_bytes.qword_flag() if is_64bit() else ida_bytes.dword_flag()
    for off in range(0, size, step):
        ida_bytes.create_data(ea + off, flag, step, idaapi.BADADDR)

def add_local_type_decl(decl_text):
    fn = getattr(idc, "parse_decls", None) or getattr(idc, "ParseTypes", None)
    if fn is None:
        if ida_typeinf:
            try:
                til = ida_typeinf.get_idati()
                tif = ida_typeinf.tinfo_t()
                ok = ida_typeinf.parse_decl(tif, til, decl_text, ida_typeinf.PT_SIL)
                return bool(ok)
            except Exception:
                return False
        return False
    try:
        res = fn(decl_text, 0)
        return bool(res)
    except Exception:
        return False

def apply_type_at(ea, type_name):
    try:
        if idc.SetType(ea, type_name):
            return True
    except Exception:
        pass
    if ida_typeinf:
        try:
            tif = ida_typeinf.tinfo_t()
            if ida_typeinf.parse_decl(tif, ida_typeinf.get_idati(), type_name, ida_typeinf.PT_SIL):
                return bool(ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE))
        except Exception:
            return False
    return False

def build_vt_struct_decl(base_ea, count, slot_target_names):
    suffix = f"{base_ea & 0xFFFFFFFF:X}"
    struct_name = VT_STRUCT_PREFIX + suffix
    lines = [f"struct {struct_name} {{"]
    for i in range(count):
        suggested = slot_target_names[i]
        ident = sanitize_ident(suggested) if suggested else f"f{i}"
        if not ident:
            ident = f"f{i}"
        lines.append(f"    void (*{ident})();")
    lines.append("};")
    return struct_name, "\n".join(lines)

def name_vtable_targets_and_slots(base_ea, count):
    step = PS()
    names = []
    for i in range(count):
        slot_ea = base_ea + i * step
        tgt = read_ptr(slot_ea)
        safe_set_name(slot_ea, f"{VT_ENTRY_PREFIX}{base_ea & 0xFFFFFFFF:X}_", i)
        tname = ida_name.get_name(tgt) if tgt else ""
        if not tname and tgt:
            if RESPECT_EXISTING_NAMES:
                ida_name.set_name(tgt, f"{VT_TARGET_PREFIX}{tgt & 0xFFFFFFFF:X}", ida_name.SN_NOWARN)
                tname = ida_name.get_name(tgt)
        names.append(tname)
    safe_set_name(base_ea, VT_STRUCT_PREFIX + f"{base_ea & 0xFFFFFFFF:X}")
    return names

def structify_vtable_at(base_ea, count):
    slot_target_names = name_vtable_targets_and_slots(base_ea, count)
    total_size = count * PS()
    ensure_data_span(base_ea, total_size)

    struct_name, decl = build_vt_struct_decl(base_ea, count, slot_target_names)
    if add_local_type_decl(decl):
        log(f"[vt] local type added:\n{decl}")
    else:
        warn(f"[vt] failed to add local type; using array fallback")
        arr_decl = f"void * {VT_STRUCT_PREFIX}{base_ea & 0xFFFFFFFF:X}[{count}];"
        add_local_type_decl(arr_decl)
        return apply_type_at(base_ea, arr_decl)

    ok = apply_type_at(base_ea, f"struct {struct_name}")
    if ok:
        log(f"[vt] struct applied @ {hex(base_ea)}: struct {struct_name} (fields={count})")
    else:
        warn(f"[vt] failed to apply struct; trying array fallback @ {hex(base_ea)}")
        arr_decl = f"void * {VT_STRUCT_PREFIX}{base_ea & 0xFFFFFFFF:X}[{count}];"
        add_local_type_decl(arr_decl)
        ok = apply_type_at(base_ea, arr_decl)
    return ok

def find_and_structify_vtables():
    total_tables = 0
    total_slots  = 0
    for s in iter_segments():
        if not seg_is_ro(s):
            continue
        name = seg_name(s).lower()
        if name.startswith(".rsrc"):
            continue
        log(f"[vt-scan] RO seg {seg_name(s)} {hex(s.start_ea)}..{hex(s.end_ea)}")
        step = PS()
        ea = s.start_ea
        while ea + step <= s.end_ea:
            run = contiguous_fnptr_run(ea, s.end_ea)
            if run >= VTABLE_MIN_PTRS:
                if structify_vtable_at(ea, run):
                    total_tables += 1
                    total_slots  += run
                    log(f"[vt] + vtable struct @ {hex(ea)} count={run}")
                else:
                    warn(f"[vt] unable to structify @ {hex(ea)} (count={run})")
                ea += run * step
                continue
            ea = next_item(ea)
    return total_tables, total_slots

# ---------------- orchestrator ----------------
def run():
    log("=== ultrafixup second pass (IDA 9.2) ? structified vtables [fix7] ===")

    totals = {
        "decoded_insns": 0,
        "new_funcs": 0,
        "reanalyzed": 0,
        "new_strings": 0,
        "vtables": 0,
        "vt_slots": 0,
    }

    prev_progress = -1
    for p in range(1, MAX_PASSES + 1):
        log(f"\n--- pass {p}/{MAX_PASSES} ---")

        decoded = decode_undef_in_exec_segments()
        totals["decoded_insns"] += decoded
        auto_wait_safe()

        made_funcs = create_functions_from_undef_blocks()
        totals["new_funcs"] += made_funcs
        auto_wait_safe()

        re_f = reanalyze_all_functions()
        totals["reanalyzed"] += re_f
        auto_wait_safe()

        new_str = define_missed_strings()
        totals["new_strings"] += new_str
        auto_wait_safe()

        vt_count, vt_slots = find_and_structify_vtables()
        totals["vtables"] += vt_count
        totals["vt_slots"] += vt_slots
        auto_wait_safe()

        progress = decoded + made_funcs + re_f + new_str + vt_count
        log(f"[pass {p}] progress score={progress}")
        if progress == 0 or progress == prev_progress:
            log(f"[stop] no further progress at pass {p}")
            break
        prev_progress = progress

    log("\n=== ultrafixup summary ===")
    log(f"decoded instructions : {totals['decoded_insns']}")
    log(f"new functions        : {totals['new_funcs']}")
    log(f"reanalyzed functions : {totals['reanalyzed']}")
    log(f"new strings          : {totals['new_strings']}")
    log(f"vtables (structs)    : {totals['vtables']}  (slots: {totals['vt_slots']})")
    log("=== done ===")

if __name__ == "__main__":
    try:
        run()
    except Exception:
        err("unexpected exception; stack follows")
        ida_kernwin.msg(traceback.format_exc() + "\n")
