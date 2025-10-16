# gui_annotator_ida92_mfc.py
# IDA 9.2-compatible GUI annotator with MFC/AFX message-map scanning.
# Assumes your .rsrc formatter/parser has already run.
#
# Features:
# - Hard error if .rsrc still looks undefined (user must run their rsrc parser first)
# - Control index from rsrc_parser.get_control_index() or scraped from [ITEMEX] comments (with title=)
# - Annotates disasm and Hex-Rays line at exact EA
# - GUI API callsite decoding (WM_*, WM_COMMAND id/notify with control class/title)
# - Annotates immediate control-id uses in code
# - Tags IDS_* string xrefs
# - NEW: MFC/AFX message map scanning; comments handler functions with decoded entries

import re
import idaapi
import idc
import idautils
import ida_funcs
import ida_bytes
import ida_kernwin
import ida_ua
import ida_lines
import ida_name
import ida_nalt
import ida_ida
import ida_idaapi
import ida_segment

try:
    import ida_hexrays
    HAVE_HEXRAYS = ida_hexrays.init_hexrays_plugin()
except Exception:
    HAVE_HEXRAYS = False

LOG_PREFIX = "[GUI-ANNO]"
CMT_PREFIX = "[GUI]"
FUNC_SUMMARY_TAG = "[GUI-SUMMARY]"
IS_X64 = ida_ida.inf_is_64bit()
PTRSZ = 8 if IS_X64 else 4
MAX_BACKTRACK_INSNS = 20
COMMENT_LOG = []   # (ea, text)
DEDUP = True

# --------- sanity check: .rsrc must be processed ----------
def check_rsrc_ready():
    for s in idautils.Segments():
        seg = ida_segment.getseg(s)
        if not seg:
            continue
        name = (ida_segment.get_segm_name(seg) or "").lower()
        if name in (".rsrc", "rsrc"):
            defined, undefined = 0, 0
            ea, end = seg.start_ea, seg.end_ea
            limit = min(end, ea + 1 << 14)  # sample up to 16KB
            while ea < limit:
                if ida_bytes.is_unknown(ida_bytes.get_flags(ea)):
                    undefined += 1
                else:
                    defined += 1
                ea = ida_bytes.next_head(ea, end)
            if defined < (undefined * 0.05):
                ida_kernwin.warning(
                    "[GUI Annotator] ERROR:\n\n"
                    ".rsrc segment still looks undefined.\n"
                    "Run your rsrc parser/formatter first."
                )
                raise RuntimeError("rsrc unprocessed")
            return
    ida_kernwin.warning(
        "[GUI Annotator] ERROR:\n\n"
        "No .rsrc segment found in database."
    )
    raise RuntimeError("no .rsrc segment")

# --------- Win32 tables ----------
WM = {
    0x0000:"WM_NULL",0x0001:"WM_CREATE",0x0002:"WM_DESTROY",0x0003:"WM_MOVE",0x0005:"WM_SIZE",
    0x000F:"WM_PAINT",0x0010:"WM_CLOSE",0x0011:"WM_QUERYENDSESSION",0x0012:"WM_QUIT",
    0x0014:"WM_ERASEBKGND",0x0016:"WM_ENDSESSION",0x0018:"WM_SHOWWINDOW",0x001A:"WM_WININICHANGE",
    0x001C:"WM_ACTIVATEAPP",0x001D:"WM_FONTCHANGE",0x001E:"WM_TIMECHANGE",0x001F:"WM_CANCELMODE",
    0x0020:"WM_SETCURSOR",0x0021:"WM_MOUSEACTIVATE",0x0024:"WM_GETMINMAXINFO",0x0046:"WM_WINDOWPOSCHANGING",
    0x0047:"WM_WINDOWPOSCHANGED",0x0048:"WM_POWER",0x004A:"WM_COPYDATA",0x004B:"WM_CANCELJOURNAL",
    0x004E:"WM_NOTIFY",0x0100:"WM_KEYDOWN",0x0101:"WM_KEYUP",0x0102:"WM_CHAR",
    0x0110:"WM_INITDIALOG",0x0111:"WM_COMMAND",0x0112:"WM_SYSCOMMAND",0x0113:"WM_TIMER",
    0x0114:"WM_HSCROLL",0x0115:"WM_VSCROLL",0x0116:"WM_INITMENU",0x0117:"WM_INITMENUPOPUP",0x011F:"WM_MENUSELECT",
    0x0200:"WM_MOUSEMOVE",0x0201:"WM_LBUTTONDOWN",0x0202:"WM_LBUTTONUP",0x0203:"WM_LBUTTONDBLCLK",
    0x0204:"WM_RBUTTONDOWN",0x0205:"WM_RBUTTONUP",0x0206:"WM_RBUTTONDBLCLK",
    0x0207:"WM_MBUTTONDOWN",0x0208:"WM_MBUTTONUP",0x0209:"WM_MBUTTONDBLCLK",
}
# Extra control-specific messages to make SendMessage* decoding less useless
BM = {0xF0: "BM_GETCHECK", 0xF1: "BM_SETCHECK", 0xF2: "BM_GETSTATE", 0xF3: "BM_SETSTATE",
      0xF4: "BM_SETSTYLE", 0xF5: "BM_CLICK", 0xF6: "BM_GETIMAGE", 0xF7: "BM_SETIMAGE"}
EM = {0x000C: "EM_SETLIMITTEXT", 0x000D: "EM_GETLIMITTEXT", 0x000E: "EM_POSFROMCHAR",
      0x00C1: "EM_SETCUEBANNER"}  # cut set for sanity
LB = {0x0180: "LB_ADDSTRING", 0x0181: "LB_INSERTSTRING", 0x0182: "LB_DELETESTRING",
      0x0183: "LB_SELITEMRANGEEX", 0x0185: "LB_RESETCONTENT"}
CB = {0x0143: "CB_ADDSTRING", 0x0144: "CB_DELETESTRING", 0x0145: "CB_INSERTSTRING",
      0x014E: "CB_GETCURSEL", 0x014F: "CB_SETCURSEL"}

# Common control messages (partial, enough to get meaningful comments)
LVM = {0x1000+0: "LVM_FIRST", 0x1000+31: "LVM_SETITEM", 0x1000+76: "LVM_SETEXTENDEDLISTVIEWSTYLE"}
TVM = {0x1100+0: "TVM_FIRST", 0x1100+63: "TVM_INSERTITEM"}
TCM = {0x1300+0: "TCM_FIRST", 0x1300+46: "TCM_SETCURSEL"}

BN  = {0:"BN_CLICKED",1:"BN_PAINT",2:"BN_HILITE",3:"BN_UNHILITE",4:"BN_DISABLE",5:"BN_DOUBLECLICKED",
       6:"BN_SETSTATE",7:"BN_KILLFOCUS",8:"BN_SETFOCUS",0xF5:"BN_PUSHED",0xF6:"BN_UNPUSHED"}
CBN = {1:"CBN_SELCHANGE",2:"CBN_DBLCLK",3:"CBN_SETFOCUS",4:"CBN_KILLFOCUS",5:"CBN_EDITCHANGE",
       6:"CBN_EDITUPDATE",7:"CBN_DROPDOWN",8:"CBN_CLOSEUP",9:"CBN_SELENDOK",10:"CBN_SELENDCANCEL"}
LBN = {1:"LBN_SELCHANGE",2:"LBN_DBLCLK",3:"LBN_SELCANCEL",4:"LBN_SETFOCUS",5:"LBN_KILLFOCUS"}
X86_REGS = ["eax","ecx","edx","ebx","esp","ebp","esi","edi"]

TARGET_APIS = {
    "CreateWindowExA":(12,[1,2,3,4,5,6]), "CreateWindowExW":(12,[1,2,3,4,5,6]),
    "RegisterClassExA":(1,[]), "RegisterClassExW":(1,[]),
    "DialogBoxParamA":(4,[1,2,3,4]), "DialogBoxParamW":(4,[1,2,3,4]),
    "CreateDialogParamA":(4,[1,2,3,4]), "CreateDialogParamW":(4,[1,2,3,4]),
    "LoadStringA":(4,[1,2]), "LoadStringW":(4,[1,2]),
    "LoadMenuA":(2,[1]), "LoadMenuW":(2,[1]),
    "GetDlgItem":(2,[1,2]), "GetDlgItemTextA":(4,[1,2]), "GetDlgItemTextW":(4,[1,2]),
    "SetDlgItemTextA":(3,[1,2,3]), "SetDlgItemTextW":(3,[1,2,3]),
    "SendMessageA":(4,[1,2,3,4]), "SendMessageW":(4,[1,2,3,4]),
    "PostMessageA":(4,[1,2,3,4]), "PostMessageW":(4,[1,2,3,4]),
    "TrackPopupMenu":(6,[1,2,3]),
    "MessageBoxA":(4,[1,2]), "MessageBoxW":(4,[1,2]),
    "Shell_NotifyIconA":(2,[1,2]), "Shell_NotifyIconW":(2,[1,2]),
    "SendDlgItemMessageA": (5, [1,2,3,4,5]),
    "SendDlgItemMessageW": (5, [1,2,3,4,5]),
    "CheckDlgButton":      (3, [1,2,3]),
    "IsDlgButtonChecked":  (2, [1,2]),
    "SetWindowLongPtrA":   (4, [1,2,3,4]),
    "SetWindowLongPtrW":   (4, [1,2,3,4]),
    "SetWindowLongA":      (4, [1,2,3,4]),
    "SetWindowLongW":      (4, [1,2,3,4]),
    "SetWindowSubclass":   (5, [1,2,3,4,5]),
    "DefSubclassProc":     (4, [1,2,3,4]),
    "CreateAcceleratorTableA": (2, [1,2]),
    "CreateAcceleratorTableW": (2, [1,2]),
    "TranslateAcceleratorA": (3, [1,2,3]),
    "TranslateAcceleratorW": (3, [1,2,3]),
    "LoadAcceleratorsA":   (2, [1,2]),
    "LoadAcceleratorsW":   (2, [1,2]),
    "LoadMenuIndirectA":   (1, [1]),
    "LoadMenuIndirectW":   (1, [1]),
}

# Prefer to attach CTRL-id comments to the *consumer* API call that uses the HWND
SHIFT_CTRL_COMMENTS_TO_CALL = False
CONSUMER_APIS = {
    # window invalidation/painting
    "InvalidateRect", "InvalidateRgn", "RedrawWindow", "UpdateWindow",
    # visibility / focus / enablement / geometry
    "ShowWindow", "EnableWindow", "SetFocus", "SetWindowPos", "MoveWindow",
    # text/label tweaks
    "SetWindowTextA", "SetWindowTextW",
    # generic send/dispatch that often uses the handle/ID right before
    "SendMessageA", "SendMessageW", "PostMessageA", "PostMessageW",
    # dialog helpers
    "GetDlgItem", "GetDlgItemTextA", "GetDlgItemTextW",
    "SetDlgItemTextA", "SetDlgItemTextW",
}
# APIs where a numeric control ID is explicitly passed (0-based arg index)
CTRL_ID_PARAM_APIS = {
    "GetDlgItem": 1,
    "GetDlgItemTextA": 1,
    "GetDlgItemTextW": 1,
    "SetDlgItemTextA": 1,
    "SetDlgItemTextW": 1,
    "SendDlgItemMessageA": 1,
    "SendDlgItemMessageW": 1,
    "CheckDlgButton": 1,
    "IsDlgButtonChecked": 1,
}


DLG_CLASS_ORDINALS = {0x80:"BUTTON",0x81:"EDIT",0x82:"STATIC",0x83:"LISTBOX",0x84:"SCROLLBAR",0x85:"COMBOBOX"}
IDS_REGEX = re.compile(rb"\bIDS_[A-Z0-9_]+\b")

CONTROL_INDEX = {}  # id -> {class, where, style, rect, dlg, title}

# --------- utilities ----------
def log(msg): ida_kernwin.msg(f"{LOG_PREFIX} {msg}\n")
def fmt_cmt(s): return f"{CMT_PREFIX} {s}"
def sanitize_name(n): return (n or "").split("@")[0]

def set_cmt(ea, text, repeatable=False):
    old = idc.get_cmt(ea, int(bool(repeatable))) or ""
    if DEDUP and old.strip() == text.strip():
        return
    idc.set_cmt(ea, text, int(bool(repeatable)))
    COMMENT_LOG.append((ea, text))
    ida_kernwin.msg(f"{LOG_PREFIX} + {ea:#x}: {text}\n")

def try_decomp_cmt(ea, text):
    if not HAVE_HEXRAYS: return
    try:
        f = ida_funcs.get_func(ea)
        if not f: return
        cfunc = ida_hexrays.decompile(f.start_ea)
        if not cfunc: return
        tl = ida_hexrays.treeloc_t()
        tl.ea = ea
        tl.itp = ida_hexrays.ITP_SEMI
        # merge if an existing user comment is present at the same treeloc
        final = text
        ucm = ida_hexrays.user_cmts_t()
        try:
            cfunc.get_user_cmts(ucm)
            existing = ucm.retrieve(tl) if hasattr(ucm, "retrieve") else None
            if existing and text not in existing:
                final = existing + "\n" + text
        except Exception:
            pass
        cfunc.set_user_cmt(tl, final)
        cfunc.save_user_cmts()
    except Exception:
        pass

def _prev_head(ea, minea): return ida_bytes.prev_head(ea, minea)
def _next_head(ea, maxea): return ida_bytes.next_head(ea, maxea)
def _func_start_for(ea):
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else idc.MinEA()

def get_operand_imm(ea, opn):
    insn = ida_ua.insn_t()
    if not ida_ua.decode_insn(insn, ea): return None
    op = insn.ops[opn]
    return op.value if op.type == ida_ua.o_imm else None

def get_callee_name(ea):
    tgt = idc.get_operand_value(ea, 0)
    if tgt == idc.BADADDR:
        return idc.print_operand(ea, 0) or ""
    return ida_name.get_ea_name(tgt) or idc.get_name(tgt, idc.GN_VISIBLE) or ""

def list_all_calls(func_ea):
    for insn_ea in idautils.FuncItems(func_ea):
        if idc.print_insn_mnem(insn_ea).lower().startswith("call"):
            yield insn_ea

def annotate_wndproc_candidates():
    hits = 0
    # 1) Call-site arg sniffing: CreateWindowEx*, DialogBoxParam*, SetWindowLongPtr(GWLP_WNDPROC), SetWindowSubclass
    wnd_like_apis = {
        "CreateWindowExA": 3, "CreateWindowExW": 3,        # lpWindowName is 2, lpWndProc is not direct here; class proc via RegisterClassEx
        "RegisterClassExA": 0, "RegisterClassExW": 0,      # we could deref WNDCLASSEX, but that?s a rabbit hole
        "DialogBoxParamA": 3, "DialogBoxParamW": 3,        # dlgproc index
        "CreateDialogParamA": 3, "CreateDialogParamW": 3,
        "SetWindowLongPtrA": 2, "SetWindowLongPtrW": 2,    # GWLP_WNDPROC case when index == -4
        "SetWindowLongA": 2, "SetWindowLongW": 2,
        "SetWindowSubclass": 1,                            # SUBCLASSPROC
    }
    for f in idautils.Functions():
        for call_ea in list_all_calls(f):
            name = sanitize_name(get_callee_name(call_ea))
            if "." in name: name = name.split(".")[-1]
            if name not in wnd_like_apis:
                continue
            argc = wnd_like_apis[name]
            args = recover_args_for_call(call_ea, max(argc+1, 4))
            proc = args[argc] if len(args) > argc else None
            # Heuristic: if proc is immediate code pointer, tag its function
            if isinstance(proc, int) and _is_code_ptr(proc):
                fn = ida_funcs.get_func(proc)
                if not fn:
                    ida_funcs.add_func(proc)
                    fn = ida_funcs.get_func(proc)
                if fn:
                    tag = fmt_cmt(f"Candidate {'DialogProc' if 'Dialog' in name else 'WndProc' if 'SetWindowLong' in name or 'Subclass' in name else 'callback'} from {name} at {call_ea:#x}")
                    set_cmt(fn.start_ea, tag, repeatable=False)
                    try_decomp_cmt(fn.start_ea, tag)
                    hits += 1
            # Special case: SetWindowLongPtr index == GWLP_WNDPROC (-4)
            if name.startswith("SetWindowLong"):
                if len(args) >= 3:
                    index = args[1]
                    if isinstance(index, int) and index in (-4, 0xFFFFFFFC):
                        newproc = args[2]
                        if isinstance(newproc, int) and _is_code_ptr(newproc):
                            fn = ida_funcs.get_func(newproc)
                            if not fn:
                                ida_funcs.add_func(newproc)
                                fn = ida_funcs.get_func(newproc)
                            if fn:
                                tag = fmt_cmt(f"Subclass WndProc via {name} at {call_ea:#x}")
                                set_cmt(fn.start_ea, tag, repeatable=False)
                                try_decomp_cmt(fn.start_ea, tag)
                                hits += 1
    if hits:
        log(f"WndProc/DialogProc candidates annotated: {hits}")

def parse_atl_msgmaps(max_scan_bytes_per_seg=1<<20):
    # Very heuristic; we look for arrays with (msg, id, lastid, code, pfn)
    entries = []
    wm_keys = set(WM.keys())
    for seg in _data_segs():
        start, end = seg.start_ea, min(seg.end_ea, seg.start_ea + max_scan_bytes_per_seg)
        ea = (start + (PTRSZ-1)) & ~(PTRSZ-1)
        rowsz = (5*4 + PTRSZ) if IS_X64 else (5*4 + 4)
        while ea + rowsz <= end:
            msg = _u32(ea)
            idv = _u32(ea+4)
            idl = _u32(ea+8)
            code = _u32(ea+12)
            # skip signature-like dword
            pfn = _uptr(ea+16) if IS_X64 else _u32(ea+16)
            if (msg in wm_keys) and (pfn == 0 or _is_code_ptr(pfn)):
                # walk array until zero row
                idx, rowea, saw = 0, ea, False
                while rowea + rowsz <= end:
                    m = _u32(rowea); i = _u32(rowea+4); l = _u32(rowea+8); c = _u32(rowea+12)
                    f = _uptr(rowea+16) if IS_X64 else _u32(rowea+16)
                    if m==0 and i==0 and l==0 and c==0 and f==0:
                        break
                    if (m in wm_keys) and (i <= max(l, i)) and (f == 0 or _is_code_ptr(f)):
                        entries.append({"msg":m,"code":c,"id":i,"idLast":l,"pfn":f,"ea_array":ea,"index":idx,"atl":True})
                        saw = True; idx += 1; rowea += rowsz; continue
                    break
                ea = rowea + rowsz
                continue
            ea += PTRSZ
    return entries

def annotate_atl_handlers(entries):
    count = 0
    for e in entries:
        pfn = e["pfn"]
        if not pfn: continue
        f = ida_funcs.get_func(pfn) or (ida_funcs.add_func(pfn) or ida_funcs.get_func(pfn))
        if not f: continue
        msgname = WM.get(e["msg"], f"WM_{e['msg']:#x}")
        lo, hi = e["id"], e["idLast"]
        id_part = f"id={lo}" if lo == hi else f"id={lo}..{hi}"
        ctrl_part = _ctrl_desc_for_id(lo) if lo == hi else ""
        text = fmt_cmt(f"ATL: {msgname} {id_part}{(' ' + ctrl_part) if ctrl_part else ''}  (map@{e['ea_array']:#x}[{e['index']}])")
        set_cmt(f.start_ea, text, repeatable=False)
        try_decomp_cmt(f.start_ea, text)
        count += 1
    if count:
        log(f"ATL/WTL message-map: annotated {count} handler entries")

def _is_call_ea(ea: int) -> bool:
    return idc.print_insn_mnem(ea).lower().startswith("call")

def _consumer_name_at_call(ea: int) -> str:
    """Return short callee name if EA is a call; else empty string."""
    if not _is_call_ea(ea):
        return ""
    name = sanitize_name(get_callee_name(ea))
    if "." in name:
        name = name.split(".")[-1]
    return name

def _find_forward_consumer_call(start_ea: int, max_steps: int = 12) -> int:
    """
    From 'start_ea', walk forward up to max_steps instructions, and:
      1) return first call whose callee is in CONSUMER_APIS
      2) else return the first call we encounter
      3) else return BADADDR
    """
    if not SHIFT_CTRL_COMMENTS_TO_CALL:
        return idc.BADADDR

    f = ida_funcs.get_func(start_ea)
    if not f:
        return idc.BADADDR
    maxea = f.end_ea
    ea = ida_bytes.next_head(start_ea, maxea)
    steps = 0
    first_call = idc.BADADDR
    while ea != idc.BADADDR and ea < maxea and steps < max_steps:
        if _is_call_ea(ea):
            if first_call == idc.BADADDR:
                first_call = ea
            callee = _consumer_name_at_call(ea)
            if callee in CONSUMER_APIS:
                return ea
        ea = ida_bytes.next_head(ea, maxea)
        steps += 1
    return first_call

# --------- pull control index from your parser or .rsrc comments ----------
def _find_rsrc_bounds():
    for s in idautils.Segments():
        seg = ida_segment.getseg(s)
        nm = (ida_segment.get_segm_name(seg) or "").lower()
        if nm in (".rsrc","rsrc"):
            return seg.start_ea, seg.end_ea
    return None, None

ITEM_RE = re.compile(
    r"\[ITEMEX\]\s*id=0x([0-9A-Fa-f]+)\s+class=([A-Za-z0-9_]+)(?:\s+title=([^\r\n]*))?"
)

def build_control_index():
    CONTROL_INDEX.clear()
    # 1) try user's module
    try:
        import rsrc_parser
        try:
            ci = rsrc_parser.get_control_index()
            if isinstance(ci, dict) and ci:
                for cid, meta in ci.items():
                    CONTROL_INDEX[int(cid)] = {
                        "class": meta.get("class"),
                        "where": meta.get("where"),
                        "style": meta.get("style"),
                        "rect":  meta.get("rect"),
                        "dlg":   meta.get("dlg"),
                        "title": meta.get("title"),
                    }
                log(f"CONTROL_INDEX: imported {len(CONTROL_INDEX)} entries from rsrc_parser")
                return
        except Exception:
            pass
    except Exception:
        pass
    # 2) scrape .rsrc comments
    rstart, rend = _find_rsrc_bounds()
    if not rstart:
        log("No .rsrc bounds for scraping.")
        return
    hits, ea = 0, rstart
    while ea < rend:
        for rep in (False, True):
            c = idc.get_cmt(ea, int(rep)) or ""
            if not c: continue
            m = ITEM_RE.search(c)
            if m:
                cid = int(m.group(1), 16)
                klass = m.group(2)
                title = (m.group(3) or "").strip() or None
                CONTROL_INDEX.setdefault(cid, {
                    "class": klass, "where": ea, "style": None, "rect": (None,None,None,None),
                    "dlg": None, "title": title
                })
                hits += 1
        ea = _next_head(ea, rend)
    if hits:
        log(f"CONTROL_INDEX: scraped {len(CONTROL_INDEX)} entries from .rsrc comments (with titles)")
    else:
        log("CONTROL_INDEX: empty. Proceeding without cross-linking.")

# --------- x86 helpers ----------
def backtrack_args_x86(call_ea, needed):
    args, insn = [], ida_ua.insn_t()
    minea = _func_start_for(call_ea)
    ea = _prev_head(call_ea, minea)
    steps = 0
    while ea != idc.BADADDR and ea >= minea and steps < MAX_BACKTRACK_INSNS and len(args) < needed:
        if ida_ua.decode_insn(insn, ea):
            m = idc.print_insn_mnem(ea).lower()
            if m == "push":
                imm = get_operand_imm(ea, 0)
                args.append(imm if imm is not None else idc.print_operand(ea, 0))
            elif m in ("call","retn","ret"):
                break
        ea = _prev_head(ea, minea)
        steps += 1
    args.reverse()
    return args

def backtrack_reg_value_x86(start_ea, regname, limit=MAX_BACKTRACK_INSNS):
    reg = regname.lower()
    if reg not in X86_REGS:
        return None
    f = ida_funcs.get_func(start_ea)
    minea = f.start_ea if f else idc.MinEA()
    ea = ida_bytes.prev_head(start_ea, minea)
    steps = 0
    insn = ida_ua.insn_t()
    while ea != idc.BADADDR and ea >= minea and steps < limit:
        if ida_ua.decode_insn(insn, ea):
            m = idc.print_insn_mnem(ea).lower()
            dst = idc.print_operand(ea, 0).lower()
            if m.startswith("mov") and dst == reg:
                imm = get_operand_imm(ea, 1)
                if imm is not None:
                    return imm
                return None
            if m.startswith(("xor","sub")) and idc.print_operand(ea,0).lower()==reg and idc.print_operand(ea,1).lower()==reg:
                return 0
        ea = ida_bytes.prev_head(ea, minea)
        steps += 1
    return None

def backtrack_args_x64(call_ea, needed):
    regs = ["rcx","rdx","r8","r9"]
    values = [None,None,None,None]
    insn = ida_ua.insn_t()
    minea = _func_start_for(call_ea)
    ea = _prev_head(call_ea, minea)
    steps = 0
    while ea != idc.BADADDR and ea >= minea and steps < MAX_BACKTRACK_INSNS and any(v is None for v in values[:min(needed,4)]):
        if ida_ua.decode_insn(insn, ea):
            m = idc.print_insn_mnem(ea).lower()
            if m.startswith("mov"):
                dst = idc.print_operand(ea, 0).lower()
                src = idc.print_operand(ea, 1)
                for i, r in enumerate(regs):
                    if values[i] is None and dst == r:
                        imm = get_operand_imm(ea, 1)
                        values[i] = imm if imm is not None else src
            elif m.startswith("lea"):
                dst = idc.print_operand(ea, 0).lower()
                src = idc.print_operand(ea, 1)
                for i, r in enumerate(regs):
                    if values[i] is None and dst == r:
                        values[i] = src
        ea = _prev_head(ea, minea); steps += 1
    return values[:needed]

def recover_args_for_call(call_ea, min_argc):
    vals = backtrack_args_x64(call_ea, min_argc) if IS_X64 else backtrack_args_x86(call_ea, min_argc)
    def norm(v):
        if isinstance(v, int) or v is None: return v
        return str(v)
    return [norm(v) for v in vals]

# --------- IDS strings tagging ----------
def scan_ids_strings():
    hits = {}
    for s in idautils.Strings():
        try:
            bs = ida_bytes.get_strlit_contents(int(s.ea), s.length, s.type)
            if not bs: continue
            if IDS_REGEX.search(bs):
                try:
                    txt = bs.decode("ascii", errors="ignore")
                except Exception:
                    txt = repr(bs)
                refs = list(idautils.XrefsTo(int(s.ea)))
                if refs:
                    hits.setdefault(txt, []).extend(refs)
        except Exception:
            continue
    return hits

def annotate_ids_xrefs(ids_hits):
    for ids_text, xrs in ids_hits.items():
        for xr in xrs:
            ea = xr.frm
            c = fmt_cmt(f"refs {ids_text}")
            set_cmt(ea, c, repeatable=False)
            try_decomp_cmt(ea, c)

# --------- control-id immediate usage ----------
def annotate_control_id_usage(func_ea):
    """
    Safe control-ID annotations:
      1) At calls where the API takes a control ID argument (per CTRL_ID_PARAM_APIS).
      2) At 'cmp/test' sites that look like LOWORD(wParam) == <id> in WM_COMMAND handlers.
    No generic immediate scanning. No shifting to unrelated calls.
    """
    lines = []
    # --- 1) Callsite annotations for ID-taking APIs ---
    for call_ea in list_all_calls(func_ea):
        name = sanitize_name(get_callee_name(call_ea))
        if "." in name:
            name = name.split(".")[-1]
        if name in CTRL_ID_PARAM_APIS:
            idx = CTRL_ID_PARAM_APIS[name]
            # Make sure we recovered enough args
            args = recover_args_for_call(call_ea, idx + 1)
            if len(args) <= idx:
                continue
            cid = args[idx]
            if isinstance(cid, int) and cid in CONTROL_INDEX:
                meta = CONTROL_INDEX[cid]
                klass = meta.get("class", "?")
                where = meta.get("where", 0)
                title = meta.get("title")
                tfrag = f" '{title}'" if title else ""
                text = fmt_cmt(f"CTRL id={cid} [{klass}]{tfrag} from .rsrc at {where:#x}")
                set_cmt(call_ea, text, False)
                try_decomp_cmt(call_ea, text)
                lines.append(text)

    # --- 2) Compare sites that look like LOWORD(wParam) vs ID in WM_COMMAND context ---
    # Heuristic: only do this if the function likely handles WM_COMMAND.
    # We detect that by looking for:
    #   a) our own earlier WM compare tags in this function, or
    #   b) a Send/PostMessage with msg==WM_COMMAND within the function, or
    #   c) an MFC/ATL message-map annotation already added to the function start.
    looks_like_wm_command = False
    # a) scan for disasm comments we added (cheap)
    for ea in idautils.FuncItems(func_ea):
        c = idc.get_cmt(ea, 0) or ""
        if "WM_COMMAND" in c:
            looks_like_wm_command = True
            break
    # b) or presence of a call we annotated as WM_COMMAND
    if not looks_like_wm_command:
        for call_ea in list_all_calls(func_ea):
            c = idc.get_cmt(call_ea, 0) or ""
            if "WM_COMMAND" in c:
                looks_like_wm_command = True
                break
    # c) function-level MFC/ATL summary
    if not looks_like_wm_command:
        fc = idc.get_func_cmt(func_ea, 1) or ""
        if "MFC:" in fc or "ATL:" in fc:
            looks_like_wm_command = True

    if looks_like_wm_command:
        for ea in idautils.FuncItems(func_ea):
            m = idc.print_insn_mnem(ea).lower()
            if m not in ("cmp", "test"):
                continue
            # imm on op1 is common; if not, also try op0 for 'cmp imm, reg'
            imm = get_operand_imm(ea, 1)
            if imm is None:
                imm = get_operand_imm(ea, 0)
            if not isinstance(imm, int):
                continue
            if imm not in CONTROL_INDEX:
                continue  # only tag real control IDs

            # Check the other operand looks like a 16-bit low word of something:
            op0 = idc.print_operand(ea, 0).lower()
            op1 = idc.print_operand(ea, 1).lower()
            other = op1 if imm == get_operand_imm(ea, 0) else op0
            # crude but effective filters to reduce noise
            hint_loword = ("word ptr" in other) or (other in ("ax", "cx", "dx", "si", "di"))
            # Also scan a small window backward for 'and reg, 0FFFFh' or 'movzx reg, word ptr ...'
            if not hint_loword:
                back_ok = False
                bk = ea
                steps = 0
                while steps < 8:
                    bk = ida_bytes.prev_head(bk, _func_start_for(ea))
                    if bk == idc.BADADDR:
                        break
                    mm = idc.print_insn_mnem(bk).lower()
                    if mm.startswith("and"):
                        if "0ffffh" in idc.print_operand(bk, 1).lower():
                            back_ok = True
                            break
                    if mm.startswith("movzx") and "word ptr" in (idc.print_operand(bk, 1).lower()):
                        back_ok = True
                        break
                    steps += 1
                hint_loword = back_ok

            if not hint_loword:
                continue  # bail: not obviously LOWORD context

            cid = imm
            meta = CONTROL_INDEX[cid]
            klass = meta.get("class", "?")
            where = meta.get("where", 0)
            title = meta.get("title")
            tfrag = f" '{title}'" if title else ""
            text = fmt_cmt(f"CTRL id={cid} [{klass}]{tfrag} from .rsrc at {where:#x}")
            set_cmt(ea, text, False)
            try_decomp_cmt(ea, text)
            lines.append(text)

    return lines



# --------- API call annotation ----------
def decode_wm(val):
    if isinstance(val, int):
        if val in WM:
            return WM[val]
        for tbl in EXTRA_MSG_TABLES:
            if val in tbl:
                return tbl[val]
        return f"WM_{val:#x}"
    return str(val)

def decode_notify(code, kind):
    tbl = {"BN":BN,"CBN":CBN,"LBN":LBN}.get(kind, {})
    return tbl.get(code, f"{kind}_{code}") if isinstance(code,int) else str(code)

def annotate_call(call_ea, api_name, args):
    pieces = []
    if api_name.startswith("CreateWindowEx"):
        cls = args[1] if len(args)>1 else None
        title = args[2] if len(args)>2 else None
        style = args[3] if len(args)>3 else None
        pieces.append(f"CreateWindowEx: class={cls} title={title} style={style}")
        
    elif api_name.startswith("SendDlgItemMessage"):
        dlg = args[0] if len(args)>0 else None
        ctrl_id = args[1] if len(args)>1 else None
        msg = args[2] if len(args)>2 else None
        wparam = args[3] if len(args)>3 else None
        lparam = args[4] if len(args)>4 else None
        msg_name = decode_wm(msg) if isinstance(msg, int) else msg
        detail = f"{api_name}: ctrl_id={ctrl_id} msg={msg_name} wParam={wparam} lParam={lparam}"
        if isinstance(ctrl_id, int) and ctrl_id in CONTROL_INDEX:
            klass = CONTROL_INDEX[ctrl_id].get('class')
            title = CONTROL_INDEX[ctrl_id].get('title')
            tfrag = f" '{title}'" if title else ""
            detail += f" [{klass}{tfrag}]"
        pieces.append(detail)

    elif api_name.startswith(("DialogBoxParam","CreateDialogParam")):
        hinst = args[0] if len(args)>0 else None
        tmpl  = args[1] if len(args)>1 else None
        parent= args[2] if len(args)>2 else None
        dlgpr = args[3] if len(args)>3 else None
        pieces.append(f"{api_name}: hInst={hinst} template={tmpl} parent={parent} dlgproc={dlgpr}")

    elif api_name.startswith("LoadString"):
        hinst = args[0] if len(args)>0 else None
        resid = args[1] if len(args)>1 else None
        pieces.append(f"LoadString: hInst={hinst} id={resid}")

    elif api_name.startswith("LoadMenu"):
        resid = args[0] if len(args)>0 else None
        pieces.append(f"LoadMenu: id={resid}")

    elif api_name in ("GetDlgItem","GetDlgItemTextA","GetDlgItemTextW","SetDlgItemTextA","SetDlgItemTextW"):
        if len(args)>=2:
            pieces.append(f"{api_name}: ctrl_id={args[1]}")

    elif api_name.startswith(("SendMessage","PostMessage")):
        msg = args[1] if len(args)>1 else None
        wparam = args[2] if len(args)>2 else None
        lparam = args[3] if len(args)>3 else None
        if not IS_X64 and isinstance(msg,str) and msg.lower() in X86_REGS:
            resolved = backtrack_reg_value_x86(call_ea, msg.lower())
            if isinstance(resolved,int):
                msg = resolved
                args = list(args); args[1] = resolved
        msg_name = decode_wm(msg) if isinstance(msg,int) else msg
        detail = f"{api_name}: msg={msg_name} wParam={wparam} lParam={lparam}"
        if isinstance(msg,int) and msg==0x0111 and isinstance(wparam,int):
            ctrl_id = wparam & 0xFFFF
            notify  = (wparam >> 16) & 0xFFFF
            # guess notify family by control class
            kind = None
            if ctrl_id in CONTROL_INDEX:
                k = (CONTROL_INDEX[ctrl_id].get("class") or "").upper()
                if k=="BUTTON": kind="BN"
                elif k=="COMBOBOX": kind="CBN"
                elif k=="LISTBOX": kind="LBN"
            notify_name = decode_notify(notify, kind or "BN")
            detail += f"  (WM_COMMAND: ctrl_id={ctrl_id} notify={notify_name})"
            if ctrl_id in CONTROL_INDEX:
                klass = CONTROL_INDEX[ctrl_id].get('class')
                title = CONTROL_INDEX[ctrl_id].get('title')
                tfrag = f" '{title}'" if title else ""
                detail += f" [{klass}{tfrag}]"
        # WM_NOTIFY: wParam is control id; lParam -> NMHDR*
        if isinstance(msg, int) and msg == 0x004E:  # WM_NOTIFY
            ctrl_id = wparam if isinstance(wparam, int) else None
            # Best-effort: even without dereferencing lParam (stack/local), show control and say NMHDR present
            if isinstance(ctrl_id, int):
                detail += f"  (WM_NOTIFY: ctrl_id={ctrl_id}"
                if ctrl_id in CONTROL_INDEX:
                    klass = CONTROL_INDEX[ctrl_id].get('class')
                    title = CONTROL_INDEX[ctrl_id].get('title')
                    tfrag = f" '{title}'" if title else ""
                    detail += f" [{klass}{tfrag}]"
                detail += ")"
        pieces.append(detail)



    elif api_name.startswith("MessageBox"):
        pieces.append(f"{api_name}: text={args[1] if len(args)>1 else None}")

    elif api_name.startswith("RegisterClassEx"):
        pieces.append(f"{api_name}: WNDCLASSEX*={args[0] if args else None}")

    elif api_name=="TrackPopupMenu":
        pieces.append(f"TrackPopupMenu: flags={args[0] if args else None} x={args[1] if len(args)>1 else None} y={args[2] if len(args)>2 else None}")

    if not pieces:
        pieces.append(f"{api_name}: args={args}")

    text = fmt_cmt(" | ".join(str(p) for p in pieces))
    set_cmt(call_ea, text, repeatable=False)
    try_decomp_cmt(call_ea, text)
    return text

# --------- MFC/AFX message map scanning ----------
# Heuristic AFX_MSGMAP_ENTRY layout assumption:
# struct { UINT msg; UINT code; UINT id; UINT idLast; UINT sig; PVOID pfn; }
# Terminator: all zeros (msg==0 && code==0 && id==0 && idLast==0 && sig==0 && pfn==0)
# We detect arrays in DATA segments with plausible values and pfn pointing into a code segment.

def _is_code_ptr(p):
    if not isinstance(p, int) or p == 0 or p == idc.BADADDR:
        return False
    seg = ida_segment.getseg(p)
    if not seg: return False
    return seg.perm & ida_segment.SEGPERM_EXEC != 0

def _uptr(ea):
    b = ida_bytes.get_bytes(ea, PTRSZ)
    if not b: return None
    return int.from_bytes(b, "little", signed=False)

def _u32(ea):
    b = ida_bytes.get_bytes(ea, 4)
    if not b: return None
    return int.from_bytes(b, "little", signed=False)

def _data_segs():
    for s in idautils.Segments():
        seg = ida_segment.getseg(s)
        if seg and (seg.perm & ida_segment.SEGPERM_WRITE):
            yield seg

def parse_mfc_msgmaps(max_scan_bytes_per_seg=1<<20):
    """
    Return list of entries:
      dict(msg, code, id, idLast, sig, pfn, ea_array, index)
    """
    entries = []
    wm_keys = set(WM.keys())
    for seg in _data_segs():
        start, end = seg.start_ea, min(seg.end_ea, seg.start_ea + max_scan_bytes_per_seg)
        ea = (start + (PTRSZ-1)) & ~(PTRSZ-1)  # align
        while ea + PTRSZ*6 <= end:
            # read one candidate row
            msg   = _u32(ea)
            code  = _u32(ea+4)
            idv   = _u32(ea+8)
            idlv  = _u32(ea+12)
            sig   = _u32(ea+16)
            pfn   = _uptr(ea+20) if IS_X64 else _u32(ea+20)
            # quick plausibility: message must be in WM or 0; function must be in code (unless zero)
            plausible = (msg in wm_keys or msg == 0)
            if plausible and (pfn == 0 or _is_code_ptr(pfn)):
                # Walk forward as an array if plausible
                arr_ea = ea
                idx = 0
                rowea = ea
                saw_one = False
                while rowea + PTRSZ*6 <= end:
                    m = _u32(rowea)
                    c = _u32(rowea+4)
                    i = _u32(rowea+8)
                    l = _u32(rowea+12)
                    s = _u32(rowea+16)
                    f = _uptr(rowea+20) if IS_X64 else _u32(rowea+20)
                    if m==0 and c==0 and i==0 and l==0 and s==0 and f==0:
                        # terminator
                        if saw_one:
                            # accept block
                            pass
                        break
                    # apply sanity: message recognized, ids monotonic (id<=idLast), handler possibly code
                    if (m in wm_keys) and (i <= max(l, i)) and (f == 0 or _is_code_ptr(f)):
                        entries.append({"msg":m,"code":c,"id":i,"idLast":l,"sig":s,"pfn":f,"ea_array":arr_ea,"index":idx})
                        saw_one = True
                        idx += 1
                        rowea += (PTRSZ*6 if IS_X64 else 24)
                        continue
                    # not looking like AFX row
                    break
                # skip past the block we just considered
                ea = rowea + (PTRSZ*6 if IS_X64 else 24)
                continue
            # no plausible row; advance
            ea += PTRSZ
    return entries

def _ctrl_desc_for_id(cid):
    if cid in CONTROL_INDEX:
        klass = CONTROL_INDEX[cid].get("class")
        title = CONTROL_INDEX[cid].get("title")
        tfrag = f" '{title}'" if title else ""
        return f"[{klass}{tfrag}]"
    return ""

def annotate_mfc_handlers(msg_entries):
    """
    For each decoded message-map entry, annotate the handler function start with a readable mapping.
    """
    count = 0
    for e in msg_entries:
        pfn = e["pfn"]
        if not pfn:
            continue
        f = ida_funcs.get_func(pfn)
        if not f:
            # try to create a func if it looks code-ish
            if _is_code_ptr(pfn):
                ida_funcs.add_func(pfn)
                f = ida_funcs.get_func(pfn)
            if not f:
                continue
        msgname = WM.get(e["msg"], f"WM_{e['msg']:#x}")
        code    = e["code"]
        # Try decoding notify by most common control families
        notify = None
        for fam, tbl in (("BN", BN), ("CBN", CBN), ("LBN", LBN)):
            if code in tbl:
                notify = f"{fam}:{tbl[code]}"
                break
        if notify is None and code != 0:
            notify = f"code={code}"
        lo, hi = e["id"], e["idLast"]
        id_part = f"id={lo}" if lo == hi else f"id={lo}..{hi}"
        # attach control info if range small and entries present
        ctrl_part = ""
        if lo == hi:
            ctrl_part = f" {_ctrl_desc_for_id(lo)}"
        else:
            if (hi - lo) <= 32:
                # small range: mention any known IDs
                known = [f"{i}{_ctrl_desc_for_id(i)}" for i in range(lo, hi+1) if i in CONTROL_INDEX]
                if known:
                    ctrl_part = f" [{', '.join(known)}]"
        text = fmt_cmt(f"MFC: {msgname} {id_part}" + (f" {notify}" if notify else "") + ctrl_part + f"  (map@{e['ea_array']:#x}[{e['index']}])")
        set_cmt(f.start_ea, text, repeatable=False)
        try_decomp_cmt(f.start_ea, text)
        count += 1
    if count:
        log(f"MFC message-map: annotated {count} handler entries")
    return count

# --------- main ----------
def summarize_into_function(func_ea, lines):
    if not lines: return
    head = f"{FUNC_SUMMARY_TAG} {len(lines)} GUI refs:\n"
    body = "\n".join(f"  - {l}" for l in lines[:80])
    idc.set_func_cmt(func_ea, f"{head}{body}", 1)

def run():
    # require parsed .rsrc
    check_rsrc_ready()
    build_control_index()

    # MFC/AFX message map discovery
    msg_entries = parse_mfc_msgmaps()
    annotate_mfc_handlers(msg_entries)

    # ATL Parser
    atl_entries = parse_atl_msgmaps()
    annotate_atl_handlers(atl_entries)

    # IDS_* tagging
    ids_hits = scan_ids_strings()
    if ids_hits:
        log(f"Found {len(ids_hits)} IDS_* strings; tagging xrefs.")
        annotate_ids_xrefs(ids_hits)

    # sweep functions for control-id immediates and GUI API calls
    total_funcs = ida_funcs.get_func_qty()
    processed = 0
    total_annos = 0

    for i in range(total_funcs):
        f = ida_funcs.getn_func(i)
        if not f: continue
        processed += 1
        if processed % 50 == 0:
            log(f"Scanning functions: {processed}/{total_funcs}")

        func_annos = []
        func_annos += annotate_control_id_usage(f.start_ea)

        for call_ea in list_all_calls(f.start_ea):
            name = sanitize_name(get_callee_name(call_ea))
            if "." in name: name = name.split(".")[-1]
            # Afx helpers: annotate too
            if "AfxMessageBox" in name:
                set_cmt(call_ea, fmt_cmt("AfxMessageBox"), False)
                try_decomp_cmt(call_ea, fmt_cmt("AfxMessageBox"))
                func_annos.append(fmt_cmt("AfxMessageBox"))
                total_annos += 1
            # CString LoadString mangled names often contain 'LoadString' and 'CString'
            if "LoadString" in name and "CString" in name:
                set_cmt(call_ea, fmt_cmt("CString::LoadString"), False)
                try_decomp_cmt(call_ea, fmt_cmt("CString::LoadString"))
                func_annos.append(fmt_cmt("CString::LoadString"))
                total_annos += 1

            if name in TARGET_APIS:
                min_argc, _ = TARGET_APIS[name]
                args = recover_args_for_call(call_ea, min_argc)
                line = annotate_call(call_ea, name, args)
                func_annos.append(line)
                total_annos += 1

        summarize_into_function(f.start_ea, func_annos)

    # final roll-call
    touched = sorted(set(ea for ea, _ in COMMENT_LOG))
    log("------------------------------------------------------------")
    log(f"Annotated {len(COMMENT_LOG)} entries at {len(touched)} unique addresses.")
    for ea in touched:
        last = next((t for (e, t) in reversed(COMMENT_LOG) if e == ea), "")
        ida_kernwin.msg(f"{LOG_PREFIX} EA {ea:#x}  :: {last}\n")
    log("------------------------------------------------------------")
    log(f"Done. GUI annotations across {processed} functions. Refresh pseudocode if needed.")

# Optional plugin wrapper
class gui_annotator_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Annotate GUI-related callsites, controls, and MFC message maps"
    help = "Consumes parsed .rsrc and scans AFX_MSGMAP_ENTRY arrays"
    wanted_name = "GUI Annotator (MFC)"
    wanted_hotkey = ""

    def init(self): return idaapi.PLUGIN_KEEP
    def run(self, arg): run()
    def term(self): pass

def PLUGIN_ENTRY(): return gui_annotator_plugin_t()

if __name__ == "__main__":
    run()
