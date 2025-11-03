# mfc_afx_rebuilder_ida92_fast_rtti_mfc.py
# IDA 9.2-only. Efficient MFC/AFX vtable & instance rebuilder with:
#  - Block-scanned vtable discovery + fixup seeding
#  - Chunked Local Types, incremental cache
#  - .rsrc ID linking & operand->offset conversion
#  - MSVC RTTI parsing (names) + MFC CRuntimeClass correlation
#  - Immediate data xrefs per slot (no deferred pass)
#  - Optimized exec-range checks + byte-scan instance discovery
#
# No hard dependency on ida_struct (used opportunistically).
# Optional Hex-Rays gated. Verbose console progress.

from __future__ import annotations
import sys, re, struct, traceback, time, gc, bisect, functools

import idc
import idaapi
import ida_ida

import ida_segment
import ida_funcs
import ida_bytes
import ida_typeinf
import ida_nalt
import ida_fixup
import ida_offset
import ida_search
import ida_netnode
import ida_kernwin
import ida_xref

# Optional helpers
try:
    import idautils
    HAVE_IDAUTILS = True
except Exception:
    HAVE_IDAUTILS = False

# Optional decompiler
try:
    import ida_hexrays
    HAVE_HXR = ida_hexrays.init_hexrays_plugin()
except Exception:
    HAVE_HXR = False

# Optional struct API (don’t require it)
try:
    import ida_struct
    HAVE_IDA_STRUCT = True
except Exception:
    HAVE_IDA_STRUCT = False

# ----------------------- CONFIG -----------------------
PTR_SIZE                = 8 if ida_ida.inf_is_64bit() else 4
ENDIAN_LE               = True  # PE/COFF on Windows
VERBOSE                 = True
MIN_VT_ENTRIES          = 3
MAX_VT_ENTRIES          = 2048
PHASE2_CONFIRM_SLOTS    = 4
DATA_SEG_PREFIXES       = ('.rdata', '.data', '.rodata', '.idata', '.data.rel', '.data.rel.ro')
RSRC_NAME_SUBSTR        = '.rsrc'
MAX_RSRC_ID             = 0xFFFF
AUTO_NAME_VFUNCS        = False
MAKE_CODE_FOR_VFUNCS    = True
CREATE_XREFS            = True
APPLY_OPERAND_OFFSETS   = True
INSTANCE_SUFFIX         = "_inst"
BATCH_APPLY_TYPES       = True
ALLOW_CANCEL            = True
CACHE_NETNODE_NAME      = "$mfc_afx_rebuilder_cache_v5"

# RTTI / MFC
RTTI_ENABLE             = True
RTTI_PREFERS_DEMANGLED  = True
RTTI_STRIP_PREFIX       = True
MFC_ENABLE              = True

# Progress cadence
PRINT_EVERY             = 1000
DECLS_CHARS_PER_CHUNK   = 120_000

# ------------------------------------------------------

def log(*a, _flush=True):
    if VERBOSE:
        print('[afx]', *a)
        if _flush:
            try: sys.stdout.flush()
            except Exception: pass

# ----------------- UI helpers -----------------
class WaitBox:
    def __init__(self, title="Working..."):
        try:
            ida_kernwin.show_wait_box(title + "\n%s")
            self.ok = True
        except Exception:
            self.ok = False
    def update(self, msg):
        if self.ok:
            try: ida_kernwin.replace_wait_box(msg)
            except Exception: pass
        log(msg)
    def close(self):
        if self.ok:
            try: ida_kernwin.hide_wait_box()
            except Exception: pass
    def cancelled(self):
        if not ALLOW_CANCEL:
            return False
        try: return ida_kernwin.user_cancelled()
        except Exception: return False

# ----------------- SEGMENTS -----------------
@functools.lru_cache(maxsize=None)
def seg_name(seg):
    try: return ida_segment.get_segm_name(seg) or ''
    except Exception: return idc.get_segm_name(seg.start_ea) or ''

# ----------------- SEGMENTS -----------------
import functools

# simple dict cache keyed by start EA; avoids hashing segment_t objects
_SEG_NAME_CACHE = {}

def seg_iter():
    n = ida_segment.get_segm_qty()
    for i in range(n):
        s = ida_segment.getnseg(i)
        if s:
            yield s

def seg_name(seg):
    if not seg:
        return ''
    try:
        key = int(seg.start_ea)
    except Exception:
        key = None
    if key is not None:
        nm = _SEG_NAME_CACHE.get(key)
        if nm is not None:
            return nm
    try:
        nm = ida_segment.get_segm_name(seg) or ''
    except Exception:
        nm = idc.get_segm_name(seg.start_ea) or ''
    if key is not None:
        _SEG_NAME_CACHE[key] = nm
    return nm

def is_data_seg(seg):
    if not seg:
        return False
    name = seg_name(seg).lower()
    return any(name.startswith(p) for p in DATA_SEG_PREFIXES)

def is_rsrc_seg(seg):
    if not seg:
        return False
    return RSRC_NAME_SUBSTR in seg_name(seg).lower()

def build_exec_ranges_flat():
    # Build sorted flat boundaries: [lo0, hi0, lo1, hi1, ...]
    pairs = []
    for s in seg_iter():
        if s.perm & ida_segment.SEGPERM_EXEC:
            pairs.append((s.start_ea, s.end_ea))
    pairs.sort()
    flat = []
    for lo, hi in pairs:
        flat.append(lo); flat.append(hi)
    return flat

EXEC_BOUNDS = build_exec_ranges_flat()

def in_exec_ranges(ea):
    # Binary search in flattened [lo,hi) pairs
    i = bisect.bisect_right(EXEC_BOUNDS, ea)
    # odd index means inside a [lo,hi) interval
    return (i & 1) == 1

# ----------------- ANALYSIS -----------------
_ensure_cache = set()
def ensure_code_and_func(ea):
    if not ea or ea == idaapi.BADADDR:
        return False
    if ea in _ensure_cache:
        return True
    if ida_funcs.get_func(ea):
        _ensure_cache.add(ea); return True
    ff = idc.get_full_flags(ea)
    if not idc.is_code(ff):
        if not idc.create_insn(ea):
            return False
    try: idc.add_func(ea)
    except Exception: pass
    ok = ida_funcs.get_func(ea) is not None
    if ok: _ensure_cache.add(ea)
    return ok

# ----------------- MEMORY -------------------
def read_ptr(ea):
    try:
        if PTR_SIZE == 8: return idc.get_qword(ea)
        else: return idc.get_wide_dword(ea)
    except Exception:
        return None

def make_ptr_data(ea):
    ff = idc.get_full_flags(ea)
    if idc.is_data(ff): return
    ft = idc.FF_QWORD if PTR_SIZE == 8 else idc.FF_DWORD
    idc.create_data(ea, ft, PTR_SIZE, idaapi.BADADDR)

# ----------------- FIXUPS -------------------
def iter_fixup_points_in_data():
    for seg in seg_iter():
        if not is_data_seg(seg): continue
        ea = ida_fixup.get_next_fixup_ea(seg.start_ea-1)
        last = None
        while ea != idaapi.BADADDR and ea < seg.end_ea:
            if last is not None and ea <= last:
                ea = last + PTR_SIZE
            fx = ida_fixup.get_fixup(ea)
            if fx is not None:
                yield seg, ea, fx
            last = ea
            ea = ida_fixup.get_next_fixup_ea(ea)

# ----------------- FAST SCAN ----------------
_FMT = "<Q" if (PTR_SIZE == 8 and ENDIAN_LE) else ("<I" if ENDIAN_LE else (">Q" if PTR_SIZE==8 else ">I"))
_unpack_from = struct.unpack_from

def scan_ptr_runs(seg):
    """Cheap prefilter over raw bytes; identify contiguous exec-range pointers."""
    start, end = seg.start_ea, seg.end_ea
    size = end - start
    if size <= 0: return
    b = ida_bytes.get_bytes(start, size) or b""
    mv = memoryview(b)
    step = PTR_SIZE
    i = 0; nbuf = len(mv)
    while i + step <= nbuf:
        val = _unpack_from(_FMT, mv, i)[0]
        if in_exec_ranges(val):
            j = i + step; cnt = 1
            while j + step <= nbuf:
                v2 = _unpack_from(_FMT, mv, j)[0]
                if not in_exec_ranges(v2): break
                cnt += 1; j += step
                if cnt >= MAX_VT_ENTRIES: break
            if cnt >= MIN_VT_ENTRIES:
                yield start + i, cnt
                i = j; continue
        i += step

def count_exec_ptrs(head_ea, seg_end):
    cnt = 0; cur = head_ea
    while cur + PTR_SIZE <= seg_end and cnt < MAX_VT_ENTRIES:
        v = read_ptr(cur)
        if not v or not in_exec_ranges(v): break
        cnt += 1; cur += PTR_SIZE
    return cnt

# ----------------- CONFIRMATION -------------
def confirm_vtable_head(head_ea, max_entries, seg_end):
    n = min(max_entries, MAX_VT_ENTRIES)
    confirm = min(PHASE2_CONFIRM_SLOTS, n)
    ok = 0
    for i in range(confirm):
        p = read_ptr(head_ea + i * PTR_SIZE)
        if p and ensure_code_and_func(p): ok += 1
        else: break
    if ok < max(1, min(2, confirm)): return 0
    tail = count_exec_ptrs(head_ea + ok*PTR_SIZE, seg_end)
    total = max(ok, tail + ok)
    return total if total >= MIN_VT_ENTRIES else 0

# ----------------- CACHING ------------------
def get_cache_node():
    nn = ida_netnode.netnode()
    if not nn.create(CACHE_NETNODE_NAME):
        nn = ida_netnode.netnode(CACHE_NETNODE_NAME)
    return nn

def cache_get_sets():
    nn = get_cache_node()
    vt_done = set()
    s = nn.getblob(0, 'V') or b""
    step = PTR_SIZE
    for i in range(0, len(s), step):
        vt_done.add(struct.unpack_from("<Q" if PTR_SIZE==8 else "<I", s, i)[0])
    return nn, vt_done

def cache_add_vtables(nn, heads):
    if not heads: return
    old = nn.getblob(0, 'V') or b""
    pack = struct.pack
    if PTR_SIZE == 8: add = b"".join(pack("<Q", x) for x in heads)
    else: add = b"".join(pack("<I", x) for x in heads)
    nn.setblob(old + add, 0, 'V')

# ----------------- LOCAL TYPES -------------
@functools.lru_cache(maxsize=1024)
def _parsed_block_hash(text_hash: int) -> bool:
    # Thin memo: if text hash seen, don't re-parse
    return True

def build_vtable_typedef(vt_name: str, entries: int) -> str:
    # small strings; join once
    body = "\n".join(f"    void* fnptr_{i};" for i in range(entries))
    return f"typedef struct {vt_name} {{\n{body}\n}} {vt_name};"

def build_instance_typedef(inst_name: str, vt_typename: str) -> str:
    return f"typedef struct {inst_name} {{ {vt_typename}* vptr; }} {inst_name};"

def _parse_decls_chunked(all_text: str, label: str):
    if not all_text: return
    h = hash(all_text)
    if _parsed_block_hash.cache_info().currsize and _parsed_block_hash(h):
        # already parsed same content before; skip
        return
    flags = getattr(idc, 'PT_SILENT', 0) | getattr(idc, 'PT_REPLACE', 0)
    n = 0
    for i in range(0, len(all_text), DECLS_CHARS_PER_CHUNK):
        chunk = all_text[i:i+DECLS_CHARS_PER_CHUNK]
        rc = idc.parse_decls(chunk, flags)
        n += 1
        log(f"Local Types [{label}] chunk {n}, len={len(chunk)}, rc={rc}")
        if rc < 0:
            preview = chunk.splitlines()[:5]
            log("Type parse error preview:", "\\n".join(preview))
    _parsed_block_hash(h)
    gc.collect()

def push_local_types_once(blocks: list[str], label: str):
    if not blocks: return
    text = "\n\n".join(blocks)
    _parse_decls_chunked(text, label)

def apply_typedef_at(ea: int, typename: str, size: int) -> bool:
    try:
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
        # build as discrete pointers first; struct will replace
        for off in range(0, size, PTR_SIZE):
            make_ptr_data(ea + off)
        ok = bool(idc.SetType(ea, typename))
        if HAVE_IDA_STRUCT:
            try:
                sid = ida_struct.get_struc_id(typename)
                if sid != idaapi.BADADDR:
                    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
                    ok = ida_bytes.create_struct(ea, size, sid) or ok
            except Exception:
                pass
        return ok
    except Exception:
        return False

# ----------------- RSRC INDEX --------------
_RSRC_PATTERNS = [
    (re.compile(r'^(IDD|IDR|IDM|IDS|IDI|IDC|IDB|IDP)_[A-Za-z0-9_]+(?:_(\d+))?$'), None),
    (re.compile(r'^(RT_[A-Z]+)_(\d+)$'), 'rt_group'),
    (re.compile(r'^MAKEINTRESOURCE(?:A|W)?_(\d+)$'), None),
]
def _ids_from_name(name: str):
    out = []
    nm = name or ''
    for pat, _ in _RSRC_PATTERNS:
        m = pat.match(nm)
        if m:
            for g in reversed(m.groups()):
                if g and g.isdigit():
                    out.append(int(g)); break
    if not out:
        m2 = re.search(r'(\d{1,6})$', nm)
        if m2: out.append(int(m2.group(1)))
    return out

def build_rsrc_index():
    id_to_names, id_to_types, have = {}, {}, False
    for seg in seg_iter():
        if not is_rsrc_seg(seg): continue
        have = True
        ea = seg.start_ea
        processed = 0
        while ea < seg.end_ea:
            nm = idc.get_name(ea, idc.GN_VISIBLE)
            if nm:
                ids = _ids_from_name(nm)
                if ids:
                    prefix = nm.split('_', 1)[0] if '_' in nm else ''
                    for rid in ids:
                        id_to_names.setdefault(rid, set()).add(nm)
                        if prefix: id_to_types.setdefault(rid, set()).add(prefix)
            cmt = idc.get_cmt(ea, 1) or ''
            for m in re.finditer(r'(?:ID|RID|ResID)\s*[:=]\s*(\d{1,6})', cmt):
                rid = int(m.group(1))
                id_to_names.setdefault(rid, set()).add(nm or f'rsrc_0x{ea:X}')
            nxt = idc.next_head(ea, seg.end_ea)
            ea = (ea + 1) if (nxt == idaapi.BADADDR or nxt <= ea) else nxt
            processed += 1
            if processed % PRINT_EVERY == 0:
                log(f".rsrc scan @0x{ea:X}")
    return ({k: sorted(v) for k, v in id_to_names.items()},
            {k: sorted(v) for k, v in id_to_types.items()},
            have)

def annotate_rsrc_literals_and_operands(id_to_names, id_to_types):
    literal_comments = 0
    operand_converts = 0
    if not id_to_names: return literal_comments, operand_converts

    # Data literal tagging
    for seg in seg_iter():
        if not is_data_seg(seg): continue
        ea, end = seg.start_ea, seg.end_ea
        processed = 0
        while ea + PTR_SIZE <= end:
            if HAVE_IDAUTILS:
                try:
                    it = idautils.XrefsTo(ea, 0)
                    if next(it, None) is None:
                        ea += PTR_SIZE; processed += 1
                        if processed % PRINT_EVERY == 0:
                            log(f"rsrc data-lits {seg_name(seg)} @0x{ea:X}")
                        continue
                except Exception:
                    pass
            v = read_ptr(ea)
            if v and 0 < v <= MAX_RSRC_ID and v in id_to_names:
                names = id_to_names.get(v, [])
                kinds = id_to_types.get(v, [])
                label = names[0] if names else f'ID_{v}'
                kind  = kinds[0] if kinds else 'RES'
                text  = f'rsrc {kind}: {label} ({v}, 0x{v:X})'
                if idc.get_cmt(ea, 0) != text:
                    idc.set_cmt(ea, text, 0)
                    literal_comments += 1
            ea += PTR_SIZE; processed += 1
            if processed % PRINT_EVERY == 0:
                log(f"rsrc data-lits {seg_name(seg)} @0x{ea:X}")

    # Operand conversions to offsets
    if APPLY_OPERAND_OFFSETS:
        for seg in seg_iter():
            start, end = seg.start_ea, seg.end_ea
            ea = start; processed = 0
            while ea != idaapi.BADADDR and ea < end:
                if idc.is_code(idc.get_full_flags(ea)):
                    for opn in (0, 1):
                        try:
                            val = idc.get_operand_value(ea, opn)
                            if val and 0 < val <= MAX_RSRC_ID and val in id_to_names:
                                ri = ida_offset.refinfo_t()
                                ri.init(ida_offset.REF_OFF32 if PTR_SIZE == 4 else ida_offset.REF_OFF64)
                                ida_offset.op_offset_ex(ea, opn, ri)
                                operand_converts += 1
                        except Exception:
                            pass
                ea = idc.next_head(ea, end)
                processed += 1
                if processed % (PRINT_EVERY * 10) == 0:
                    log(f"rsrc operand-scan {seg_name(seg)} @0x{ea:X}")

    return literal_comments, operand_converts

# ----------------- RTTI (MSVC) -------------
def _rva_to_ea(rva):
    return (idc.get_imagebase() + (rva & 0xFFFFFFFFFFFFFFFF)) if rva else 0

def _read_dword(ea): return idc.get_wide_dword(ea)
def _read_qword(ea): return idc.get_qword(ea)

@functools.lru_cache(maxsize=4096)
def _demangle_cached(name):
    dm = idc.Demangle(name, idc.MNG_NODEFINIT)
    if not dm: return None
    if RTTI_STRIP_PREFIX and (dm.startswith("class ") or dm.startswith("struct ")):
        return dm.split(' ', 1)[1]
    return dm

def _read_cstr(ea, maxlen=512):
    try:
        s = idc.get_strlit_contents(ea, maxlen, idc.STRTYPE_C)
        if s:
            try: return s.decode('utf-8', 'ignore')
            except Exception: return s.decode('latin-1', 'ignore')
    except Exception:
        pass
    return None

def demangle_msvc(name):
    if not name: return None
    if RTTI_PREFERS_DEMANGLED:
        dm = _demangle_cached(name)
        if dm: return dm
    m = re.search(r'\.?\?A[VU]([^@]+)@', name)
    return m.group(1) if m else name

def rtti_from_vtable_head(vt_ea):
    if not RTTI_ENABLE: return None
    try:
        p_col = read_ptr(vt_ea - PTR_SIZE)
        if not p_col or p_col == idaapi.BADADDR: return None
        sig = _read_dword(p_col + 0)
        off = _read_dword(p_col + 4)
        cd  = _read_dword(p_col + 8)
        if PTR_SIZE == 8:
            pTD  = _rva_to_ea(_read_dword(p_col + 12))
            pCHD = _rva_to_ea(_read_dword(p_col + 16))
        else:
            pTD  = _read_dword(p_col + 12)
            pCHD = _read_dword(p_col + 16)
        if not pTD or pTD == idaapi.BADADDR: return None
        name_ea = pTD + (16 if PTR_SIZE == 8 else 8)
        rawname = _read_cstr(name_ea, 1024)
        if not rawname: return None
        cls = demangle_msvc(rawname)
        num_bases = None
        if pCHD and pCHD != idaapi.BADADDR:
            try: num_bases = _read_dword(pCHD + 8)
            except Exception: pass
        return {
            'col': p_col, 'signature': sig, 'offset': off, 'cdOffset': cd,
            'td': pTD, 'chd': pCHD, 'classname': cls, 'rawname': rawname,
            'num_bases': num_bases
        }
    except Exception:
        return None

# --------- MFC CRuntimeClass indexer -------
def is_probable_ascii(ea, maxlen=128):
    s = _read_cstr(ea, maxlen)
    if not s: return False, None
    return (1 <= len(s) <= maxlen and re.match(r'^[ -~]+$', s)) , s

def mfc_index_cruntimeclasses():
    if not MFC_ENABLE: return {}, {}
    classes = {}
    name_lut = {}
    for seg in seg_iter():
        if not is_data_seg(seg): continue
        ea, end = seg.start_ea, seg.end_ea
        processed = 0
        while ea + (PTR_SIZE * 5) <= end:
            nameptr = read_ptr(ea + 0)
            ok, s = is_probable_ascii(nameptr)
            if not ok:
                ea += PTR_SIZE; processed += 1
                if processed % (PRINT_EVERY * 4) == 0: log(f"MFC scan {seg_name(seg)} @0x{ea:X}")
                continue
            objsz  = _read_dword(ea + (4 if PTR_SIZE == 4 else 8))
            if not objsz or objsz > 10_000_000:
                ea += PTR_SIZE; processed += 1; continue
            create = read_ptr(ea + (12 if PTR_SIZE == 4 else 16))
            base   = read_ptr(ea + (16 if PTR_SIZE == 4 else 24))
            if base:
                segb = ida_segment.getseg(base)
                if not segb or not is_data_seg(segb):
                    ea += PTR_SIZE; processed += 1; continue
            cname = s.strip()
            if cname not in classes:
                classes[cname] = {'ea': ea, 'nameptr': nameptr, 'objsz': objsz, 'create': create, 'base': base}
                name_lut[cname.lower()] = cname
            ea += PTR_SIZE * 5; processed += 5
            if processed % (PRINT_EVERY * 4) == 0: log(f"MFC scan {seg_name(seg)} @0x{ea:X}")
    return classes, name_lut

def correlate_rtti_mfc(rtti_name, name_lut, classes):
    if not rtti_name or not name_lut: return None
    key = rtti_name.lower()
    cname = name_lut.get(key)
    if cname: return classes.get(cname)
    cand = rtti_name.replace("::","_").replace(" ","").lower()
    for _, lcanon in list(name_lut.items()):
        if lcanon.replace("::","_").replace(" ","").lower() == cand:
            return classes.get(lcanon)
    return None

# -------------- INSTANCES ----------------
def _pack_ptr_le(val):
    return (struct.pack("<Q", val) if PTR_SIZE==8 else struct.pack("<I", val))

def _find_all_occurrences(buf: memoryview, needle: bytes):
    # Simple sliding find; Python's find handles Boyer–Moore-ish internally
    start = 0
    while True:
        pos = buf.tobytes().find(needle, start)  # memoryview.find not in 3.9
        if pos == -1: break
        yield pos
        start = pos + 1

def find_instances_pointing_to(vt_ea):
    # Fast path: byte search each data segment for the vtable pointer pattern
    needle = _pack_ptr_le(vt_ea)
    sites = set()
    for seg in seg_iter():
        if not is_data_seg(seg): continue
        base, end = seg.start_ea, seg.end_ea
        size = end - base
        if size <= 0: continue
        b = ida_bytes.get_bytes(base, size) or b""
        mv = memoryview(b)
        for pos in _find_all_occurrences(mv, needle):
            ea = base + pos
            # verify exact pointer read
            if read_ptr(ea) == vt_ea:
                sites.add(ea)
    # Fallback xrefs if available (may catch reloc-based refs not present as raw bytes)
    if HAVE_IDAUTILS:
        try:
            for x in idautils.XrefsTo(vt_ea, 0):
                if x.frm is not None:
                    sites.add(x.frm)
        except Exception:
            pass
    return sorted(sites)

# -------------- HEX-RAYS NAMING -----------
def maybe_name_virtuals_from_calls(vt_ea, entries, clsname=None):
    if not HAVE_HXR: return 0
    renamed = 0
    prefix = f'{clsname}::' if clsname else f'vt_{vt_ea:X}_'
    cap = min(entries, 64)
    for i in range(cap):
        fptr = read_ptr(vt_ea + i * PTR_SIZE)
        if not fptr or idc.get_name(fptr): continue
        try:
            cfunc = ida_hexrays.decompile(fptr)
            if cfunc and cfunc.entry_ea == fptr:
                idc.set_name(fptr, f'{prefix}fn{i}', idc.SN_NOWARN)
                renamed += 1
        except Exception:
            pass
    return renamed

# -------------- VTABLE APPLY ------------
def _set_name_if_missing(ea, new):
    old = idc.get_name(ea)
    if old == new or (old and old != ""): return
    idc.set_name(ea, new, idc.SN_NOWARN)

def _set_cmt_if_diff(ea, text, rpt=0):
    if idc.get_cmt(ea, rpt) != text:
        idc.set_cmt(ea, text, rpt)

def apply_vtable(ea, entries):
    """
    Create per-slot pointer items and add data xrefs immediately.
    Convert to struct AFTER xrefs, to preserve valid 'from' heads.
    """
    vt_typename = f'vtable_0x{ea:X}'
    _set_name_if_missing(ea, vt_typename)
    for i in range(entries):
        slot = ea + i * PTR_SIZE
        make_ptr_data(slot)
        tgt = read_ptr(slot)
        if tgt:
            if MAKE_CODE_FOR_VFUNCS and i < PHASE2_CONFIRM_SLOTS:
                ensure_code_and_func(tgt)
            if CREATE_XREFS:
                try: ida_xref.add_dref(slot, tgt, ida_xref.dr_O)
                except Exception: pass
    size = entries * PTR_SIZE
    return vt_typename, size

# ------------------- MAIN -----------------
def run():
    t0 = time.time()
    wb = WaitBox("MFC/AFX Rebuilder…")
    try:
        wb.update("Indexing .rsrc…")
        id_to_names, id_to_types, have_rsrc = build_rsrc_index()
        log(f"Resource IDs indexed: {len(id_to_names)}")

        wb.update("Indexing MFC CRuntimeClass…")
        mfc_map, mfc_lut = mfc_index_cruntimeclasses() if MFC_ENABLE else ({}, {})
        log(f"MFC CRuntimeClass entries: {len(mfc_map)}")

        wb.update("Scanning data segments…")
        candidates = []
        for seg in seg_iter():
            if wb.cancelled(): print("Cancelled."); return
            if not is_data_seg(seg): continue
            c_local = 0
            for head, cnt in scan_ptr_runs(seg):
                candidates.append((seg, head, cnt))
                c_local += 1
                if c_local % PRINT_EVERY == 0:
                    log(f"Scan {seg_name(seg)}: {c_local} runs…")

        # Fixup seeds
        fix_ct = 0
        for seg, fea, fx in iter_fixup_points_in_data():
            tgt = read_ptr(fea)
            if tgt and in_exec_ranges(tgt):
                head = fea
                while head - PTR_SIZE >= seg.start_ea:
                    pv = read_ptr(head - PTR_SIZE)
                    if not pv or not in_exec_ranges(pv): break
                    head -= PTR_SIZE
                span = count_exec_ptrs(head, seg.end_ea)
                if span >= MIN_VT_ENTRIES:
                    candidates.append((seg, head, span))
                    fix_ct += 1
                    if fix_ct % PRINT_EVERY == 0:
                        log(f"Fixup seeds: {fix_ct}")
        log(f"Prefilter raw candidates: {len(candidates)}")
        gc.collect()

        # Dedup heads (keep max span)
        heads = {}
        for seg, head, cnt in candidates:
            if cnt > heads.get(head, 0):
                heads[head] = cnt
        pref = sorted(heads.items(), key=lambda x: x[0])
        log("Prefilter unique:", len(pref))

        nn, vt_done = cache_get_sets()
        todo = [(h, n) for h, n in pref if h not in vt_done]
        log("New candidates:", len(todo))
        print(f"[afx] Phase B confirm: {len(todo)} heads")

        # Confirm
        confirmed = []
        for idx, (head, cnt) in enumerate(todo, 1):
            if wb.cancelled(): print("Cancelled."); return
            seg = ida_segment.getseg(head)
            if not seg: continue
            real = confirm_vtable_head(head, cnt, seg.end_ea)
            if real >= MIN_VT_ENTRIES:
                confirmed.append((head, real))
            if idx % PRINT_EVERY == 0:
                log(f"Confirmed {len(confirmed)}/{idx}…")
        log("Confirmed vtables:", len(confirmed))
        wb.update(f"Confirmed {len(confirmed)} vtables…")
        gc.collect()

        # RTTI
        rtti_info = {}
        if RTTI_ENABLE:
            wb.update("Reading RTTI…")
            for i, (head, n) in enumerate(confirmed, 1):
                info = rtti_from_vtable_head(head)
                if info and info.get('classname'):
                    rtti_info[head] = info
                if i % (PRINT_EVERY // 2 or 1) == 0:
                    log(f"RTTI {i}/{len(confirmed)}")
        log(f"RTTI named: {len(rtti_info)}")

        # Build typedefs (use RTTI names when present)
        vt_typedefs, inst_typedefs = [], []
        vt_display_names = {}
        for head, n in confirmed:
            clsname = rtti_info.get(head, {}).get('classname')
            if clsname:
                cname = re.sub(r'[^A-Za-z0-9_]', '_', clsname)
                vt_name = f'vtbl_{cname}'
            else:
                vt_name = f'vtable_0x{head:X}'
            vt_display_names[head] = vt_name
            vt_typedefs.append(build_vtable_typedef(vt_name, n))
            inst_typedefs.append(build_instance_typedef(vt_name + INSTANCE_SUFFIX, vt_name))

        if BATCH_APPLY_TYPES:
            wb.update("Pushing Local Types (vtables)…")
            push_local_types_once(vt_typedefs, "vtables")
            wb.update("Pushing Local Types (instances)…")
            push_local_types_once(inst_typedefs, "instances")
        gc.collect()

        # Apply vtables, then convert to struct
        applied_vt_heads = []
        vt_info = []   # (head, vt_typename, entries, clsname)
        for i, (head, n) in enumerate(confirmed, 1):
            vt_typename = vt_display_names.get(head, f'vtable_0x{head:X}')
            _set_name_if_missing(head, vt_typename)

            # 1) per-slot pointer items and immediate drefs
            _, size = apply_vtable(head, n)

            # 2) convert entire run to a struct
            apply_typedef_at(head, vt_typename, size)

            clsname = rtti_info.get(head, {}).get('classname')
            mfc = correlate_rtti_mfc(clsname, mfc_lut, mfc_map) if clsname else None
            if mfc:
                _set_cmt_if_diff(head, f'RTTI={clsname}, MFC=CRuntimeClass@0x{mfc["ea"]:X}', 1)
            elif clsname:
                _set_cmt_if_diff(head, f'RTTI={clsname}', 1)
            vt_info.append((head, vt_typename, n, clsname))
            applied_vt_heads.append(head)
            if i % (PRINT_EVERY // 2 or 1) == 0:
                log(f"Applied vtables {i}/{len(confirmed)}")
        gc.collect()

        # Instances (byte-scan + verify)
        wb.update("Initializing instances…")
        total_instances = 0
        total_inst_typed = 0
        for i, (head, vt_typename, _n, clsname) in enumerate(vt_info, 1):
            sites = find_instances_pointing_to(head)
            total_instances += len(sites)
            inst_typename = vt_typename + INSTANCE_SUFFIX
            for j, addr in enumerate(sites, 1):
                ida_bytes.del_items(addr, ida_bytes.DELIT_SIMPLE, PTR_SIZE)
                make_ptr_data(addr)
                ok = bool(idc.SetType(addr, inst_typename))
                if HAVE_IDA_STRUCT:
                    try:
                        sid = ida_struct.get_struc_id(inst_typename)
                        if sid != idaapi.BADADDR:
                            ida_bytes.del_items(addr, ida_bytes.DELIT_SIMPLE, PTR_SIZE)
                            ok = ida_bytes.create_struct(addr, PTR_SIZE, sid) or ok
                    except Exception:
                        pass
                cmt = f'vptr -> {vt_typename} (0x{head:X})'
                if clsname: cmt += f'  class {clsname}'
                if not idc.get_cmt(addr, 0): idc.set_cmt(addr, cmt, 0)
                if not idc.get_name(addr): idc.set_name(addr, f'obj_0x{addr:X}', idc.SN_NOWARN)
                if ok: total_inst_typed += 1
                if j % (PRINT_EVERY * 2) == 0:
                    log(f"Instances for 0x{head:X}: {j}/{len(sites)}")
            if i % (PRINT_EVERY // 2 or 1) == 0:
                log(f"Instance pass {i}/{len(vt_info)}")
        gc.collect()

        # Hex-Rays optional pass
        wb.update("Optional Hex-Rays hints…")
        total_renamed = 0
        if HAVE_HXR:
            for i, (head, n) in enumerate(confirmed, 1):
                clsname = rtti_info.get(head, {}).get('classname')
                total_renamed += maybe_name_virtuals_from_calls(head, n, clsname)
                if i % (PRINT_EVERY // 2 or 1) == 0:
                    log(f"Hex-Rays hints {i}/{len(confirmed)}")

        # Resource annotations
        wb.update("Annotating resources…")
        lit_comments, op_offsets = (0, 0)
        if have_rsrc:
            lit_comments, op_offsets = annotate_rsrc_literals_and_operands(id_to_names, id_to_types)
        gc.collect()

        # Cache
        cache_add_vtables(nn, applied_vt_heads)

        # Summary
        t1 = time.time()
        print('--- MFC/AFX Rebuilder (IDA 9.2, fast + RTTI + MFC) ---')
        print(f'Runtime:                  {t1 - t0:.2f}s')
        print(f'Exec segments:            {len(EXEC_BOUNDS)//2}')
        print(f'Prefilter candidates:     {len(pref)}')
        print(f'Confirmed vtables:        {len(confirmed)}')
        print(f'Vtables newly applied:    {len(applied_vt_heads)}')
        print(f'Instances found:          {total_instances}')
        print(f'Instances typed:          {total_inst_typed}')
        if have_rsrc:
            print(f'Resource comments added:  {lit_comments}')
            print(f'Operand->offset converts: {op_offsets}')
        if RTTI_ENABLE:
            print(f'Vtables with RTTI names:  {len(rtti_info)}')
        if MFC_ENABLE:
            print(f'CRuntimeClass entries:    {len(mfc_map)}  (name LUT {len(mfc_lut)})')
        if HAVE_HXR:
            print(f'Hex-Rays vfunc renames:   {total_renamed}')
        print('Done.')

    finally:
        wb.close()

if __name__ == "__main__":
    try:
        run()
    except Exception:
        traceback.print_exc()
