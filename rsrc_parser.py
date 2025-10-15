# rsrc_full_parser_ida92_nostructs.py
# Zero dependency on IDA struct APIs. Writes fields directly. Compatible with weird IDA 9.x Python.

import idaapi, idc, idautils
import ida_bytes, ida_segment, ida_kernwin, ida_nalt

LOG = True
SAFE_PREVIEW = 80
MAKE_COMMENTS = True
MAKE_NAMES = True

def log(msg):
    if LOG: ida_kernwin.msg(str(msg) + "\n")

# ---------- basics ----------
def align2(ea):
    return (ea + 1) & ~1

def make_utf16_fixed(ea, wchar_count):
    bl = max(0, int(wchar_count) * 2)
    if bl:
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, bl)
        ida_bytes.create_strlit(ea, bl, ida_nalt.STRTYPE_C_16)
        ida_nalt.set_str_type(ea, ida_nalt.STRTYPE_C_16)
    return ea + bl

def make_pad(ea, up_to):
    if up_to > ea:
        make_bytes(ea, up_to - ea, "pad")
    return up_to


def image_base():
    try:
        return idaapi.get_imagebase()
    except Exception:
        return ida_nalt.get_imagebase()

def rsrc_seg_bounds():
    for s in idautils.Segments():
        seg = ida_segment.getseg(s)
        if ida_segment.get_segm_name(seg).lower() == ".rsrc":
            return seg.start_ea, seg.end_ea
    return None, None

def rva_to_ea(rva): return image_base() + (rva & 0xFFFFFFFF)

def set_cmt(ea, text):
    if MAKE_COMMENTS:
        ida_bytes.set_cmt(ea, text, False)

def ascii_name(s, fallback="res"):
    try:
        s = (s or "").encode("ascii", "ignore").decode("ascii")
    except Exception:
        s = ""
    out, last = [], False
    for ch in s:
        if ch.isalnum():
            out.append(ch); last = False
        else:
            if not last:
                out.append('_'); last = True
    nm = "".join(out).strip('_') or fallback
    if nm and nm[0].isdigit(): nm = "r_" + nm
    return nm[:40]

def set_name_safe(ea, base):
    if not MAKE_NAMES: return
    nm = f"{base}_{ea:08X}"
    try:
        idc.set_name(ea, nm, idc.SN_CHECK)
    except Exception:
        pass

def read_u16(ea):
    b = ida_bytes.get_bytes(ea, 2)
    return None if not b else int.from_bytes(b, "little", signed=False)

def read_u32(ea):
    b = ida_bytes.get_bytes(ea, 4)
    return None if not b else int.from_bytes(b, "little", signed=False)

def align4(ea): return (ea + 3) & ~3

def make_word(ea, cmt=None):
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 2)
    ida_bytes.create_data(ea, ida_bytes.FF_WORD, 2, idaapi.BADNODE)
    if cmt: set_cmt(ea, cmt)

def make_dword(ea, cmt=None):
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 4)
    ida_bytes.create_data(ea, ida_bytes.FF_DWORD, 4, idaapi.BADNODE)
    if cmt: set_cmt(ea, cmt)

def make_bytes(ea, size, cmt=None):
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
    ida_bytes.create_data(ea, ida_bytes.FF_BYTE, size, idaapi.BADNODE)
    if cmt: set_cmt(ea, cmt)

def make_utf16z(ea, max_chars=0x400):
    cur, n = ea, 0
    while n < max_chars:
        w = read_u16(cur)
        if w is None: break
        cur += 2
        if w == 0: break
        n += 1
    bytelen = (n + 1) * 2 if n else 2
    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, bytelen)
    ida_bytes.create_strlit(ea, bytelen, ida_nalt.STRTYPE_C_16)
    ida_nalt.set_str_type(ea, ida_nalt.STRTYPE_C_16)
    return ea + bytelen

def get_utf16z_text(ea, max_chars=0x400):
    cur, out, n = ea, [], 0
    while n < max_chars:
        w = read_u16(cur)
        if w is None: break
        cur += 2
        if w == 0: break
        out.append(chr(w) if (0x20 <= w <= 0x7E) or (0xA0 <= w <= 0xFF) else '?')
        n += 1
    return "".join(out)

# ---------- “struct” writers (manual) ----------
def write_IMAGE_RESOURCE_DIRECTORY(ea):
    # DWORD Characteristics, TimeDateStamp; WORD Major, Minor, Named, Id
    make_dword(ea + 0, "Characteristics")
    make_dword(ea + 4, "TimeDateStamp")
    make_word(ea + 8, "MajorVersion")
    make_word(ea + 10, "MinorVersion")
    make_word(ea + 12, "NumberOfNamedEntries")
    make_word(ea + 14, "NumberOfIdEntries")
    return 16

def write_IMAGE_RESOURCE_DIRECTORY_ENTRY(ea):
    make_dword(ea + 0, "NameOrId")
    make_dword(ea + 4, "OffsetToData")
    return 8

def write_IMAGE_RESOURCE_DATA_ENTRY(ea):
    make_dword(ea + 0, "OffsetToData")
    make_dword(ea + 4, "Size")
    make_dword(ea + 8, "CodePage")
    make_dword(ea + 12, "Reserved")
    return 16

# ---------- resource tree ----------
RT_TYPES = {
    1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING",
    7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE",
    12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 17: "DLGINIT",
    23: "HTML", 24: "MANIFEST",
}

def parse_resource_dir(node_ea, path):
    write_IMAGE_RESOURCE_DIRECTORY(node_ea)
    n_named  = read_u16(node_ea + 12) or 0
    n_id     = read_u16(node_ea + 14) or 0
    total    = n_named + n_id
    set_cmt(node_ea, f"[RES_DIR] named={n_named} id={n_id}")
    ent_ea = node_ea + 16
    rstart, rend = rsrc_seg_bounds()

    for _ in range(total):
        write_IMAGE_RESOURCE_DIRECTORY_ENTRY(ent_ea)
        name_or_id = read_u32(ent_ea)
        off_to_data = read_u32(ent_ea + 4)
        is_dir = (off_to_data & 0x80000000) != 0
        child_off = off_to_data & 0x7FFFFFFF
        child_ea = (rstart + child_off) if rstart else None

        label = None
        if name_or_id & 0x80000000:
            # Named entry: first WORD is char count, UTF-16 string follows
            name_off = name_or_id & 0x7FFFFFFF
            name_ea = rstart + name_off
            strlen = read_u16(name_ea) or 0
            make_word(name_ea, "NameLength")
            str_ea = name_ea + 2
            ida_bytes.del_items(str_ea, ida_bytes.DELIT_SIMPLE, strlen*2)
            ida_bytes.create_strlit(str_ea, strlen*2, ida_nalt.STRTYPE_C_16)
            ida_nalt.set_str_type(str_ea, ida_nalt.STRTYPE_C_16)
            raw = ida_bytes.get_strlit_contents(str_ea, strlen*2, ida_nalt.STRTYPE_C_16) or b""
            try: nm = raw.decode("utf-16le", errors="ignore")
            except Exception: nm = ""
            label = ascii_name(nm, "res")
            set_cmt(ent_ea, f"[ENTRY] name=\"{nm}\" -> {'DIR' if is_dir else 'DATA'}")
        else:
            rid = name_or_id & 0xFFFF
            label = RT_TYPES.get(rid, f"TYPE_{rid}")
            set_cmt(ent_ea, f"[ENTRY] id={rid} ({label}) -> {'DIR' if is_dir else 'DATA'}")

        if child_ea and rstart <= child_ea < rend:
            if is_dir:
                set_name_safe(child_ea, f"resdir_{ascii_name(label)}")
                parse_resource_dir(child_ea, path + [label])
            else:
                parse_resource_data_entry(child_ea, path + [label])
        ent_ea += 8

def parse_resource_data_entry(ea, path):
    write_IMAGE_RESOURCE_DATA_ENTRY(ea)
    data_rva = read_u32(ea) or 0
    size     = read_u32(ea + 4) or 0
    codepage = read_u32(ea + 8) or 0
    tgt_ea   = rva_to_ea(data_rva)
    set_cmt(ea, f"[DATA] rva=0x{data_rva:X} size={size} cp={codepage}")
    set_name_safe(ea, f"resdata_{ascii_name('_'.join(path))}")

    top = path[0] if path else "unknown"
    try:
        if top == "STRING":
            parse_rt_string(tgt_ea, size)
        elif top == "DIALOG":
            parse_rt_dialog(tgt_ea, size)
        elif top == "MENU":
            parse_rt_menu(tgt_ea, size)
        elif top == "ACCELERATOR":
            parse_rt_accel(tgt_ea, size)
        elif top == "VERSION":
            parse_rt_version(tgt_ea, size)
        elif top == "DLGINIT":
            parse_rt_dlgin(tgt_ea, size)
        elif top in ("GROUP_ICON", "GROUP_CURSOR"):
            parse_rt_group_icon_cursor(tgt_ea, size, top)
        elif top in ("ICON", "CURSOR"):
            make_bytes(tgt_ea, size, f"[{top}] raw image data, {size} bytes")
            set_name_safe(tgt_ea, f"{top.lower()}")
        elif top in ("MANIFEST","HTML","RCDATA"):
            parse_textish_or_bytes(tgt_ea, size, top)
        else:
            make_bytes(tgt_ea, size, f"[{top}] {size} bytes")
    except Exception as ex:
        make_bytes(tgt_ea, size, f"[{top}] parse error: {ex}")

# ---------- type parsers ----------
def parse_rt_string(ea, size):
    end, cur = ea + size, ea
    for i in range(16):
        if cur + 2 > end: break
        length = read_u16(cur) or 0
        make_word(cur, "len"); cur += 2
        if length:
            bl = length * 2
            ida_bytes.del_items(cur, ida_bytes.DELIT_SIMPLE, bl)
            ida_bytes.create_strlit(cur, bl, ida_nalt.STRTYPE_C_16)
            ida_nalt.set_str_type(cur, ida_nalt.STRTYPE_C_16)
            txt = ida_bytes.get_strlit_contents(cur, bl, ida_nalt.STRTYPE_C_16) or b""
            try: s = txt.decode("utf-16le", errors="ignore")
            except Exception: s = ""
            set_cmt(cur, f"[STRING#{i}] \"{s[:SAFE_PREVIEW]}\"")
            cur += bl
        else:
            set_cmt(cur, f"[STRING#{i}] <empty>")
    set_name_safe(ea, "rt_string_tbl")

def _ord_or_wstr(cur, end):
    w = read_u16(cur)
    if w == 0xFFFF:
        make_word(cur, "0xFFFF"); make_word(cur+2, "ordinal")
        return cur + 4, ('ord', read_u16(cur+2))
    nxt = make_utf16z(cur); s = get_utf16z_text(cur)
    set_cmt(cur, f"\"{s[:SAFE_PREVIEW]}\"")
    return nxt, ('str', s)

def _class_ord_name(ordv):
    return {0x80:"BUTTON",0x81:"EDIT",0x82:"STATIC",0x83:"LISTBOX",0x84:"SCROLLBAR",0x85:"COMBOBOX"}.get(ordv, f"ORD_{ordv:04X}")

def parse_rt_dialog(ea, size):
    """Detect classic vs EX and route."""
    ver = read_u16(ea)
    sig = read_u16(ea + 2)
    # DIALOGEX: dlgVer==1 and signature==0xFFFF
    if ver == 1 and sig == 0xFFFF:
        parse_dlgtpl_ex(ea, ea + size)
    else:
        parse_dlgtpl_classic(ea, ea + size)
def parse_dlgtpl_ex(ea, end):
    """
    DIALOGEX layout (per MSDN):
      WORD  dlgVer
      WORD  signature (0xFFFF)
      DWORD helpID
      DWORD exStyle
      DWORD style
      WORD  cDlgItems
      SHORT x, y, cx, cy
      [if DS_SETFONT]
        WORD pointsize
        WORD weight
        BYTE italic
        BYTE charset
        WCHAR typeface[]  ; NUL-terminated
      then cDlgItems of:
        DWORD helpID
        DWORD exStyle
        DWORD style
        SHORT x, y, cx, cy
        DWORD id
        class (0xFFFF,ord) | UTF16Z
        title (0xFFFF,ord) | UTF16Z
        WORD extraCount
        BYTE extra[extraCount]
      Each item ends on a DWORD boundary.
    """
    # Fixed header (26 bytes)
    make_word(ea + 0,  "dlgVer")
    make_word(ea + 2,  "signature")
    make_dword(ea + 4, "helpID")
    make_dword(ea + 8, "exStyle")
    make_dword(ea + 12,"style")
    make_word(ea + 16, "cDlgItems")
    make_word(ea + 18, "x")
    make_word(ea + 20, "y")
    make_word(ea + 22, "cx")
    make_word(ea + 24, "cy")

    cItems = read_u16(ea + 16) or 0
    style  = read_u32(ea + 12) or 0
    cur    = ea + 26

    # Dialog-level menu, class, title
    cur, _        = _ord_or_wstr(cur, end)              # menu
    cur, _        = _ord_or_wstr(cur, end)              # class
    cur, (tk,tv)  = _ord_or_wstr(cur, end)              # title

    # Optional font block (EX has pointsize, weight, italic, charset)
    DS_SETFONT = 0x00000040
    if style & DS_SETFONT:
        make_word(cur, "pointsize"); cur += 2
        if cur + 4 <= end:
            make_word(cur, "weight"); cur += 2
            ida_bytes.del_items(cur, ida_bytes.DELIT_SIMPLE, 1); ida_bytes.create_data(cur, ida_bytes.FF_BYTE, 1, idaapi.BADNODE); set_cmt(cur, "italic");  cur += 1
            ida_bytes.del_items(cur, ida_bytes.DELIT_SIMPLE, 1); ida_bytes.create_data(cur, ida_bytes.FF_BYTE, 1, idaapi.BADNODE); set_cmt(cur, "charset"); cur += 1
        cur = make_utf16z(cur)  # typeface
    # Align to DWORD before first item, and type the pad so the listing is clean
    pad_to = align4(cur)
    if pad_to > cur: make_pad(cur, pad_to)
    cur = pad_to

    dlg_title = tv if tk == 'str' else f"ORD_{tv:04X}"
    set_name_safe(ea, f"dlgex_{ascii_name(dlg_title)}")

    # Items
    for i in range(cItems):
        if cur + 24 > end:
            set_cmt(cur, f"[ITEMEX] truncated before header #{i}")
            break

        base = cur
        make_dword(base + 0,  "helpID")
        make_dword(base + 4,  "exStyle")
        make_dword(base + 8,  "style")
        make_word(base + 12, "x")
        make_word(base + 14, "y")
        make_word(base + 16, "cx")
        make_word(base + 18, "cy")
        make_dword(base + 20, "id")                      # DWORD id (EX)
        cur = base + 24

        # class, title
        cur, (ck, cv) = _ord_or_wstr(cur, end)
        class_desc = cv if ck == 'str' else _class_ord_name(cv)

        cur, (tk2, tv2) = _ord_or_wstr(cur, end)
        title_desc = tv2 if tk2 == 'str' else f"ORD_{tv2:04X}"

        # extra
        if cur + 2 > end:
            set_cmt(base, f"[ITEMEX] missing extraCount; id=0x{(read_u32(base+20) or 0):08X}")
            break
        make_word(cur, "extraCount")
        extra = read_u16(cur) or 0
        cur += 2

        remaining = max(0, end - cur)
        if extra > remaining:
            set_cmt(cur, f"[WARN] extraCount={extra} > remaining={remaining}; clamped")
            extra = remaining
        if extra:
            make_bytes(cur, extra, f"extra[{extra}]"); cur += extra

        # Type and apply DWORD padding between items
        pad_to = align4(cur)
        if pad_to > cur: make_pad(cur, pad_to)
        cur = pad_to

        set_cmt(base, f"[ITEMEX] id=0x{(read_u32(base+20) or 0):08X} class={class_desc} title={title_desc}")
        set_name_safe(base, f"dlgex_item_{i:03d}_{ascii_name(class_desc)}")
def parse_dlgtpl_classic(ea, end):
    """
    Classic DLGTEMPLATE:
      DWORD style
      DWORD exStyle
      WORD  cDlgItems
      SHORT x, y, cx, cy
      [if DS_SETFONT] WORD pointsize; WCHAR typeface[]
      Items:
        DWORD style
        DWORD exStyle
        SHORT x, y, cx, cy
        WORD  id
        class (0xFFFF,ord | UTF16Z)
        title (0xFFFF,ord | UTF16Z)
        WORD  extraCount
        BYTE  extra[extraCount]
      Each item ends DWORD-aligned.
    """
    make_dword(ea + 0,  "style")
    make_dword(ea + 4,  "exStyle")
    make_word(ea + 8,  "cDlgItems")
    make_word(ea + 10, "x")
    make_word(ea + 12, "y")
    make_word(ea + 14, "cx")
    make_word(ea + 16, "cy")

    cItems = read_u16(ea + 8) or 0
    style  = read_u32(ea + 0) or 0
    cur = ea + 18

    # menu, class, title
    cur, _       = _ord_or_wstr(cur, end)
    cur, _       = _ord_or_wstr(cur, end)
    cur, (tk,tv) = _ord_or_wstr(cur, end)

    DS_SETFONT = 0x00000040
    if style & DS_SETFONT:
        if cur + 2 <= end:
            make_word(cur, "pointsize"); cur += 2
        cur = make_utf16z(cur)  # typeface
    # Classic doesn’t mandate an align here, but many blobs are already dword-aligned.
    # If there is slack, type it so the listing stays tidy.
    pad_to = align4(cur)
    if pad_to > cur: make_pad(cur, pad_to)
    cur = pad_to

    set_name_safe(ea, f"dlg_{ascii_name(tv if tk == 'str' else 'ord')}")

    for i in range(cItems):
        if cur + 18 > end:
            set_cmt(cur, f"[ITEM] truncated before header #{i}")
            break

        base = cur
        make_dword(base + 0,  "style")
        make_dword(base + 4,  "exStyle")
        make_word(base + 8,  "x")
        make_word(base + 10, "y")
        make_word(base + 12, "cx")
        make_word(base + 14, "cy")
        make_word(base + 16, "id")                         # WORD id (classic)
        cur = base + 18

        # Heuristic fix: some classic resources put an extra WORD (0x0000 or 0x0001)
        # right before the ordinal class. If we see [0000|0001], FFFF, 0080..0085,
        # treat the first word as padding and start class at FFFF.
        if cur + 6 <= end:
            w0 = read_u16(cur)
            w1 = read_u16(cur + 2)
            w2 = read_u16(cur + 4)
            if w0 in (0x0000, 0x0001) and w1 == 0xFFFF and 0x0080 <= w2 <= 0x0085:
                make_word(cur, "pad/align")
                cur += 2

        cur, _ = _ord_or_wstr(cur, end)                    # class
        cur, _ = _ord_or_wstr(cur, end)                    # title

        if cur + 2 > end:
            set_cmt(base, f"[ITEM] missing extraCount; id=0x{(read_u16(base+16) or 0):04X}")
            break

        make_word(cur, "extraCount")
        extra = read_u16(cur) or 0
        cur += 2

        remaining = max(0, end - cur)
        if extra > remaining:
            set_cmt(cur, f"[WARN] extraCount={extra} > remaining={remaining}; clamped")
            extra = remaining

        if extra:
            make_bytes(cur, extra, f"extra[{extra}]")
            cur += extra

        # Type and apply DWORD padding between items
        pad_to = align4(cur)
        if pad_to > cur: make_pad(cur, pad_to)
        cur = pad_to

def parse_rt_menu(ea, size):
    end = ea + size
    ver = read_u16(ea); hdrsz = read_u16(ea+2)
    if ver == 0 and hdrsz == 0:
        # classic MENU header
        make_word(ea+0, "wVersion"); make_word(ea+2, "wOffset")
        set_cmt(ea, "[MENU] classic header")
        cur, idx = ea + 4, 0
        while cur + 2 <= end:
            flags = read_u16(cur); make_word(cur, "flags"); cur += 2
            if flags is None: break
            MF_POPUP = 0x0010
            if (flags & MF_POPUP) == 0:
                make_word(cur, "id"); cur += 2
            cur = make_utf16z(cur)
            set_cmt(cur, f"[MENUITEM#{idx}]")
            idx += 1
            if cur >= end: break
        set_name_safe(ea, "menu")
    else:
        # MENUEX: write a minimal header shape and items
        make_dword(ea+0, "dwHelpId"); make_dword(ea+4, "dwMenuFlag"); make_dword(ea+8, "dwMenuID")
        make_word(ea+12, "wPad1"); make_word(ea+14, "wPad2")
        cur, idx = ea + 16, 0
        while cur + 14 <= end:
            # MENUEX_ITEM fixed: 14 bytes
            make_dword(cur+0,  "dwType")
            make_dword(cur+4,  "dwState")
            make_dword(cur+8,  "dwID")
            make_word(cur+12,  "wFlags")
            cur += 14
            if read_u16(cur) == 0:
                make_word(cur, "title_zero"); cur += 2
            else:
                cur = make_utf16z(cur)
            set_cmt(cur, f"[MENUEX_ITEM#{idx}]")
            idx += 1
            if cur >= end: break
        set_name_safe(ea, "menuex")

def parse_rt_accel(ea, size):
    end, cur, cnt = ea + size, ea, 0
    while cur + 8 <= end:
        make_word(cur+0, "fVirt")
        make_word(cur+2, "key")
        make_word(cur+4, "cmd")
        make_word(cur+6, "pad")
        set_cmt(cur, f"[ACCEL] fVirt=0x{(read_u16(cur) or 0):04X}")
        cnt += 1
        cur += 8
    set_name_safe(ea, f"accel_tbl_{cnt:03d}")
# --- VERSION parsing: replace parse_rt_version, parse_vs_block, parse_vs_children with these ---

def parse_rt_version(ea, size):
    end = ea + size
    set_name_safe(ea, "version_info")
    try:
        nxt = parse_vs_block(ea, end, depth=0)
        # Any tail bytes are junk/padding; type them so the view is clean
        if nxt < end:
            make_bytes(nxt, end - nxt, "tail/pad")
    except Exception as ex:
        make_bytes(ea, size, f"[VERSION] parse error: {ex}")

def parse_vs_block(base, limit, depth):
    """Parse a generic VS block at 'base'. Returns EA after this block (DWORD-aligned)."""
    if base + 6 > limit:
        return base

    # Header (make sure they are WORDs, not stray bytes)
    make_word(base + 0, "wLength")
    make_word(base + 2, "wValueLength")
    make_word(base + 4, "wType")
    wLength      = read_u16(base + 0) or 0
    wValueLength = read_u16(base + 2) or 0
    wType        = read_u16(base + 4) or 0

    # Validate/clamp block length
    if wLength < 6 or base + wLength > limit:
        wLength = max(6, min(limit - base, 0xFFFF))

    cur = base + 6

    # Key (UTF-16 NUL-terminated)
    cur = make_utf16z(cur)
    key = get_utf16z_text(cur - 2)
    key_ascii = ascii_name(key, "vskey")
    set_cmt(base, f"[VS] key=\"{key}\" len={wLength} vlen={wValueLength} type={wType}")

    # Align to DWORD before value
    cur = make_pad(cur, align4(cur))
    val_start = cur

    # Value area
    if wValueLength:
        if wType == 1:
            # string value: vlen is in WCHARs
            val_end = min(limit, make_utf16_fixed(val_start, wValueLength))
        else:
            blen = min(int(wValueLength), max(0, limit - val_start))
            if key == "VS_VERSION_INFO" and blen >= 0x34:
                make_dword(val_start + 0x00, "dwSignature")
                make_dword(val_start + 0x04, "dwStrucVersion")
                make_dword(val_start + 0x08, "dwFileVersionMS")
                make_dword(val_start + 0x0C, "dwFileVersionLS")
                make_dword(val_start + 0x10, "dwProductVersionMS")
                make_dword(val_start + 0x14, "dwProductVersionLS")
                make_dword(val_start + 0x18, "dwFileFlagsMask")
                make_dword(val_start + 0x1C, "dwFileFlags")
                make_dword(val_start + 0x20, "dwFileOS")
                make_dword(val_start + 0x24, "dwFileType")
                make_dword(val_start + 0x28, "dwFileSubtype")
                make_dword(val_start + 0x2C, "dwFileDateMS")
                make_dword(val_start + 0x30, "dwFileDateLS")
                set_cmt(val_start, "[VS_FIXEDFILEINFO]")
            else:
                make_bytes(val_start, blen, f"value[{blen}]")
            val_end = val_start + blen
        cur = align4(val_end)
    else:
        # No value -> children start immediately, still DWORD-align
        cur = align4(cur)

    block_end = base + wLength
    if block_end > limit:
        block_end = min(limit, align4(cur))

    # Children
    if key in ("VS_VERSION_INFO", "StringFileInfo", "VarFileInfo", "StringTable"):
        cur = parse_vs_children(key, cur, block_end, depth + 1)

    # If we didn’t land exactly at end-of-block, mark leftover as padding so nothing looks “raw”
    if cur < block_end:
        make_pad(cur, block_end)

    set_name_safe(base, f"vs_{key_ascii}")
    return align4(block_end)

def parse_vs_children(parent_key, start, end, depth):
    """Parse children blocks inside [start, end). Returns EA after last child."""
    cur = start
    idx = 0
    while cur + 6 <= end:
        # Peek child length cleanly; stop on padding
        wlen = read_u16(cur) or 0
        if wlen < 6 or cur + wlen > end:
            # it’s not a valid child header; the rest is padding
            break

        # Don’t DIY-write header here; let the child parser type it completely.
        # But for readability, add a small preview comment of the key.
        key_preview_ea = cur + 6
        key_preview_ea = make_utf16z(key_preview_ea)
        preview = get_utf16z_text(key_preview_ea - 2)
        set_cmt(cur, f"[VS-CHILD#{idx}] {preview}")

        # Now parse the child fully (this will re-type the header/strings/values/padding)
        nxt = parse_vs_block(cur, end, depth)
        if nxt <= cur:  # paranoia guard
            break
        cur = nxt
        idx += 1
    return cur

def parse_rt_dlgin(ea, size):
    """
    RT_DLGINIT: sequence of entries:
      WORD id; WORD message; DWORD length; BYTE data[length]; WORD 0 terminator
    Stops at id==0.
    """
    end = ea + size
    cur = ea
    i = 0
    while cur + 2 <= end:
        make_word(cur, "id");  idv = read_u16(cur) or 0; cur += 2
        if idv == 0:
            set_cmt(cur - 2, "[DLGINIT] terminator")
            break
        if cur + 2 > end: break
        make_word(cur, "msg"); msg = read_u16(cur) or 0; cur += 2
        if cur + 4 > end: break
        make_dword(cur, "len"); ln = read_u32(cur) or 0; cur += 4
        ln = min(ln, max(0, end - cur))
        if ln:
            make_bytes(cur, ln, f"data[{ln}]"); cur += ln
        cur = align2(cur)
        set_cmt(cur - ln, f"[DLGINIT#{i}] id=0x{idv:04X} msg=0x{msg:04X} len={ln}")
        i += 1
    set_name_safe(ea, "dlgin it_tbl")

def parse_rt_group_icon_cursor(ea, size, top):
    if size < 6:
        make_bytes(ea, size, f"[{top}] too small"); return
    make_word(ea+0, "wReserved")
    make_word(ea+2, "wType")
    make_word(ea+4, "wCount")
    count = read_u16(ea+4) or 0
    cur = ea + 6
    for _ in range(count):
        # Both share the same footprint; semantic diff on planes/hotspot
        make_bytes(cur+0, 4, "bWidth,bHeight,bColorCount,bReserved")
        make_word(cur+4,  "wPlanes/wHotspotX")
        make_word(cur+6,  "wBitCount/wHotspotY")
        make_dword(cur+8, "dwBytesInRes")
        make_word(cur+12, "nID")
        cur += 14
    set_name_safe(ea, f"{top.lower()}_group")

def parse_textish_or_bytes(ea, size, top):
    if size >= 2:
        bom = ida_bytes.get_bytes(ea, 2)
        if bom in (b"\xff\xfe", b"\xfe\xff"):
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
            ida_bytes.create_strlit(ea, size, ida_nalt.STRTYPE_C_16)
            ida_nalt.set_str_type(ea, ida_nalt.STRTYPE_C_16)
            set_name_safe(ea, f"{top.lower()}_u16")
            return
    data = ida_bytes.get_bytes(ea, min(size, 4096)) or b""
    pct = sum(1 for b in data if 32 <= b <= 126 or b in (9,10,13)) / float(len(data) or 1)
    if pct > 0.7:
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
        ida_bytes.create_strlit(ea, size, ida_nalt.STRTYPE_C)
        set_name_safe(ea, f"{top.lower()}_txt")
    else:
        make_bytes(ea, size, f"[{top}] {size} bytes")

# ---------- entry ----------
def run():
    rstart, _ = rsrc_seg_bounds()
    if not rstart:
        log("[!] .rsrc not found. Load a PE, not a PDF.")
        return
    log("=== Parsing .rsrc (no struct API) ===")
    set_name_safe(rstart, "resdir_root")
    parse_resource_dir(rstart, [])
    log("=== Done. Struct-less, tear-free. ===")

if __name__ == "__main__":
    run()
