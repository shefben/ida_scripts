# rsrc_viewer_ida92.py
# IDA 9.2 | PySide6 | Windows-only .rsrc browser with live previews (rev 2)
# Changes per user request:
# 1) Removed image/text/table tabs; central pane auto-switches by type
# 2) Tree view is read-only (no edits, no drag/drop)
# 3) Single-click selection previews immediately
# 4) Dialog/Menu default to native Windows preview in separate windows
# 5) Tree starts collapsed
# 6) Dialog viewer: spawn native dialog window; main pane shows RC script
# 7) Menu viewer: spawn native menu window; main pane shows RC script
# 8) Cursor groups: thin right pane stacks cursors; main shows group entries text
# 9) Icon groups: same as cursor groups
import os

import sys, struct, ctypes, traceback
import idaapi, idc, idautils
import ida_kernwin, ida_bytes, ida_segment, ida_nalt
import threading

from PySide6 import QtCore, QtGui, QtWidgets
# ==== WINDOWS CTYPES COMPAT SHIMS (drop in once, near imports) ====
import ctypes
from ctypes import wintypes as _wt
from ctypes import wintypes as _wtt

icc = ctypes.c_ulong(0x0000FFFF)  # ICC_WIN95_CLASSES and friends
class INITCOMMONCONTROLSEX(ctypes.Structure):
    _fields_ = [("dwSize", _wtt.DWORD), ("dwICC", _wtt.DWORD)]
_init = INITCOMMONCONTROLSEX(ctypes.sizeof(INITCOMMONCONTROLSEX), icc)

ctypes.windll.comctl32.InitCommonControlsEx(ctypes.byref(_init))

import io
try:
    from PIL import Image
except Exception:
    Image = None


_PTR64 = (ctypes.sizeof(ctypes.c_void_p) == 8)

# Handle-ish
if not hasattr(_wt, "HANDLE"):    _wt.HANDLE    = ctypes.c_void_p
if not hasattr(_wt, "HWND"):      _wt.HWND      = _wt.HANDLE
if not hasattr(_wt, "HICON"):     _wt.HICON     = _wt.HANDLE
if not hasattr(_wt, "HCURSOR"):   _wt.HCURSOR   = _wt.HANDLE
if not hasattr(_wt, "HBRUSH"):    _wt.HBRUSH    = _wt.HANDLE
if not hasattr(_wt, "HMENU"):     _wt.HMENU     = _wt.HANDLE
if not hasattr(_wt, "HINSTANCE"): _wt.HINSTANCE = _wt.HANDLE

# Scalars
if not hasattr(_wt, "ATOM"):      _wt.ATOM      = ctypes.c_ushort
if not hasattr(_wt, "INT"):       _wt.INT       = ctypes.c_int
if not hasattr(_wt, "UINT"):      _wt.UINT      = ctypes.c_uint
if not hasattr(_wt, "DWORD"):     _wt.DWORD     = ctypes.c_uint32
if not hasattr(_wt, "WORD"):      _wt.WORD      = ctypes.c_ushort
if not hasattr(_wt, "BOOL"):      _wt.BOOL      = ctypes.c_int
if not hasattr(_wt, "LPCWSTR"):   _wt.LPCWSTR   = ctypes.c_wchar_p
if not hasattr(_wt, "LPWSTR"):    _wt.LPWSTR    = ctypes.c_wchar_p
if not hasattr(_wt, "LPCVOID"):   _wt.LPCVOID   = ctypes.c_void_p
if not hasattr(_wt, "LPVOID"):    _wt.LPVOID    = ctypes.c_void_p

# More GDI-ish types PySide likes to forget
if not hasattr(_wt, "HDC"):      _wt.HDC = _wt.HANDLE
if not hasattr(_wt, "HGDIOBJ"):  _wt.HGDIOBJ = _wt.HANDLE
if not hasattr(_wt, "HBITMAP"):  _wt.HBITMAP = _wt.HANDLE

# Pointer-sized ints
if not hasattr(_wt, "WPARAM"):
    _wt.WPARAM = ctypes.c_uint64 if _PTR64 else ctypes.c_uint32
if not hasattr(_wt, "LPARAM"):
    _wt.LPARAM = ctypes.c_int64  if _PTR64 else ctypes.c_long
if not hasattr(_wt, "LRESULT"):
    _wt.LRESULT = ctypes.c_int64 if _PTR64 else ctypes.c_long

# Minimal MSG
class MSG(ctypes.Structure):
    _fields_ = [
        ("hwnd",    _wt.HWND),
        ("message", _wt.UINT),
        ("wParam",  _wt.WPARAM),
        ("lParam",  _wt.LPARAM),
        ("time",    _wt.DWORD),
        ("pt_x",    ctypes.c_long),
        ("pt_y",    ctypes.c_long),
    ]
if not hasattr(_wt, "MSG"):
    _wt.MSG = MSG

# Add RECT if not present
if not hasattr(_wt, "RECT"):
    from ctypes import wintypes as _wtt
    _wt.RECT = _wtt.RECT

# Prototypes we use below (explicit is better than magical)
NativePreview.user32.GetWindowRect.argtypes = [_wt.HWND, ctypes.POINTER(_wt.RECT)]
NativePreview.user32.GetWindowRect.restype  = _wt.BOOL

NativePreview.user32.SetWindowPos.argtypes = [_wt.HWND, _wt.HWND,
                                              ctypes.c_int, ctypes.c_int,
                                              ctypes.c_int, ctypes.c_int,
                                              _wt.UINT]
NativePreview.user32.SetWindowPos.restype  = _wt.BOOL

NativePreview.user32.GetWindow.argtypes = [_wt.HWND, _wt.UINT]
NativePreview.user32.GetWindow.restype  = _wt.HWND

NativePreview.user32.DestroyWindow.argtypes = [_wt.HWND]
NativePreview.user32.DestroyWindow.restype  = _wt.BOOL

# Proc signatures
WNDPROC_T = ctypes.WINFUNCTYPE(_wt.LRESULT, _wt.HWND, _wt.UINT, _wt.WPARAM, _wt.LPARAM)
DLGPROC_T = ctypes.WINFUNCTYPE(_wt.INT,     _wt.HWND, _wt.UINT, _wt.WPARAM, _wt.LPARAM)

# WNDCLASSW
class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style",        _wt.UINT),
        ("lpfnWndProc",  WNDPROC_T),
        ("cbClsExtra",   ctypes.c_int),
        ("cbWndExtra",   ctypes.c_int),
        ("hInstance",    _wt.HINSTANCE),
        ("hIcon",        _wt.HICON),
        ("hCursor",      _wt.HCURSOR),
        ("hbrBackground",_wt.HBRUSH),
        ("lpszMenuName", _wt.LPCWSTR),
        ("lpszClassName",_wt.LPCWSTR),
    ]

# Dialog proc signature: INT_PTR CALLBACK(HWND, UINT, WPARAM, LPARAM)
DLGPROC_T = ctypes.WINFUNCTYPE(_wt.INT, _wt.HWND, _wt.UINT, _wt.WPARAM, _wt.LPARAM)

LOG = True
def log(msg):
    if LOG:
        ida_kernwin.msg(f"[RSRC] {msg}\n")

RT = {
    1: "CURSOR",
    2: "BITMAP",
    3: "ICON",
    4: "MENU",
    5: "DIALOG",
    6: "STRING",
    7: "FONTDIR",
    8: "FONT",
    9: "ACCELERATOR",
    10: "RCDATA",
    11: "MESSAGETABLE",
    12: "GROUP_CURSOR",
    14: "GROUP_ICON",
    16: "VERSION",
    17: "DLGINCLUDE",
    19: "PLUGPLAY",
    20: "VXD",
    21: "ANICURSOR",
    22: "ANIICON",
    23: "HTML",
    24: "MANIFEST",
}

def get_rsrc_segment():
    n = ida_segment.get_segm_qty()
    for i in range(n):
        s = ida_segment.getnseg(i)
        name = ida_segment.get_segm_name(s) or ""
        if name.lower().startswith(".rsrc"):
            return s
    return None

def read_bytes(ea, size):
    b = ida_bytes.get_bytes(ea, size)
    if not b or len(b) != size:
        raise RuntimeError(f"Failed reading {size} bytes at {ea:x}")
    return b

def u16(b, off=0): return struct.unpack_from("<H", b, off)[0]
def u32(b, off=0): return struct.unpack_from("<I", b, off)[0]
def s16(b, off=0): return struct.unpack_from("<h", b, off)[0]

class ResData:
    def __init__(self, type_id, type_name, name_id, name_str, lang, data_rva, size, codepage, raw):
        self.type_id = type_id
        self.type_name = type_name
        self.name_id = name_id
        self.name_str = name_str
        self.lang = lang
        self.data_rva = data_rva
        self.size = size
        self.codepage = codepage
        self.raw = raw

def rva_to_ea(rva):
    return ida_nalt.get_imagebase() + rva

def parse_resource_tree():
    seg = get_rsrc_segment()
    if not seg:
        raise RuntimeError(".rsrc segment not found")
    base_ea = seg.start_ea
    base_rva = int(base_ea - ida_nalt.get_imagebase())

    def read_dir(off_rel):
        ea = base_ea + off_rel
        b = read_bytes(ea, 16)
        _, _, _, _, n_named, n_id = struct.unpack_from("<I I H H H H", b, 0)
        total = n_named + n_id
        entries = []
        if total:
            eb = read_bytes(ea + 16, total * 8)
            for i in range(total):
                Name, Offset = struct.unpack_from("<II", eb, i * 8)
                entries.append((Name, Offset))
        return (n_named, n_id, entries)

    def read_u16z_str(u16_units_off_rel):
        ea = base_ea + u16_units_off_rel
        n = u16(read_bytes(ea, 2), 0)
        if n == 0:
            return ""
        b = read_bytes(ea + 2, n * 2)
        try:
            return b.decode("utf-16le")
        except Exception:
            return ""

    results = []

    def walk_level(off_rel, type_id=None, type_name=None, name_id=None, name_str=None):
        n_named, n_id, entries = read_dir(off_rel)
        for (Name, Offset) in entries:
            is_name = (Name & 0x80000000) != 0
            name_val = Name & 0x7FFFFFFF
            is_dir = (Offset & 0x80000000) != 0
            next_off = Offset & 0x7FFFFFFF

            nm = read_u16z_str(name_val) if is_name else None
            sub_off = next_off

            if type_id is None:
                if is_dir:
                    if is_name:
                        walk_level(sub_off, type_id=None, type_name=nm)
                    else:
                        walk_level(sub_off, type_id=name_val, type_name=RT.get(name_val, str(name_val)))
            elif name_id is None and name_str is None:
                if is_dir:
                    if is_name:
                        walk_level(sub_off, type_id=type_id, type_name=type_name, name_id=None, name_str=nm)
                    else:
                        walk_level(sub_off, type_id=type_id, type_name=type_name, name_id=name_val, name_str=None)
            else:
                if is_dir:
                    walk_level(sub_off, type_id=type_id, type_name=type_name, name_id=name_id, name_str=name_str)
                else:
                    deb = read_bytes(base_ea + sub_off, 16)
                    data_rva, size, codepage, _ = struct.unpack_from("<IIII", deb, 0)
                    data_ea = rva_to_ea(data_rva)
                    raw = read_bytes(data_ea, size)
                    lang = name_val if not is_name else 0
                    results.append(ResData(type_id, type_name, name_id, name_str, lang, data_rva, size, codepage, raw))

    log("Scanning .rsrc...")
    walk_level(0)
    log(f"Found {len(results)} resource blobs")
    return results

def ensure_bmp_from_dib(dib_bytes):
    if len(dib_bytes) < 40:
        raise ValueError("DIB too small")
    biSize = u32(dib_bytes, 0)
    biWidth  = struct.unpack_from("<i", dib_bytes, 4)[0]
    bpp      = u16(dib_bytes, 14)
    clr_used = u32(dib_bytes, 32)
    palette_entries = 0
    if bpp <= 8:
        palette_entries = clr_used if clr_used != 0 else (1 << bpp)
    off_bits = 14 + biSize + palette_entries * 4
    file_size = 14 + len(dib_bytes)
    bf = b"BM" + struct.pack("<IHHI", file_size, 0, 0, off_bits)
    return bf + dib_bytes

def make_ico_from_group(group_bytes, rt_icon_dict):
    if len(group_bytes) < 6:
        raise ValueError("Group icon too small")
    idReserved, idType, idCount = struct.unpack_from("<HHH", group_bytes, 0)
    if idType != 1:
        raise ValueError("Not an ICON group")
    entries = []
    off = 6
    for _ in range(idCount):
        bWidth, bHeight, bColorCount, bReserved = struct.unpack_from("BBBB", group_bytes, off)
        wPlanes, wBitCount, dwBytesInRes, nID = struct.unpack_from("<HHIH", group_bytes, off + 4)
        off += 14
        img = rt_icon_dict.get(nID)
        if not img:
            continue
        entries.append((bWidth, bHeight, bColorCount, bReserved, wPlanes, wBitCount, len(img), img, nID))
    out = struct.pack("<HHH", 0, 1, len(entries))
    data_off = 6 + 16 * len(entries)
    blobs = []
    for e in entries:
        bWidth, bHeight, bColorCount, bReserved, wPlanes, wBitCount, sz, img, _ = e
        out += struct.pack("BBBBHHII", bWidth, bHeight, bColorCount, bReserved, wPlanes, wBitCount, sz, data_off)
        blobs.append(img)
        data_off += sz
    for blob in blobs:
        out += blob
    return out, entries  # also return parsed entries

def make_cur_from_group(group_bytes, rt_cursor_dict):
    if len(group_bytes) < 6:
        raise ValueError("Group cursor too small")
    idReserved, idType, idCount = struct.unpack_from("<HHH", group_bytes, 0)
    if idType != 2:
        raise ValueError("Not a CURSOR group")
    entries = []
    off = 6
    for _ in range(idCount):
        bWidth, bHeight, bColorCount, bReserved = struct.unpack_from("BBBB", group_bytes, off)
        wXHot, wYHot, dwBytesInRes, nID = struct.unpack_from("<HHIH", group_bytes, off + 4)
        off += 14
        img = rt_cursor_dict.get(nID)
        if not img:
            continue
        entries.append((bWidth, bHeight, bColorCount, bReserved, wXHot, wYHot, len(img), img, nID))
    out = struct.pack("<HHH", 0, 2, len(entries))
    data_off = 6 + 16 * len(entries)
    blobs = []
    for e in entries:
        bWidth, bHeight, bColorCount, bReserved, wXHot, wYHot, sz, img, _ = e
        out += struct.pack("<BBBBHHII", bWidth, bHeight, bColorCount, bReserved, wXHot, wYHot, sz, data_off)
        blobs.append(img)
        data_off += sz
    for blob in blobs:
        out += blob
    return out, entries

# ---------- Version info ----------
class VersionInfo:
    def __init__(self):
        self.fixed = {}
        self.string_table = {}
        self.var = {}
def parse_version_info(b):
    vi = VersionInfo()

    def read_u16(off): return u16(b, off) if 0 <= off+2 <= len(b) else 0
    def read_u32(off): return u32(b, off) if 0 <= off+4 <= len(b) else 0
    def read_wstr(off, nchars):
        nbytes = max(0, int(nchars)) * 2
        end = min(len(b), off + nbytes)
        if off < 0 or off >= len(b) or end <= off:
            return ""
        return b[off:end].decode("utf-16le", errors="ignore")
    def align4(x): return (x + 3) & ~3

    def parse_block(off, limit):
        # Basic sanity
        if off < 0 or off + 6 > limit:
            return limit

        wLength      = read_u16(off)
        wValueLength = read_u16(off + 2)
        wType        = read_u16(off + 4)

        # Header-only or bogus size: advance minimally to avoid looping forever
        if wLength < 8:
            return min(limit, off + max(6, wLength or 6))

        # Bound this block to its parent
        block_end = min(limit, off + wLength)

        # Read UTF-16 key up to NUL within this block
        key_off = off + 6
        p = key_off
        while p + 2 <= block_end:
            if b[p:p+2] == b"\x00\x00":
                p += 2  # include NUL before aligning
                break
            p += 2
        if p > block_end:
            p = block_end

        key_bytes = b[key_off:max(key_off, p - 2)]
        try:
            key = key_bytes.decode("utf-16le", errors="ignore")
        except Exception:
            key = ""

        # Align value start
        val_off = align4(p)
        if val_off > block_end:
            val_off = block_end

        # Value length in bytes (strings count in WCHARs)
        avail = max(0, block_end - val_off)
        value_bytes = min((wValueLength * 2) if wType == 1 else wValueLength, avail)

        # Children begin after value, aligned
        child_off = align4(val_off + value_bytes)
        if child_off > block_end:
            child_off = block_end

        # Known blocks
        if key == "VS_VERSION_INFO":
            # VS_FIXEDFILEINFO typically 52 bytes; guard with bounds
            if wValueLength >= 52 and val_off + 52 <= block_end:
                vi.fixed = {
                    "FileVersionMS":    read_u32(val_off + 8),
                    "FileVersionLS":    read_u32(val_off + 12),
                    "ProductVersionMS": read_u32(val_off + 16),
                    "ProductVersionLS": read_u32(val_off + 20),
                }
            c = child_off
            while c < block_end:
                c2 = parse_block(c, block_end)
                if c2 <= c:
                    break
                c = c2

        elif key in ("StringFileInfo", "VarFileInfo"):
            c = child_off
            while c < block_end:
                c2 = parse_block(c, block_end)
                if c2 <= c:
                    break
                c = c2

        else:
            # String table buckets like "040904E4"
            hexish = len(key) >= 8 and all(ch in "0123456789abcdefABCDEF" for ch in key)
            if hexish:
                c = child_off
                while c < block_end:
                    c2 = parse_block(c, block_end)
                    if c2 <= c:
                        break
                    c = c2
            else:
                if key.lower() == "translation" and wValueLength and (wValueLength % 4) == 0 and (val_off + wValueLength) <= block_end:
                    count = wValueLength // 4
                    vals = []
                    for i in range(count):
                        base = val_off + i * 4
                        lang = read_u16(base)
                        cp   = read_u16(base + 2)
                        vals.append((lang, cp))
                    if vals:
                        vi.var["Translation"] = vals
                elif wType == 1 and wValueLength > 0:
                    s = read_wstr(val_off, wValueLength).rstrip("\x00")
                    vi.string_table[key] = s

        # Advance to next sibling, with corruption guards
        next_off = off + wLength
        if next_off <= off or next_off > limit:
            return block_end
        return next_off

    try:
        top_len = u16(b, 0) if len(b) >= 2 else 0
        parse_block(0, min(len(b), top_len if 8 <= top_len <= len(b) else len(b)))
    except Exception:
        log("Version parse error:\n" + traceback.format_exc())
    return vi


# ---------- Accelerators ----------
def parse_accelerators(b):
    out = []
    off = 0
    while off + 8 <= len(b):
        fVirt, key, cmd, _ = struct.unpack_from("<HHHH", b, off)
        off += 8
        out.append((fVirt, key, cmd))
        if (fVirt & 0x80) != 0:
            break
    return out

# ---------- RC script dump (best-effort) ----------
def rc_escape(s):
    return s.replace("\\", "\\\\").replace('"', r'\"')

def rc_dump_dialog(raw):
    # Heuristic: detect DLGTEMPLATEEX vs DLGTEMPLATE
    is_ex = False
    if len(raw) >= 6 and u16(raw, 0) == 1 and u16(raw, 2) == 0xFFFF:
        is_ex = True
    out = []
    try:
        if is_ex:
            # DLGTEMPLATEEX:
            # WORD dlgVer, WORD signature(0xFFFF), DWORD helpID, DWORD exStyle, DWORD style,
            # WORD cDlgItems, short x,y,cx,cy, menu, windowClass, title, [font stuff...]
            dlgVer, sig = u16(raw,0), u16(raw,2)
            helpID, exStyle, style, cDlgItems = u32(raw,4), u32(raw,8), u32(raw,12), u16(raw,16)
            x,y,cx,cy = struct.unpack_from("<hhhh", raw, 18)
            off = 26
            def skip_menu_or_class(off):
                if u16(raw, off) == 0x0000:
                    return off+2, "0"
                if u16(raw, off) == 0xFFFF:
                    mid = u16(raw, off+2)
                    return off+4, str(mid)
                # string
                p = off
                s = []
                while True:
                    w = u16(raw, p); p += 2
                    if w == 0: break
                    s.append(w)
                txt = bytes(bytearray(sum(([w&0xFF, (w>>8)&0xFF] for w in s), []))).decode("utf-16le")
                return p, f'"{rc_escape(txt)}"'
            off, menu_txt = skip_menu_or_class(off)
            off, class_txt = skip_menu_or_class(off)
            # title string
            p = off; title_chars = []
            while True:
                w = u16(raw, p); p += 2
                if w == 0: break
                title_chars.append(w)
            title = bytes(bytearray(sum(([w&0xFF, (w>>8)&0xFF] for w in title_chars), []))).decode("utf-16le")
            off = p
            # optional font
            font_clause = ""
            if style & 0x00000040: # DS_SETFONT
                pointsize = u16(raw, off); off += 2
                weight = u16(raw, off); off += 2
                italic = u16(raw, off); off += 2
                charset = u16(raw, off); off += 2
                # face name
                p = off; face = []
                while True:
                    w = u16(raw, p); p += 2
                    if w == 0: break
                    face.append(w)
                face_name = bytes(bytearray(sum(([w&0xFF, (w>>8)&0xFF] for w in face), []))).decode("utf-16le")
                off = p
                font_clause = f', {pointsize}, "{rc_escape(face_name)}", {weight}, {"TRUE" if italic else "FALSE"}, {charset}'
            out.append(f'DIALOGEX {x}, {y}, {cx}, {cy}')
            out.append(f'STYLE 0x{style:08X}')
            if exStyle:
                out.append(f'EXSTYLE 0x{exStyle:08X}')
            if menu_txt != "0":
                out.append(f"MENU {menu_txt}")
            if class_txt != "0":
                out.append(f"CLASS {class_txt}")
            out.append(f'CAPTION "{rc_escape(title)}"')
            if font_clause:
                out.append(f'FONT {font_clause.lstrip(", ")}')
            out.append("BEGIN")
            out.append(f"    // {cDlgItems} controls omitted in dump")
            out.append("END")
        else:
            # DLGTEMPLATE
            style, exStyle, cDlgItems = u32(raw,0), u32(raw,4), u16(raw,8)
            x,y,cx,cy = struct.unpack_from("<hhhh", raw, 10)
            off = 18
            def skip_menu_or_class(off):
                w = u16(raw, off)
                if w == 0:
                    return off+2, "0"
                if w == 0xFFFF:
                    return off+4, str(u16(raw, off+2))
                p = off
                s = []
                while True:
                    w = u16(raw, p); p += 2
                    if w == 0: break
                    s.append(w)
                txt = bytes(bytearray(sum(([w&0xFF, (w>>8)&0xFF] for w in s), []))).decode("utf-16le")
                return p, f'"{rc_escape(txt)}"'
            off, menu_txt = skip_menu_or_class(off)
            off, class_txt = skip_menu_or_class(off)
            # title
            p = off; title_chars=[]
            while True:
                w = u16(raw, p); p += 2
                if w == 0: break
                title_chars.append(w)
            title = bytes(bytearray(sum(([w&0xFF, (w>>8)&0xFF] for w in title_chars), []))).decode("utf-16le")
            off = p
            font_clause = ""
            if style & 0x00000040: # DS_SETFONT
                pointsize = u16(raw, off); off += 2
                p = off; face=[]
                while True:
                    w = u16(raw, p); p += 2
                    if w == 0: break
                    face.append(w)
                face_name = bytes(bytearray(sum(([w&0xFF, (w>>8)&0xFF] for w in face), []))).decode("utf-16le")
                font_clause = f'{pointsize}, "{rc_escape(face_name)}"'
            out.append(f'DIALOG {x}, {y}, {cx}, {cy}')
            out.append(f'STYLE 0x{style:08X}')
            if exStyle:
                out.append(f'EXSTYLE 0x{exStyle:08X}')
            if menu_txt != "0":
                out.append(f"MENU {menu_txt}")
            if class_txt != "0":
                out.append(f"CLASS {class_txt}")
            out.append(f'CAPTION "{rc_escape(title)}"')
            if font_clause:
                out.append(f'FONT {font_clause}')
            out.append("BEGIN")
            out.append(f"    // {cDlgItems} controls omitted in dump")
            out.append("END")
    except Exception:
        out = ["// Failed to dump dialog RC (best-effort parser)"]
    return "\n".join(out)

def rc_dump_menu(raw):
    # Best-effort: we don't decode every flag. We list items and popups.
    out = ["MENU", "BEGIN", "    // best-effort dump"]
    try:
        # Basic RT_MENU template: WORD wVersion, WORD wOffset, WORD Flags, ... blocks
        # We'll scan UTF-16 sequences as labels and mark popups.
        text_chunks = []
        i = 0
        # cheap heuristic: search for UTF-16LE strings
        while i+4 <= len(raw):
            w = u16(raw, i)
            if w != 0 and 32 <= w < 0xD800:
                p = i
                s = []
                while p+2 <= len(raw):
                    ww = u16(raw, p); p += 2
                    if ww == 0:
                        break
                    if ww < 32 or ww >= 0xF000: break
                    s.append(ww)
                if s:
                    txt = bytes(bytearray(sum(([ww&0xFF, (ww>>8)&0xFF] for ww in s), []))).decode("utf-16le", errors="ignore")
                    text_chunks.append(txt)
                    i = p
                    continue
            i += 2
        for t in text_chunks:
            out.append(f'    MENUITEM "{rc_escape(t)}", 0')  # id unknown in lightweight dump
        out.append("END")
    except Exception:
        out = ["// Failed to dump menu RC (best-effort parser)"]
    return "\n".join(out)
# ==== NATIVE PREVIEW (VirtualAlloc + threaded modal dialogs) ====
class NativePreview:
    user32   = ctypes.WinDLL("user32",   use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
    kernel32.VirtualAlloc.restype  = ctypes.c_void_p

    _dlgprocs = []
    _wndprocs = []
    _allocs   = []

    WNDPROC = WNDPROC_T
    DLGPROC = DLGPROC_T

    # --- user32 prototypes used elsewhere (as you had) ---
    user32.CreateDialogIndirectParamW.argtypes = [_wt.HINSTANCE, _wt.LPCVOID, _wt.HWND, DLGPROC_T, _wt.LPARAM]
    user32.CreateDialogIndirectParamW.restype  = _wt.HWND
    user32.DialogBoxIndirectParamW.argtypes    = [_wt.HINSTANCE, _wt.LPCVOID, _wt.HWND, DLGPROC_T, _wt.LPARAM]
    user32.DialogBoxIndirectParamW.restype     = _wt.INT
    user32.LoadMenuIndirectW.argtypes          = [_wt.LPCVOID]
    user32.LoadMenuIndirectW.restype           = _wt.HMENU
    user32.RegisterClassW.argtypes             = [ctypes.POINTER(WNDCLASSW)]
    user32.RegisterClassW.restype              = _wt.ATOM
    user32.CreateWindowExW.argtypes = [
        _wt.DWORD, _wt.LPCWSTR, _wt.LPCWSTR, _wt.DWORD,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        _wt.HWND, _wt.HMENU, _wt.HINSTANCE, _wt.LPVOID
    ]
    user32.CreateWindowExW.restype  = _wt.HWND
    user32.DefWindowProcW.argtypes  = [_wt.HWND, _wt.UINT, _wt.WPARAM, _wt.LPARAM]
    user32.DefWindowProcW.restype   = _wt.LRESULT
    user32.SetWindowTextW.argtypes  = [_wt.HWND, _wt.LPCWSTR]
    user32.SetWindowTextW.restype   = _wt.BOOL
    user32.ShowWindow.argtypes      = [_wt.HWND, ctypes.c_int]
    user32.ShowWindow.restype       = _wt.BOOL
    user32.UpdateWindow.argtypes    = [_wt.HWND]
    user32.UpdateWindow.restype     = _wt.BOOL
    user32.SetMenu.argtypes         = [_wt.HWND, _wt.HMENU]
    user32.SetMenu.restype          = _wt.BOOL
    user32.PostQuitMessage.argtypes = [ctypes.c_int]
    user32.PostQuitMessage.restype  = None
    user32.EndDialog.argtypes       = [_wt.HWND, _wt.INT]
    user32.EndDialog.restype        = _wt.BOOL
    user32.PeekMessageW.argtypes    = [ctypes.POINTER(_wt.MSG), _wt.HWND, _wt.UINT, _wt.UINT, _wt.UINT]
    user32.PeekMessageW.restype     = _wt.BOOL
    user32.TranslateMessage.argtypes= [ctypes.POINTER(_wt.MSG)]
    user32.TranslateMessage.restype = _wt.BOOL
    user32.DispatchMessageW.argtypes= [ctypes.POINTER(_wt.MSG)]
    user32.DispatchMessageW.restype = _wt.LRESULT

    # --- extra prototypes we need for proper embedding ---
    LONG_PTR = ctypes.c_longlong if _PTR64 else ctypes.c_long

    user32.GetWindowRect.argtypes   = [_wt.HWND, ctypes.POINTER(_wt.RECT)]
    user32.GetWindowRect.restype    = _wt.BOOL
    user32.GetClientRect.argtypes   = [_wt.HWND, ctypes.POINTER(_wt.RECT)]
    user32.GetClientRect.restype    = _wt.BOOL
    user32.SetWindowPos.argtypes    = [_wt.HWND, _wt.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, _wt.UINT]
    user32.SetWindowPos.restype     = _wt.BOOL
    user32.MoveWindow.argtypes      = [_wt.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, _wt.BOOL]
    user32.MoveWindow.restype       = _wt.BOOL
    user32.GetWindow.argtypes       = [_wt.HWND, _wt.UINT]
    user32.GetWindow.restype        = _wt.HWND
    user32.DestroyWindow.argtypes   = [_wt.HWND]
    user32.DestroyWindow.restype    = _wt.BOOL
    user32.SetParent.argtypes       = [_wt.HWND, _wt.HWND]
    user32.SetParent.restype        = _wt.HWND
    user32.GetWindowLongPtrW.argtypes = [_wt.HWND, ctypes.c_int]
    user32.GetWindowLongPtrW.restype  = LONG_PTR
    user32.SetWindowLongPtrW.argtypes = [_wt.HWND, ctypes.c_int, LONG_PTR]
    user32.SetWindowLongPtrW.restype  = LONG_PTR
    user32.SendMessageW.argtypes    = [_wt.HWND, _wt.UINT, _wt.WPARAM, _wt.LPARAM]
    user32.SendMessageW.restype     = _wt.LRESULT
    user32.RedrawWindow.argtypes    = [_wt.HWND, ctypes.c_void_p, ctypes.c_void_p, _wt.UINT]
    user32.RedrawWindow.restype     = _wt.BOOL

    kernel32.GetModuleHandleW.argtypes = [_wt.LPCWSTR]
    kernel32.GetModuleHandleW.restype  = _wt.HINSTANCE

    # --- constants ---
    PAGE_READWRITE = 0x04
    MEM_COMMIT     = 0x1000
    MEM_RESERVE    = 0x2000

    GWL_STYLE      = -16
    WS_CHILD       = 0x40000000
    WS_POPUP       = 0x80000000
    SWP_NOZORDER   = 0x0004
    SWP_NOMOVE     = 0x0002
    SWP_NOACTIVATE = 0x0010
    SWP_FRAMECHANGED = 0x0020
    RDW_INVALIDATE = 0x0001
    RDW_ALLCHILDREN= 0x0080
    RDW_ERASE      = 0x0004

    _open_hwnds = []
    _open       = []
    _host_atom  = 0
    _host_class = None

    @staticmethod
    def _va_alloc_copy(data: bytes) -> int:
        sz  = ctypes.c_size_t(len(data))
        ptr = NativePreview.kernel32.VirtualAlloc(None, sz,
                         NativePreview.MEM_COMMIT | NativePreview.MEM_RESERVE,
                         NativePreview.PAGE_READWRITE)
        if not ptr:
            raise OSError("VirtualAlloc failed")
        ctypes.memmove(ptr, data, sz.value)
        NativePreview._allocs.append((ptr, sz.value))
        return ptr

    @staticmethod
    def _get_hinstance():
        try:
            return _wt.HINSTANCE(int(idaapi.get_kernel_module()))
        except Exception:
            return NativePreview.kernel32.GetModuleHandleW(None)

    @staticmethod
    @WNDPROC_T
    def _host_wndproc(hwnd, msg, wparam, lparam):
        WM_DESTROY = 0x0002
        if msg == WM_DESTROY:
            GW_CHILD = 5
            child = NativePreview.user32.GetWindow(hwnd, GW_CHILD)
            if child:
                NativePreview.user32.DestroyWindow(child)
            return 0
        return NativePreview.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    @staticmethod
    def _create_host_window(hInst, title):
        if not NativePreview._host_atom:
            wc = WNDCLASSW()
            wc.style = 0
            wc.lpfnWndProc  = NativePreview._host_wndproc
            wc.cbClsExtra   = 0
            wc.cbWndExtra   = 0
            wc.hInstance    = hInst
            wc.hIcon        = None
            wc.hCursor      = None
            wc.hbrBackground= ctypes.c_void_p(5)  # COLOR_WINDOW+1
            wc.lpszMenuName = None
            NativePreview._host_class = f"IDA_RSRC_PREVIEW_HOST_{os.getpid()}"
            wc.lpszClassName = NativePreview._host_class
            atom = NativePreview.user32.RegisterClassW(ctypes.byref(wc))
            if not atom:
                atom = 1
            NativePreview._host_atom = atom

        WS_OVERLAPPEDWINDOW = 0x00CF0000
        WS_VISIBLE      = 0x10000000
        WS_CLIPCHILDREN = 0x02000000
        WS_EX_TOOLWINDOW= 0x00000080

        hwnd = NativePreview.user32.CreateWindowExW(
            WS_EX_TOOLWINDOW,
            NativePreview._host_class, title,
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_VISIBLE,
            100, 100, 420, 320,
            None, None, hInst, None
        )
        return hwnd

    @staticmethod
    def _register_preview(host_hwnd, child_hwnd):
        NativePreview._open.append((host_hwnd, child_hwnd))

    @staticmethod
    def close_all_previews():
        for host, dlg in reversed(NativePreview._open):
            try:
                if dlg:
                    NativePreview.user32.DestroyWindow(dlg)
            finally:
                if host:
                    NativePreview.user32.DestroyWindow(host)
        NativePreview._open.clear()

        @staticmethod
        def preview_dialog_hosted(raw_tmpl: bytes, title: str = "Dialog Preview") -> bool:
            hInst = NativePreview._get_hinstance()
            host  = NativePreview._create_host_window(hInst, title)
            if not host:
                return False

            # Create a normal dialog (top-level popup)
            dlg = NativePreview.user32.CreateDialogIndirectParamW(
                hInst,
                ctypes.cast(raw_tmpl, ctypes.c_void_p),
                host,           # owner, ignored for childness
                DLGPROC_T(0),
                0
            )
            if not dlg:
                NativePreview.user32.DestroyWindow(host)
                return False

            # Flip WS_POPUP -> WS_CHILD and reparent into host
            style = NativePreview.user32.GetWindowLongPtrW(dlg, NativePreview.GWL_STYLE)
            style = (style | NativePreview.WS_CHILD) & ~NativePreview.WS_POPUP
            NativePreview.user32.SetWindowLongPtrW(dlg, NativePreview.GWL_STYLE, style)
            NativePreview.user32.SetParent(dlg, host)
            NativePreview.user32.SetWindowPos(
                dlg, None, 0, 0, 0, 0,
                NativePreview.SWP_NOZORDER | NativePreview.SWP_NOMOVE | NativePreview.SWP_FRAMECHANGED
            )

            # Show dialog so it computes its real pixel size
            NativePreview.user32.ShowWindow(dlg, 5)   # SW_SHOW
            NativePreview.user32.UpdateWindow(dlg)

            # Fit host to the dialog?s current outer size
            rc = _wt.RECT()
            if NativePreview.user32.GetWindowRect(dlg, ctypes.byref(rc)):
                width  = rc.right  - rc.left
                height = rc.bottom - rc.top
            else:
                width, height = 320, 200

            NativePreview.user32.SetWindowPos(
                host, None, 0, 0,
                max(160, width + 16), max(120, height + 16),
                NativePreview.SWP_NOZORDER | NativePreview.SWP_NOACTIVATE
            )
            # Slam child to 0,0 inside host client and redraw
            NativePreview.user32.MoveWindow(dlg, 0, 0, width, height, True)
            NativePreview.user32.RedrawWindow(dlg, None, None,
                NativePreview.RDW_INVALIDATE | NativePreview.RDW_ALLCHILDREN | NativePreview.RDW_ERASE)

            NativePreview.user32.ShowWindow(host, 5)
            NativePreview._register_preview(host, dlg)
            return True


    # -------- dialog: modeless fallback --
    @staticmethod
    def preview_dialog_modeless(template_bytes: bytes, title="Dialog Preview") -> bool:
        @NativePreview.DLGPROC
        def dlg_proc(hDlg, msg, wParam, lParam):
            if msg == 0x0010:  # WM_CLOSE
                NativePreview.user32.EndDialog(hDlg, 0); return 1
            if msg == 0x0100 and wParam == 27:  # VK_ESCAPE
                NativePreview.user32.EndDialog(hDlg, 0); return 1
            return 0

        NativePreview._dlgprocs.append(dlg_proc)
        lp = NativePreview._va_alloc_copy(template_bytes)
        hwnd = NativePreview.user32.CreateDialogIndirectParamW(NativePreview._get_hinstance(), lp, None, dlg_proc, 0)
        if not hwnd:
            return False

        NativePreview.user32.SetWindowTextW(hwnd, title)
        NativePreview.user32.ShowWindow(hwnd, 1)

        # Tiny pump via Qt timer so controls render in IDA?s mixed loop
        def pump_once():
            msg = _wt.MSG()
            while NativePreview.user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):
                NativePreview.user32.TranslateMessage(ctypes.byref(msg))
                NativePreview.user32.DispatchMessageW(ctypes.byref(msg))
        try:
            from PySide6 import QtCore
            t = QtCore.QTimer()
            t.setInterval(10)
            t.timeout.connect(pump_once)
            t.start()
        except Exception:
            pass
        return True

    # -------- dialog: modal (worker thr) -
    @staticmethod
    def preview_dialog_modal_threaded(template_bytes: bytes, title="Dialog Preview") -> bool:
        @NativePreview.DLGPROC
        def dlg_proc(hDlg, msg, wParam, lParam):
            if msg == 0x0010 or (msg == 0x0100 and wParam == 27):
                NativePreview.user32.EndDialog(hDlg, 0); return 1
            return 0

        NativePreview._dlgprocs.append(dlg_proc)
        lp    = NativePreview._va_alloc_copy(template_bytes)
        hinst = NativePreview._get_hinstance()

        def worker():
            NativePreview.user32.DialogBoxIndirectParamW(hinst, lp, None, dlg_proc, 0)

        th = threading.Thread(target=worker, name="rsrc-dialog-preview", daemon=True)
        th.start()
        return True

    # -------- menu preview window --------
    @staticmethod
    def preview_menu_window(menu_bytes: bytes, title="Menu Preview") -> bool:
        hmenu = NativePreview.user32.LoadMenuIndirectW(NativePreview._va_alloc_copy(menu_bytes))
        if not hmenu:
            return False

        @NativePreview.WNDPROC
        def wndproc(hwnd, msg, wparam, lparam):
            if msg == 0x0010:  # WM_CLOSE
                NativePreview.user32.DestroyWindow(hwnd)
                return 0
            if msg == 0x0002:  # WM_DESTROY
                try:
                    NativePreview._open_hwnds.remove(hwnd)
                except ValueError:
                    pass
                return 0
            return NativePreview.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        NativePreview._wndprocs.append(wndproc)

        wc = WNDCLASSW()
        wc.style = 0
        wc.lpfnWndProc  = wndproc
        wc.cbClsExtra   = 0
        wc.cbWndExtra   = 0
        wc.hInstance    = NativePreview._get_hinstance()
        wc.hIcon        = None
        wc.hCursor      = None
        wc.hbrBackground= None
        wc.lpszMenuName = None
        wc.lpszClassName= "RSRC_MENU_PREVIEW"
        NativePreview.user32.RegisterClassW(ctypes.byref(wc))

        WS_OVERLAPPEDWINDOW = 0x00CF0000
        hwnd = NativePreview.user32.CreateWindowExW(
            0, wc.lpszClassName, title, WS_OVERLAPPEDWINDOW,
            200, 200, 600, 400, None, None, wc.hInstance, None
        )
        if not hwnd:
            return False

        NativePreview._open_hwnds.append(hwnd)
        NativePreview.user32.SetMenu(hwnd, hmenu)
        NativePreview.user32.ShowWindow(hwnd, 1)
        NativePreview.user32.UpdateWindow(hwnd)
        return True

# ---------- UI panes ----------
class ImagePane(QtWidgets.QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.lbl = QtWidgets.QLabel()
        self.lbl.setAlignment(QtCore.Qt.AlignCenter)
        self.setWidget(self.lbl)
    def show_qimage(self, img: QtGui.QImage):
        if img.isNull():
            self.lbl.setText("Invalid image")
        else:
            self.lbl.setPixmap(QtGui.QPixmap.fromImage(img).scaledToWidth(512, QtCore.Qt.SmoothTransformation))

class TextPane(QtWidgets.QPlainTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setWordWrapMode(QtGui.QTextOption.NoWrap)
    def set_text(self, s):
        self.setPlainText(s if isinstance(s, str) else repr(s))

class GroupThumbPane(QtWidgets.QScrollArea):
    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.container = QtWidgets.QWidget()
        self.v = QtWidgets.QVBoxLayout(self.container)
        self.v.setContentsMargins(4,4,4,4)
        self.v.setSpacing(8)
        self.setWidget(self.container)
    def clear(self):
        while self.v.count():
            item = self.v.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
    def add_image(self, qimg: QtGui.QImage, label=None):
        holder = QtWidgets.QVBoxLayout()
        lbl = QtWidgets.QLabel()
        lbl.setAlignment(QtCore.Qt.AlignCenter)
        if not qimg.isNull():
            lbl.setPixmap(QtGui.QPixmap.fromImage(qimg).scaledToWidth(96, QtCore.Qt.SmoothTransformation))
        else:
            lbl.setText("Invalid")
        frame = QtWidgets.QFrame()
        frame.setLayout(holder)
        holder.addWidget(lbl)
        if label:
            cap = QtWidgets.QLabel(label)
            cap.setAlignment(QtCore.Qt.AlignCenter)
            holder.addWidget(cap)
        wrap = QtWidgets.QWidget()
        wrap.setLayout(holder)
        self.v.addWidget(wrap)
        sp = QtWidgets.QSpacerItem(0,0, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.v.addItem(sp)

# ---------- Tree model ----------
class ResTreeModel(QtGui.QStandardItemModel):
    def __init__(self, res_list):
        super().__init__()
        self.setHorizontalHeaderLabels(["Type / Name / Lang", "Info"])
        types = {}
        for r in res_list:
            tkey = r.type_name if r.type_name else str(r.type_id)
            types.setdefault(tkey, {}).setdefault(r.name_str if r.name_str else str(r.name_id), {})[r.lang] = r
        for tkey, names in sorted(types.items()):
            t_item = QtGui.QStandardItem(tkey)
            t_info = QtGui.QStandardItem(f"{len(names)} items")
            t_item.setEditable(False); t_info.setEditable(False)
            for nkey, langs in sorted(names.items()):
                n_item = QtGui.QStandardItem(nkey)
                n_info = QtGui.QStandardItem(f"{len(langs)} langs")
                n_item.setEditable(False); n_info.setEditable(False)
                for lang, r in sorted(langs.items()):
                    l_item = QtGui.QStandardItem(f"lang {lang}")
                    l_item.setData(r)
                    l_item.setEditable(False)
                    l_info = QtGui.QStandardItem(f"{r.size} bytes")
                    l_info.setEditable(False)
                    n_item.appendRow([l_item, l_info])
                t_item.appendRow([n_item, n_item.child(0,1) or QtGui.QStandardItem("")])
            self.appendRow([t_item, t_info])

# ---------- Main window ----------
class MainWin(QtWidgets.QMainWindow):
    def __init__(self, res_list):
        super().__init__()
        self.setWindowTitle("RSRC Viewer (IDA 9.2)")
        self.resize(1100, 700)
        self.res_list = res_list

        # Left: tree
        self.tree = QtWidgets.QTreeView()

        # Model first, always.
        self.model = ResTreeModel(res_list)
        self.tree.setModel(self.model)

        # Start collapsed + read-only
        self.tree.collapseAll()
        self.tree.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tree.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tree.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.tree.setDragDropMode(QtWidgets.QAbstractItemView.NoDragDrop)

        # Explicit selection model so it's never None
        self.sel = QtCore.QItemSelectionModel(self.model)
        self.tree.setSelectionModel(self.sel)

        # Wire signals (do not assign; connect)
        self.sel.selectionChanged.connect(self._on_any_selection_event)   # mouse/kb/programmatic
        self.sel.currentChanged.connect(self._on_current_changed)         # keyboard nav
        self.tree.clicked.connect(self._on_any_selection_event)           # single-clicks

        # Center: main view (auto-switch)
        self.center_stack = QtWidgets.QStackedWidget()
        self.text_pane = TextPane()
        self.image_pane = ImagePane()
        self.center_stack.addWidget(self.text_pane)   # index 0
        self.center_stack.addWidget(self.image_pane)  # index 1

        # Right: group thumbnails (thin)
        self.group_thin = GroupThumbPane()
        self.group_thin.setMinimumWidth(140)
        self.group_thin.setMaximumWidth(200)
        self.group_thin.hide()

        # Layout
        self.split_h = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.split_h.addWidget(self.tree)
        self.split_h.addWidget(self.center_stack)
        self.split_h.addWidget(self.group_thin)
        self.split_h.setStretchFactor(0, 0)
        self.split_h.setStretchFactor(1, 1)
        self.split_h.setStretchFactor(2, 0)

        central = QtWidgets.QWidget()
        v = QtWidgets.QVBoxLayout(central)
        v.addWidget(self.split_h)
        self.setCentralWidget(central)

        # Toolbar action to close preview host windows
        tb = self.addToolBar("RSRC")
        act_close = QtGui.QAction("Close previews", self)
        act_close.triggered.connect(NativePreview.close_all_previews)
        tb.addAction(act_close)

        self.current_res = None
        self._last_render_key = None      # (type_id, name_id_or_str, lang, data_rva, size)
        self._render_guard = False
        self.index_rt_maps()
        
    def _decode_monochrome_cursor(self, blob: bytes) -> QtGui.QImage | None:
        """
        Decode classic RT_CURSOR payload:
          WORD xHotspot, WORD yHotspot, BITMAPINFOHEADER (40), then XOR 1bpp plane,
          then AND 1bpp plane. No palette is present.
        Returns a QImage preview (white bg; black for XOR=1; transparent where AND=1),
        or None if the blob doesn't match this legacy layout.
        """
        try:
            if len(blob) < 4 + 40:
                return None

            # Detect the hotspot prelude:
            # many RT_CURSOR payloads start with 2 WORDs for x/y hotspot,
            # followed by a BITMAPINFOHEADER with biSize == 40.
            xhot = u16(blob, 0)
            yhot = u16(blob, 2)
            off = 4
            biSize = u32(blob, off + 0)
            if biSize != 40:
                # some payloads might omit hotspot; try without it
                off = 0
                if len(blob) < 40 or u32(blob, 0) != 40:
                    return None

            # Parse header
            biWidth   = struct.unpack_from("<i", blob, off + 4)[0]
            biHeightT = struct.unpack_from("<i", blob, off + 8)[0]  # total height (xor+and for icons/cursors)
            biPlanes  = u16(blob, off + 12)
            biBitCnt  = u16(blob, off + 14)

            if biBitCnt != 1 or biWidth <= 0 or biHeightT <= 0:
                # Not a 1-bpp legacy cursor; let other code handle it
                return None

            w = int(biWidth)
            # For (cur|ico) DIB masks, height is XOR+AND stacked
            h = int(abs(biHeightT)) // 2
            if h <= 0:
                return None

            # Row size aligned to 32 bits
            row_bytes = ((w * biBitCnt + 31) // 32) * 4
            xor_size = row_bytes * h
            and_size = row_bytes * h

            bmp_off = off + 40  # BITMAPINFOHEADER only; no palette for 1 bpp in these payloads
            if bmp_off + xor_size + and_size > len(blob):
                return None

            xor_plane = blob[bmp_off : bmp_off + xor_size]
            and_plane = blob[bmp_off + xor_size : bmp_off + xor_size + and_size]

            # Convert 1-bpp bottom-up bitmaps into ARGB32
            # Leftmost pixel is MSB of each byte.
            def get_bit(buf, row, col):
                # bottom-up: file row 0 is bottom
                inv_row = h - 1 - row
                byte_index = inv_row * row_bytes + (col >> 3)
                bit_index  = 7 - (col & 7)
                return 1 if (buf[byte_index] >> bit_index) & 1 else 0

            # BGRA order for QImage.Format_ARGB32
            out = bytearray(w * h * 4)
            p = 0
            for y in range(h):
                for x in range(w):
                    xor_bit = get_bit(xor_plane, y, x)
                    and_bit = get_bit(and_plane, y, x)
                    if and_bit == 1:
                        # AND=1 means transparent in the mask semantics; show transparent pixel
                        out[p+0] = 0
                        out[p+1] = 0
                        out[p+2] = 0
                        out[p+3] = 0
                    else:
                        # AND=0 => opaque. XOR toggles color; we?ll preview XOR=1 as black, XOR=0 as white.
                        if xor_bit:
                            out[p+0] = 0
                            out[p+1] = 0
                            out[p+2] = 0
                            out[p+3] = 255
                        else:
                            out[p+0] = 255
                            out[p+1] = 255
                            out[p+2] = 255
                            out[p+3] = 255
                    p += 4

            # Build QImage; PySide6 expects BGRA bytes for Format_ARGB32
            qimg = QtGui.QImage(out, w, h, w * 4, QtGui.QImage.Format_ARGB32)
            qimg._keepalive = out
            return qimg
        except Exception:
            return None
    def _get_selected_item_col0(self):
        idx = self.sel.currentIndex()
        if not idx.isValid():
            return None
        if idx.column() != 0:
            idx = idx.sibling(idx.row(), 0)
        return self.model.itemFromIndex(idx)

    def _on_any_selection_event(self, *args):
        if self._render_guard:
            return
        item = self._get_selected_item_col0()
        if not item:
            return
        r = item.data()
        if not isinstance(r, ResData):
            return
        # Debounce identical resource picked by overlapping signals
        key = (r.type_id, r.name_id if r.name_id is not None else r.name_str, r.lang, r.data_rva, r.size)
        if key == self._last_render_key:
            return
        self._last_render_key = key
        try:
            self._render_guard = True
            self.current_res = r
            self.render_res(r)
        finally:
            self._render_guard = False


    def _on_current_changed(self, new_idx, old_idx):
        self._on_any_selection_event()

    def index_rt_maps(self):
        self.rt_icon = {}
        self.rt_cursor = {}
        self.group_icon = []
        self.group_cursor = []
        self.string_blocks = []
        self.accels = []
        self.menus = []
        self.dialogs = []
        self.bitmaps = []
        self.version_infos = []
        for r in self.res_list:
            if r.type_name == "ICON":
                if r.name_id is not None:
                    self.rt_icon[r.name_id] = r.raw
            elif r.type_name == "CURSOR":
                if r.name_id is not None:
                    self.rt_cursor[r.name_id] = r.raw
            elif r.type_name == "GROUP_ICON":
                self.group_icon.append(r)
            elif r.type_name == "GROUP_CURSOR":
                self.group_cursor.append(r)
            elif r.type_name == "STRING":
                self.string_blocks.append(r)
            elif r.type_name == "ACCELERATOR":
                self.accels.append(r)
            elif r.type_name == "MENU":
                self.menus.append(r)
            elif r.type_name == "DIALOG":
                self.dialogs.append(r)
            elif r.type_name == "BITMAP":
                self.bitmaps.append(r)
            elif r.type_name == "VERSION":
                self.version_infos.append(r)

    def show_text(self, s):
        self.text_pane.set_text(s)
        self.center_stack.setCurrentWidget(self.text_pane)

    # ---------- Pillow helpers ----------
    @staticmethod
    def _qimage_from_pillow(img: "Image.Image") -> QtGui.QImage:
        if img.mode not in ("RGBA", "RGB"):
            img = img.convert("RGBA")
        else:
            img = img.copy()
        b = img.tobytes()
        w, h = img.size
        if img.mode == "RGBA":
            fmt = QtGui.QImage.Format_RGBA8888
            bpl = 4 * w
        else:
            fmt = QtGui.QImage.Format_RGB888
            bpl = 3 * w
        ba = bytearray(b)  # Python-owned buffer so Qt won't touch freed memory
        qimg = QtGui.QImage(ba, w, h, bpl, fmt)
        qimg._keepalive = ba
        return qimg

    def _show_pillow_bytes(self, data: bytes):
        if Image is None:
            self.show_text("Pillow not installed. Install it in IDA's Python: pip install Pillow")
            return
        try:
            bio = io.BytesIO(data)
            img = Image.open(bio)
            img.load()
            qi = MainWin._qimage_from_pillow(img)
            self.image_pane.show_qimage(qi)
            self.center_stack.setCurrentWidget(self.image_pane)
        except Exception as e:
            self.show_text(f"Image decode failed: {e}")

    # ---------- renderers ----------
    def render_res(self, r: ResData):

        def _make_single_ico(blob: bytes) -> bytes:
            if blob[:8] == b"\x89PNG\r\n\x1a\n":
                w = int.from_bytes(blob[16:20], "big")
                h = int.from_bytes(blob[20:24], "big")
                bpp = 32; planes = 1
            else:
                if len(blob) < 40:
                    return None
                biWidth  = struct.unpack_from("<i", blob, 4)[0]
                biHeight = abs(struct.unpack_from("<i", blob, 8)[0]) // 2 or 1
                planes   = u16(blob, 12)
                bpp      = u16(blob, 14)
                w, h = abs(biWidth), abs(biHeight)
            header = struct.pack("<HHH", 0, 1, 1)
            bWidth  = min(255, w) or 0
            bHeight = min(255, h) or 0
            entry = struct.pack("<BBBBHHII", bWidth, bHeight, 0, 0, planes or 1, bpp or 32, len(blob), 22)
            return header + entry + blob

        def _make_single_cur(blob: bytes, xhot: int = 0, yhot: int = 0) -> bytes:
            if blob[:8] == b"\x89PNG\r\n\x1a\n":
                w = int.from_bytes(blob[16:20], "big")
                h = int.from_bytes(blob[20:24], "big")
            else:
                if len(blob) < 40:
                    return None
                biWidth  = struct.unpack_from("<i", blob, 4)[0]
                biHeight = abs(struct.unpack_from("<i", blob, 8)[0]) // 2 or 1
                w, h = abs(biWidth), abs(biHeight)
            header = struct.pack("<HHH", 0, 2, 1)
            bWidth  = min(255, w) or 0
            bHeight = min(255, h) or 0
            entry = struct.pack("<BBBBHHII", bWidth, bHeight, 0, 0, xhot, yhot, len(blob), 22)
            return header + entry + blob

        self.group_thin.hide()
        self.group_thin.clear()
        t = r.type_name or str(r.type_id)
        log(f"Preview {t} {r.name_str or r.name_id} lang {r.lang}, size {r.size}")
        try:
            if t == "GROUP_ICON":
                _, entries = make_ico_from_group(r.raw, self.rt_icon)
                self.group_thin.show()
                lines = []
                for bWidth, bHeight, bColorCount, _, wPlanes, wBitCount, _sz, img, nID in entries:
                    ico = _make_single_ico(img)
                    if ico and Image:
                        im = Image.open(io.BytesIO(ico)); im.load()
                        qi = MainWin._qimage_from_pillow(im)
                        self.group_thin.add_image(qi, f"{bWidth}x{bHeight} ({bColorCount or 0}) id:{nID}")
                    lines.append(f"{bWidth} x {bHeight} ({bColorCount or 0}) - Ordinal name: {nID}")
                self.show_text("\n".join(lines))

            elif t == "GROUP_CURSOR":
                _, entries = make_cur_from_group(r.raw, self.rt_cursor)
                self.group_thin.show()
                lines = []
                for bWidth, bHeight, bColorCount, _, xhot, yhot, _sz, img, nID in entries:
                    # Try to decode legacy monochrome payloads first
                    qi = self._decode_monochrome_cursor(img)
                    if qi is None or qi.isNull():
                        # PNG or color DIB fallback
                        if img[:8] == b"\x89PNG\r\n\x1a\n":
                            im = Image.open(io.BytesIO(img)); im.load()
                            qi = self._qimage_from_pillow(im)
                        else:
                            try:
                                bmp = self._bmp_from_dib_safe(img)
                                im = Image.open(io.BytesIO(bmp)); im.load()
                                qi = self._qimage_from_pillow(im)
                            except Exception:
                                qi = QtGui.QImage()

                    # Add to the right-hand thumbnail strip
                    if qi and not qi.isNull():
                        self.group_thin.add_image(qi, f"{bWidth}x{bHeight} id:{nID} @({xhot},{yhot})")
                    else:
                        # Show placeholder if decoding failed
                        self.group_thin.add_image(QtGui.QImage(), f"{bWidth}x{bHeight} id:{nID} (unreadable)")

                    lines.append(f"{bWidth} x {bHeight} ({bColorCount or 0}) - Ordinal name: {nID} hotspot=({xhot},{yhot})")

                self.show_text("\n".join(lines))

            elif t == "ICON":
                if r.raw[:8] == b"\x89PNG\r\n\x1a\n":
                    self._show_pillow_bytes(r.raw)
                else:
                    ico = _make_single_ico(r.raw)
                    if ico: self._show_pillow_bytes(ico)
                    else:   self.show_text("Invalid ICON payload")

            elif t == "CURSOR":
                            # 1) Legacy 1-bpp XOR/AND RT_CURSOR payloads (no palette) ? manual decode
                            qi = self._decode_monochrome_cursor(r.raw)
                            if qi is not None and not qi.isNull():
                                self.image_pane.show_qimage(qi)
                                self.center_stack.setCurrentWidget(self.image_pane)
                                return

                            # 2) PNG-backed cursor payload (rare but valid) ? show as image
                            if r.raw[:8] == b"\x89PNG\r\n\x1a\n":
                                self._show_pillow_bytes(r.raw)
                                return

                            # 3) Color DIB cursor payload: wrap into a minimal .CUR container for Pillow
                            def _make_single_cur(blob: bytes, xhot: int = 0, yhot: int = 0) -> bytes | None:
                                # Attempt to read width/height from PNG or DIB header
                                if blob[:8] == b"\x89PNG\r\n\x1a\n":
                                    w = int.from_bytes(blob[16:20], "big")
                                    h = int.from_bytes(blob[20:24], "big")
                                else:
                                    if len(blob) < 40:
                                        return None
                                    # If RT_CURSOR had 2 WORD hotspots, skip them
                                    start = 4 if len(blob) >= 44 and u32(blob, 4) == 40 else 0
                                    if start + 40 > len(blob) or u32(blob, start) != 40:
                                        return None
                                    w = abs(struct.unpack_from("<i", blob, start + 4)[0])
                                    h = abs(struct.unpack_from("<i", blob, start + 8)[0]) // 2 or 1
                                header = struct.pack("<HHH", 0, 2, 1)
                                bWidth  = min(255, w) or 0
                                bHeight = min(255, h) or 0
                                entry = struct.pack("<BBBBHHII", bWidth, bHeight, 0, 0, xhot, yhot, len(blob), 6 + 16)
                                return header + entry + blob

                            cur = _make_single_cur(r.raw)
                            if cur and Image:
                                # Try Pillow with full .CUR container (works for color DIB/PNG)
                                self._show_pillow_bytes(cur)
                            else:
                                # Last resort: text
                                self.show_text("Cursor preview unavailable (unsupported payload layout).")


            elif t == "BITMAP":
                bmp = ensure_bmp_from_dib(r.raw) if r.raw[:2] != b"BM" else r.raw
                if Image:
                    im = Image.open(io.BytesIO(bmp)); im.load()
                    qi = MainWin._qimage_from_pillow(im)
                    self.image_pane.show_qimage(qi)
                    self.center_stack.setCurrentWidget(self.image_pane)
                else:
                    self.show_text("Pillow not installed. Run: pip install Pillow")

            elif t == "STRING":
                block_id = r.name_id if r.name_id is not None else 0
                out = []
                off = 0
                for i in range(16):
                    if off + 2 > len(r.raw): break
                    n = u16(r.raw, off); off += 2
                    if n == 0:
                        out.append(f"{block_id*16 + i:04X}: "); continue
                    nbytes = n * 2
                    s = r.raw[off:off+nbytes].decode("utf-16le", errors="ignore")
                    off += nbytes
                    out.append(f"{block_id*16 + i:04X}: {s}")
                self.show_text("\n".join(out))

            elif t == "ACCELERATOR":
                acc = parse_accelerators(r.raw)
                def flags_to_str(f):
                    parts = []
                    if f & 0x01: parts.append("VIRTKEY")
                    if f & 0x02: parts.append("NOINV")
                    if f & 0x04: parts.append("SHIFT")
                    if f & 0x08: parts.append("CTRL")
                    if f & 0x10: parts.append("ALT")
                    if f & 0x80: parts.append("END")
                    return "|".join(parts) if parts else "0"
                text = "\n".join(f"{flags_to_str(f):<20} key=0x{key:04X} cmd=0x{cmd:04X}" for f, key, cmd in acc)
                self.show_text(text)

            elif t == "VERSION":
                vi = parse_version_info(r.raw)
                lines = []
                if vi.fixed:
                    fv = f'{vi.fixed["FileVersionMS"]>>16}.{vi.fixed["FileVersionMS"]&0xFFFF}.{vi.fixed["FileVersionLS"]>>16}.{vi.fixed["FileVersionLS"]&0xFFFF}'
                    pv = f'{vi.fixed["ProductVersionMS"]>>16}.{vi.fixed["ProductVersionMS"]&0xFFFF}.{vi.fixed["ProductVersionLS"]>>16}.{vi.fixed["ProductVersionLS"]&0xFFFF}'
                    lines.append(f"FileVersion: {fv}")
                    lines.append(f"ProductVersion: {pv}")
                for k, v in sorted(vi.string_table.items()):
                    lines.append(f"{k}: {v}")
                if "Translation" in vi.var:
                    lines.append("Translation: " + ",".join(f"{lang:04x}-{cp:04x}" for lang, cp in vi.var["Translation"]))
                self.show_text("\n".join(lines))

            elif t == "DIALOG":
                # hard kill any floating-preview paths that draw controls
                try:
                    self.imagePane.setVisible(False)
                    self.tablePane.setVisible(False)
                    self.textPane.setVisible(True)   # only show RC text
                    self.clear_any_qt_overlay_widgets()  # no-ops if you don?t have this
                except Exception:
                    pass

                # show RC dump for context only
                rc = rc_dump_dialog(r.raw)
                self.show_text(rc)

                # ensure we close prior native previews
                try:
                    NativePreview.close_all_previews()
                except Exception:
                    pass

                # use hosted native dialog only
                ok = NativePreview.preview_dialog_hosted(
                    r.raw,
                    title=f"Dialog: {r.name_str or r.name_id}"
                )
                if not ok:
                    self.show_text("Dialog preview failed (malformed template or missing ACCEL/CLASS).")



            elif t == "MENU":
                # Close previously opened preview windows so we don't spawn multiples
                try:
                    NativePreview.close_all_previews()
                except Exception:
                    pass

                rc = rc_dump_menu(r.raw)
                self.show_text(rc)
                if not NativePreview.preview_menu_window(
                    r.raw, title=f"Menu: {r.name_str or r.name_id}"
                ):
                    self.show_text("Menu preview failed (template may be malformed).")

            else:
                self.show_text(f"{t} size={r.size}\n\n{r.raw[:256].hex(' ')}" + (" ..." if r.size > 256 else ""))
        except Exception as e:
            self.show_text(f"Error rendering: {e}\n{traceback.format_exc()}")

# ---------- entrypoint ----------
RSRC_VIEWER_WIN = None

def run():
    global RSRC_VIEWER_WIN
    try:
        log("Building resource index...")
        res = parse_resource_tree()
        app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv)
        QtWidgets.QApplication.setQuitOnLastWindowClosed(False)
        if RSRC_VIEWER_WIN is not None and RSRC_VIEWER_WIN.isVisible():
            RSRC_VIEWER_WIN.raise_()
            RSRC_VIEWER_WIN.activateWindow()
            return
        w = MainWin(res)
        RSRC_VIEWER_WIN = w
        w.setAttribute(QtCore.Qt.WA_DeleteOnClose, False)
        g = QtWidgets.QApplication.primaryScreen().availableGeometry()
        w.resize(min(1100, g.width() - 100), min(700, g.height() - 100))
        w.move(g.center() - w.frameGeometry().center())
        w.show()
        w.raise_()
        w.activateWindow()
        log("Viewer ready.")
    except Exception as e:
        ida_kernwin.warning(f"RSRC viewer failed:\n{e}\n{traceback.format_exc()}")

def init(self):
    try:
        ACTION_NAME = "rsrc_viewer:open"
        class Handler(ida_kernwin.action_handler_t):
            def __init__(self): ida_kernwin.action_handler_t.__init__(self)
            def activate(self, ctx): run(); return 1
            def update(self, ctx): return ida_kernwin.AST_ENABLE_ALWAYS

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                ACTION_NAME, "RSRC Viewer", Handler(), self.wanted_hotkey, "Open the RSRC Viewer"
            )
        )
        ida_kernwin.attach_action_to_menu("View/RSRC Viewer", ACTION_NAME, ida_kernwin.SETMENU_APP)
    except Exception:
        pass
    return idaapi.PLUGIN_KEEP


class rsrc_viewer_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Resource Viewer for PE resources"
    help = "Browse and preview .rsrc contents: icons, cursors, dialogs, menus, strings, version, bitmaps"
    wanted_name = "RSRC Viewer"
    wanted_hotkey = "Ctrl-Alt-R"

    def init(self):
        # If you want a menu item under View, you can also register an action here.
        # Minimal init is fine; IDA will list this under Plugins automatically.
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        # Call the existing GUI entrypoint
        try:
            run()
        except Exception as e:
            ida_kernwin.warning(f"RSRC viewer failed: {e}")

    def term(self):
        # Optional: close preview host windows if you?re being neat
        try:
            from __main__ import NativePreview  # if top-level
        except Exception:
            try:
                # Same module scope if imported as a plugin
                NativePreview.close_all_previews()
            except Exception:
                pass

def PLUGIN_ENTRY():
    return rsrc_viewer_plugin_t()
    
if __name__ == "__main__":
    log("Launching RSRC Viewer...")
    run()
