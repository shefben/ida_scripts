# ida93_arm_linux_secondpass.py
# IDA Pro 9.3 / Python 3.13 plugin
# Second-pass recovery for ARM/AArch64 Linux ELF binaries.
#
# Drop this file into your IDA 9.3 plugins directory, restart IDA, then run:
#   Edit -> Plugins -> ARM Linux Second Pass
# or run it as a script with File -> Script file...

from __future__ import annotations

import json
import os
import time
import traceback
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

import ida_auto
import ida_bytes
import ida_entry
import ida_fixup
import ida_funcs
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_lines
import ida_loader
import ida_name
import ida_nalt
import ida_offset
import ida_segment
import ida_segregs
import ida_strlist
import ida_ua
import ida_undo
import ida_xref
import idautils
import idc

BADADDR = ida_idaapi.BADADDR
PLUGIN_NAME = "ARM Linux Second Pass"
PLUGIN_VERSION = "1.0.0"
LOG_PREFIX = "[arm-linux-secondpass]"


@dataclass
class SecondPassConfig:
    # General behavior
    create_undo_point: bool = True
    ask_before_run: bool = True
    rename_auto_items: bool = True
    rebuild_string_list: bool = True
    run_final_autoanalysis: bool = True
    create_report_file: bool = True

    # Function discovery
    enable_entry_recovery: bool = True
    enable_fixup_recovery: bool = True
    enable_data_pointer_recovery: bool = True
    enable_arm_exidx_recovery: bool = True
    enable_eh_frame_hdr_recovery: bool = True
    enable_prologue_sweep: bool = True
    prologue_sweep_stride_aarch64: int = 4
    prologue_sweep_stride_arm32: int = 2
    max_prologue_candidates_per_segment: int = 50000

    # Vtable / pointer table discovery
    enable_vtable_recovery: bool = True
    min_vtable_functions: int = 2
    min_raw_fnptr_table: int = 3
    max_vtable_span_ptrs: int = 512
    max_abs_offset_to_top: int = 0x100000

    # String discovery
    enable_string_recovery: bool = True
    min_ascii_len: int = 5
    min_utf16_chars: int = 5
    max_string_len: int = 0x4000
    only_strings_with_alpha_or_path_chars: bool = True

    # Safety/performance
    scan_writable_segments_for_strings: bool = True
    scan_executable_segments_for_strings: bool = False
    scan_bss_segments: bool = False
    pointer_scan_alignment: int = 0  # 0 means pointer-size alignment
    chunk_size: int = 8 * 1024 * 1024
    progress_every_seconds: float = 0.50


@dataclass
class Stats:
    segments_seen: int = 0
    exec_segments: int = 0
    data_segments: int = 0
    entries_processed: int = 0
    fixups_processed: int = 0
    arm_exidx_entries: int = 0
    eh_frame_hdr_entries: int = 0
    pointer_slots_seen: int = 0
    pointer_slots_to_code: int = 0
    pointer_slots_to_data: int = 0
    pointers_made: int = 0
    functions_created: int = 0
    functions_already_existing: int = 0
    function_candidates_rejected: int = 0
    prologue_candidates: int = 0
    prologue_functions_created: int = 0
    strings_created_ascii: int = 0
    strings_created_utf16: int = 0
    vtables_found: int = 0
    fnptr_tables_found: int = 0
    names_set: int = 0
    errors: List[str] = field(default_factory=list)
    interesting: Dict[str, List[str]] = field(default_factory=lambda: {
        "functions": [],
        "vtables": [],
        "fnptr_tables": [],
        "strings": [],
    })


class Cancelled(Exception):
    pass


class SecondPassAnalyzer:
    def __init__(self, cfg: Optional[SecondPassConfig] = None):
        self.cfg = cfg or SecondPassConfig()
        self.stats = Stats()
        self.ptr_size = 8 if ida_ida.inf_is_64bit() else 4
        self.endian = "big" if ida_ida.inf_is_be() else "little"
        self.arch_name = (ida_idp.get_idp_name() or "").lower()
        self.is_aarch64 = self.ptr_size == 8 or "arm64" in self.arch_name or "aarch64" in self.arch_name
        self.is_arm32 = not self.is_aarch64 and "arm" in self.arch_name
        self.exec_ranges: List[Tuple[int, int, str]] = []
        self.data_ranges: List[Tuple[int, int, str]] = []
        self.all_ranges: List[Tuple[int, int, str]] = []
        self.created_funcs: Set[int] = set()
        self.ptr_code_targets: Set[int] = set()
        self.last_progress = 0.0

    # ---------- logging / progress ----------

    def msg(self, text: str) -> None:
        ida_kernwin.msg(f"{LOG_PREFIX} {text}\n")

    def progress(self, text: str, force: bool = False) -> None:
        now = time.monotonic()
        if force or now - self.last_progress >= self.cfg.progress_every_seconds:
            self.last_progress = now
            try:
                ida_kernwin.replace_wait_box(f"HIDECANCEL\n{PLUGIN_NAME}\n{text}")
            except Exception:
                pass
            self.msg(text)
            self.check_cancel()

    def check_cancel(self) -> None:
        try:
            if ida_kernwin.user_cancelled():
                raise Cancelled()
        except Cancelled:
            raise
        except Exception:
            pass

    # ---------- segment helpers ----------

    def iter_segments(self) -> Iterable[ida_segment.segment_t]:
        qty = ida_segment.get_segm_qty()
        for i in range(qty):
            seg = ida_segment.getnseg(i)
            if seg is not None:
                yield seg

    def seg_name(self, seg: ida_segment.segment_t) -> str:
        try:
            return ida_segment.get_segm_name(seg) or ""
        except Exception:
            return ""

    def is_exec_seg(self, seg: ida_segment.segment_t) -> bool:
        try:
            return bool(seg.perm & ida_segment.SEGPERM_EXEC) or ida_segment.segtype(seg.start_ea) == ida_segment.SEG_CODE
        except Exception:
            return False

    def is_bss_seg(self, seg: ida_segment.segment_t) -> bool:
        name = self.seg_name(seg).lower()
        try:
            st = ida_segment.segtype(seg.start_ea)
            if st in (ida_segment.SEG_BSS, ida_segment.SEG_UNDF):
                return True
        except Exception:
            pass
        return name in (".bss", ".tbss") or name.endswith(".bss") or "nobits" in name

    def is_readable_data_seg(self, seg: ida_segment.segment_t) -> bool:
        if self.is_bss_seg(seg) and not self.cfg.scan_bss_segments:
            return False
        if self.is_exec_seg(seg) and not self.cfg.scan_executable_segments_for_strings:
            return False
        if not self.cfg.scan_writable_segments_for_strings:
            try:
                if seg.perm & ida_segment.SEGPERM_WRITE:
                    return False
            except Exception:
                pass
        try:
            if seg.perm and not (seg.perm & ida_segment.SEGPERM_READ):
                return False
        except Exception:
            pass
        return True

    def index_segments(self) -> None:
        self.exec_ranges.clear()
        self.data_ranges.clear()
        self.all_ranges.clear()
        for seg in self.iter_segments():
            self.stats.segments_seen += 1
            name = self.seg_name(seg)
            start, end = int(seg.start_ea), int(seg.end_ea)
            self.all_ranges.append((start, end, name))
            if self.is_exec_seg(seg):
                self.exec_ranges.append((start, end, name))
                self.stats.exec_segments += 1
            elif self.is_readable_data_seg(seg):
                self.data_ranges.append((start, end, name))
                self.stats.data_segments += 1

    def range_contains(self, ranges: Sequence[Tuple[int, int, str]], ea: int) -> bool:
        # Segment count is normally tiny. Linear scan is faster than building a fancier monument to overengineering.
        for start, end, _name in ranges:
            if start <= ea < end:
                return True
        return False

    def get_range_name(self, ea: int) -> str:
        for start, end, name in self.all_ranges:
            if start <= ea < end:
                return name
        return ""

    def is_mapped(self, ea: int) -> bool:
        return self.range_contains(self.all_ranges, ea)

    def is_exec_ea(self, ea: int) -> bool:
        return self.range_contains(self.exec_ranges, ea)

    def is_data_ea(self, ea: int) -> bool:
        return self.range_contains(self.data_ranges, ea)

    def read_seg_bytes(self, seg: ida_segment.segment_t) -> bytes:
        start, end = int(seg.start_ea), int(seg.end_ea)
        size = max(0, end - start)
        out = bytearray()
        off = 0
        while off < size:
            self.check_cancel()
            take = min(self.cfg.chunk_size, size - off)
            chunk = ida_bytes.get_bytes(start + off, take)
            if chunk is None:
                # get_bytes() can fail on unloaded holes. Fill with zeros so offsets stay sane.
                chunk = b"\x00" * take
            out.extend(chunk)
            off += take
        return bytes(out)

    # ---------- decoding helpers ----------

    def read_ptr_from_buf(self, buf: bytes, off: int) -> int:
        return int.from_bytes(buf[off: off + self.ptr_size], self.endian, signed=False)

    def sign_extend(self, value: int, bits: int) -> int:
        sign = 1 << (bits - 1)
        return (value ^ sign) - sign

    def normalize_code_ptr(self, value: int) -> Tuple[Optional[int], bool]:
        """Return (real_ea, thumb). Thumb bit is valid only for 32-bit ARM."""
        if value in (0, BADADDR, (1 << (self.ptr_size * 8)) - 1):
            return None, False

        thumb = False
        ea = int(value)
        if self.is_arm32 and (ea & 1):
            ea &= ~1
            thumb = True

        if self.is_exec_ea(ea):
            return ea, thumb
        return None, False

    def plausible_code_target(self, ea: int) -> bool:
        if not self.is_exec_ea(ea):
            return False
        try:
            if not ida_bytes.is_loaded(ea):
                return False
        except Exception:
            pass
        try:
            return bool(ida_ua.can_decode(ea))
        except Exception:
            try:
                insn = ida_ua.insn_t()
                return ida_ua.decode_insn(insn, ea) > 0
            except Exception:
                return False

    def set_thumb_at(self, ea: int) -> None:
        if not self.is_arm32:
            return
        try:
            idc.split_sreg_range(ea, "T", 1, idc.SR_user)
        except Exception:
            try:
                reg = ida_idp.str2sreg("T")
                if reg != -1:
                    ida_segregs.split_sreg_range(ea, reg, 1, ida_segregs.SR_user)
            except Exception:
                pass

    def get_item_end(self, ea: int) -> int:
        try:
            size = ida_bytes.get_item_size(ea)
            if size <= 0:
                return ea + 1
            return ea + size
        except Exception:
            return ea + 1

    def is_existing_function_start(self, ea: int) -> bool:
        f = ida_funcs.get_func(ea)
        return bool(f and int(f.start_ea) == ea)

    def safe_name(self, prefix: str, ea: int) -> str:
        return f"{prefix}_{ea:0{self.ptr_size * 2}X}"

    def set_auto_name(self, ea: int, name: str) -> bool:
        if not self.cfg.rename_auto_items:
            return False
        try:
            old = ida_name.get_name(ea) or ""
            if old and not old.startswith(("sub_", "loc_", "unk_", "off_", "qword_", "dword_", "word_", "byte_")):
                return False
            ok = ida_name.set_name(ea, name, ida_name.SN_AUTO | ida_name.SN_NOCHECK | ida_name.SN_NOWARN)
            if ok:
                self.stats.names_set += 1
            return bool(ok)
        except Exception:
            return False

    def make_code_and_function(self, ea: int, reason: str, thumb: bool = False, from_prologue: bool = False) -> bool:
        if ea is None or ea == BADADDR:
            self.stats.function_candidates_rejected += 1
            return False
        ea = int(ea)
        if not self.plausible_code_target(ea):
            self.stats.function_candidates_rejected += 1
            return False

        existing = ida_funcs.get_func(ea)
        if existing:
            if int(existing.start_ea) == ea:
                self.stats.functions_already_existing += 1
                return False
            # Don't split existing functions. That is how databases become confetti.
            self.stats.function_candidates_rejected += 1
            return False

        if thumb:
            self.set_thumb_at(ea)

        flags = ida_bytes.get_full_flags(ea)
        if not ida_bytes.is_code(flags):
            # For pointer-confirmed targets, allow fixing stale data in executable segments.
            # For prologue sweep, be conservative and only touch unknown bytes.
            if from_prologue and not ida_bytes.is_unknown(flags):
                self.stats.function_candidates_rejected += 1
                return False
            try:
                if not ida_bytes.is_unknown(flags):
                    ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, ida_bytes.get_item_size(ea))
                if ida_ua.create_insn(ea) <= 0:
                    self.stats.function_candidates_rejected += 1
                    return False
            except Exception:
                self.stats.function_candidates_rejected += 1
                return False

        ok = False
        try:
            ida_auto.auto_make_proc(ea)
            ida_auto.auto_wait_range(ea, min(ea + 0x1000, ida_segment.getseg(ea).end_ea if ida_segment.getseg(ea) else ea + 0x1000))
            ok = self.is_existing_function_start(ea)
        except Exception:
            ok = False

        if not ok:
            try:
                ok = bool(ida_funcs.add_func(ea))
            except Exception:
                ok = False

        if ok:
            self.created_funcs.add(ea)
            self.stats.functions_created += 1
            if from_prologue:
                self.stats.prologue_functions_created += 1
            self.set_auto_name(ea, self.safe_name("sp_func", ea))
            if len(self.stats.interesting["functions"]) < 500:
                self.stats.interesting["functions"].append(f"0x{ea:X} {reason}")
            return True

        self.stats.function_candidates_rejected += 1
        return False

    # ---------- pointer/data helpers ----------

    def make_ptr_data(self, ea: int, target: Optional[int] = None) -> bool:
        flags = ida_bytes.get_full_flags(ea)
        if ida_bytes.is_code(flags) or ida_bytes.is_strlit(flags):
            return False
        try:
            if self.ptr_size == 8:
                ok = ida_bytes.create_qword(ea, 8, True)
            else:
                ok = ida_bytes.create_dword(ea, 4, True)
        except Exception:
            ok = False
        if ok:
            self.stats.pointers_made += 1
            try:
                ida_offset.op_plain_offset(ea, 0, 0)
            except Exception:
                pass
            if target is not None and target != BADADDR:
                try:
                    ida_xref.add_dref(ea, target, ida_xref.dr_O)
                except Exception:
                    pass
            return True
        return False


    def segment_likely_contains_pointers(self, name: str) -> bool:
        n = (name or "").lower()
        pointerish = (
            ".got", ".data", ".data.rel", ".data.rel.ro", ".rodata",
            ".init_array", ".fini_array", ".preinit_array", ".ctors", ".dtors",
            ".dynamic", ".jcr", ".tdata", "rel.ro", "vtable", "rtti"
        )
        return any(x in n for x in pointerish)

    def process_pointer_slot(self, ea: int, value: int, reason: str, make_data: bool = True, allow_data_targets: bool = False) -> Optional[int]:
        self.stats.pointer_slots_seen += 1
        target, thumb = self.normalize_code_ptr(value)
        if target is not None:
            self.stats.pointer_slots_to_code += 1
            self.ptr_code_targets.add(target)
            if make_data:
                self.make_ptr_data(ea, target)
            self.make_code_and_function(target, reason, thumb=thumb)
            return target

        raw_target = int(value)
        if allow_data_targets and raw_target and self.is_mapped(raw_target):
            self.stats.pointer_slots_to_data += 1
            if make_data:
                self.make_ptr_data(ea, raw_target)
            return raw_target
        return None

    # ---------- recovery passes ----------

    def recover_entries(self) -> None:
        if not self.cfg.enable_entry_recovery:
            return
        self.progress("Recovering entry/export functions...", True)
        try:
            qty = ida_entry.get_entry_qty()
            for i in range(qty):
                self.check_cancel()
                ord_ = ida_entry.get_entry_ordinal(i)
                ea = ida_entry.get_entry(ord_)
                if ea == BADADDR:
                    continue
                self.stats.entries_processed += 1
                target, thumb = self.normalize_code_ptr(ea)
                if target is None and self.is_exec_ea(ea):
                    target, thumb = int(ea), False
                if target is not None:
                    self.make_code_and_function(target, "entry/export", thumb=thumb)
        except Exception as exc:
            self.record_error("entries", exc)

    def recover_named_exec_locations(self) -> None:
        self.progress("Recovering named executable locations...", True)
        try:
            for ea, name in idautils.Names():
                self.check_cancel()
                if self.is_exec_ea(int(ea)) and not ida_funcs.get_func(ea):
                    self.make_code_and_function(int(ea), f"named location {name}")
        except Exception as exc:
            self.record_error("named exec locations", exc)

    def recover_fixups(self) -> None:
        if not self.cfg.enable_fixup_recovery:
            return
        self.progress("Recovering code targets from fixups/relocations...", True)
        try:
            ea = ida_fixup.get_first_fixup_ea()
            fd = ida_fixup.fixup_data_t()
            while ea != BADADDR:
                self.check_cancel()
                self.stats.fixups_processed += 1
                if ida_fixup.get_fixup(fd, ea):
                    target = int(fd.off)
                    self.process_pointer_slot(int(ea), target, "fixup/relocation", make_data=True, allow_data_targets=True)
                ea = ida_fixup.get_next_fixup_ea(ea)
        except Exception as exc:
            self.record_error("fixups", exc)

    def recover_data_pointers(self) -> None:
        if not self.cfg.enable_data_pointer_recovery:
            return
        self.progress("Scanning data segments for code/data pointers...", True)
        align = self.cfg.pointer_scan_alignment or self.ptr_size
        for seg in self.iter_segments():
            if self.is_bss_seg(seg) and not self.cfg.scan_bss_segments:
                continue
            if self.is_exec_seg(seg):
                continue
            try:
                name = self.seg_name(seg)
                buf = self.read_seg_bytes(seg)
                base = int(seg.start_ea)
                first = (-base) % align
                allow_data_targets = self.segment_likely_contains_pointers(name)
                self.progress(f"Pointer scan {name or hex(base)}")
                for off in range(first, max(0, len(buf) - self.ptr_size + 1), align):
                    self.check_cancel()
                    value = self.read_ptr_from_buf(buf, off)
                    if value == 0:
                        continue
                    self.process_pointer_slot(base + off, value, f"data pointer in {name}", make_data=True, allow_data_targets=allow_data_targets)
            except Cancelled:
                raise
            except Exception as exc:
                self.record_error(f"data pointer scan {self.seg_name(seg)}", exc)

    def recover_arm_exidx(self) -> None:
        if not self.cfg.enable_arm_exidx_recovery or not self.is_arm32:
            return
        for seg in self.iter_segments():
            name = self.seg_name(seg)
            if name != ".ARM.exidx" and not name.endswith("ARM.exidx"):
                continue
            self.progress(f"Parsing {name} unwind index...", True)
            try:
                buf = self.read_seg_bytes(seg)
                base = int(seg.start_ea)
                for off in range(0, len(buf) - 7, 8):
                    self.check_cancel()
                    raw = int.from_bytes(buf[off:off + 4], self.endian, signed=False)
                    # ELF for ARM uses PREL31: signed 31-bit offset from the word itself.
                    disp = self.sign_extend(raw & 0x7FFFFFFF, 31)
                    target = (base + off + disp) & 0xFFFFFFFF
                    if self.is_exec_ea(target):
                        self.stats.arm_exidx_entries += 1
                        self.make_ptr_data(base + off, target)
                        self.make_code_and_function(target, ".ARM.exidx PREL31")
            except Exception as exc:
                self.record_error("ARM.exidx", exc)

    # ----- .eh_frame_hdr support -----

    DW_EH_PE_omit = 0xFF
    DW_EH_PE_absptr = 0x00
    DW_EH_PE_uleb128 = 0x01
    DW_EH_PE_udata2 = 0x02
    DW_EH_PE_udata4 = 0x03
    DW_EH_PE_udata8 = 0x04
    DW_EH_PE_sleb128 = 0x09
    DW_EH_PE_sdata2 = 0x0A
    DW_EH_PE_sdata4 = 0x0B
    DW_EH_PE_sdata8 = 0x0C
    DW_EH_PE_pcrel = 0x10
    DW_EH_PE_textrel = 0x20
    DW_EH_PE_datarel = 0x30
    DW_EH_PE_funcrel = 0x40
    DW_EH_PE_aligned = 0x50
    DW_EH_PE_indirect = 0x80

    def read_uleb(self, buf: bytes, off: int) -> Tuple[int, int]:
        result = 0
        shift = 0
        while off < len(buf):
            b = buf[off]
            off += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                return result, off
            shift += 7
        raise ValueError("truncated uleb128")

    def read_sleb(self, buf: bytes, off: int) -> Tuple[int, int]:
        result = 0
        shift = 0
        size = self.ptr_size * 8
        while off < len(buf):
            b = buf[off]
            off += 1
            result |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                if shift < size and (b & 0x40):
                    result |= -1 << shift
                return result, off
        raise ValueError("truncated sleb128")

    def decode_eh_value(self, buf: bytes, off: int, enc: int, section_base: int, datarel_base: int) -> Tuple[Optional[int], int]:
        if enc == self.DW_EH_PE_omit:
            return None, off

        fmt = enc & 0x0F
        app = enc & 0x70
        start_off = off

        if app == self.DW_EH_PE_aligned:
            # Align to pointer size relative to section start.
            off = (off + self.ptr_size - 1) & ~(self.ptr_size - 1)
            start_off = off

        if fmt == self.DW_EH_PE_absptr:
            size = self.ptr_size
            value = int.from_bytes(buf[off:off + size], self.endian, signed=False)
            off += size
        elif fmt == self.DW_EH_PE_uleb128:
            value, off = self.read_uleb(buf, off)
        elif fmt == self.DW_EH_PE_sleb128:
            value, off = self.read_sleb(buf, off)
        elif fmt == self.DW_EH_PE_udata2:
            value = int.from_bytes(buf[off:off + 2], self.endian, signed=False)
            off += 2
        elif fmt == self.DW_EH_PE_udata4:
            value = int.from_bytes(buf[off:off + 4], self.endian, signed=False)
            off += 4
        elif fmt == self.DW_EH_PE_udata8:
            value = int.from_bytes(buf[off:off + 8], self.endian, signed=False)
            off += 8
        elif fmt == self.DW_EH_PE_sdata2:
            value = int.from_bytes(buf[off:off + 2], self.endian, signed=True)
            off += 2
        elif fmt == self.DW_EH_PE_sdata4:
            value = int.from_bytes(buf[off:off + 4], self.endian, signed=True)
            off += 4
        elif fmt == self.DW_EH_PE_sdata8:
            value = int.from_bytes(buf[off:off + 8], self.endian, signed=True)
            off += 8
        else:
            raise ValueError(f"unsupported DW_EH_PE format 0x{fmt:X}")

        field_ea = section_base + start_off
        if app == self.DW_EH_PE_pcrel:
            value = field_ea + value
        elif app == self.DW_EH_PE_datarel:
            value = datarel_base + value
        elif app == self.DW_EH_PE_absptr:
            pass
        elif app in (self.DW_EH_PE_textrel, self.DW_EH_PE_funcrel):
            # There is no portable public base for these here; most Linux ELF .eh_frame_hdr files use pcrel/datarel.
            raise ValueError(f"unsupported DW_EH_PE application 0x{app:X}")

        if enc & self.DW_EH_PE_indirect:
            if self.ptr_size == 8:
                value = ida_bytes.get_qword(value)
            else:
                value = ida_bytes.get_wide_dword(value)

        return int(value), off

    def recover_eh_frame_hdr(self) -> None:
        if not self.cfg.enable_eh_frame_hdr_recovery:
            return
        for seg in self.iter_segments():
            name = self.seg_name(seg)
            if name != ".eh_frame_hdr" and not name.endswith("eh_frame_hdr"):
                continue
            self.progress(f"Parsing {name} binary-search FDE table...", True)
            try:
                buf = self.read_seg_bytes(seg)
                if len(buf) < 4:
                    continue
                version = buf[0]
                if version != 1:
                    continue
                eh_frame_ptr_enc = buf[1]
                fde_count_enc = buf[2]
                table_enc = buf[3]
                base = int(seg.start_ea)
                off = 4
                _eh_frame_ptr, off = self.decode_eh_value(buf, off, eh_frame_ptr_enc, base, base)
                fde_count, off = self.decode_eh_value(buf, off, fde_count_enc, base, base)
                if fde_count is None or fde_count <= 0 or fde_count > 10_000_000:
                    continue
                for _ in range(int(fde_count)):
                    self.check_cancel()
                    pc, off = self.decode_eh_value(buf, off, table_enc, base, base)
                    _fde, off = self.decode_eh_value(buf, off, table_enc, base, base)
                    if pc is None:
                        continue
                    target, thumb = self.normalize_code_ptr(pc)
                    if target is None and self.is_exec_ea(int(pc)):
                        target, thumb = int(pc), False
                    if target is not None:
                        self.stats.eh_frame_hdr_entries += 1
                        self.make_code_and_function(target, ".eh_frame_hdr FDE", thumb=thumb)
            except Exception as exc:
                self.record_error("eh_frame_hdr", exc)

    def recover_vtables(self) -> None:
        if not self.cfg.enable_vtable_recovery:
            return
        self.progress("Scanning for Itanium C++ vtables and raw function-pointer tables...", True)
        align = self.cfg.pointer_scan_alignment or self.ptr_size
        for seg in self.iter_segments():
            if self.is_exec_seg(seg) or (self.is_bss_seg(seg) and not self.cfg.scan_bss_segments):
                continue
            name = self.seg_name(seg)
            try:
                buf = self.read_seg_bytes(seg)
                base = int(seg.start_ea)
                first = (-base) % align
                off = first
                while off <= len(buf) - self.ptr_size:
                    self.check_cancel()
                    ea = base + off

                    vt_len = self.detect_itanium_vtable(buf, off, base)
                    if vt_len >= self.cfg.min_vtable_functions:
                        self.mark_itanium_vtable(ea, vt_len, name, buf, off, base)
                        off += max((2 + vt_len) * self.ptr_size, self.ptr_size)
                        continue

                    table_len = self.detect_raw_fnptr_table(buf, off, base)
                    if table_len >= self.cfg.min_raw_fnptr_table:
                        self.mark_raw_fnptr_table(ea, table_len, name, buf, off, base)
                        off += max(table_len * self.ptr_size, self.ptr_size)
                        continue

                    off += align
            except Cancelled:
                raise
            except Exception as exc:
                self.record_error(f"vtable scan {name}", exc)

    def detect_itanium_vtable(self, buf: bytes, off: int, base: int) -> int:
        ps = self.ptr_size
        if off + (2 + self.cfg.min_vtable_functions) * ps > len(buf):
            return 0
        raw_offset = self.read_ptr_from_buf(buf, off)
        signed_offset = int.from_bytes(buf[off:off + ps], self.endian, signed=True)
        if abs(signed_offset) > self.cfg.max_abs_offset_to_top:
            return 0

        typeinfo = self.read_ptr_from_buf(buf, off + ps)
        # Itanium ABI typeinfo pointer is often 0 in stripped/no-rtti builds, or a data pointer.
        if typeinfo != 0 and not self.is_mapped(typeinfo):
            return 0

        count = 0
        scan = off + 2 * ps
        while scan + ps <= len(buf) and count < self.cfg.max_vtable_span_ptrs:
            value = self.read_ptr_from_buf(buf, scan)
            target, _thumb = self.normalize_code_ptr(value)
            if target is None or not self.plausible_code_target(target):
                break
            count += 1
            scan += ps
        return count

    def detect_raw_fnptr_table(self, buf: bytes, off: int, base: int) -> int:
        ps = self.ptr_size
        count = 0
        scan = off
        while scan + ps <= len(buf) and count < self.cfg.max_vtable_span_ptrs:
            value = self.read_ptr_from_buf(buf, scan)
            target, _thumb = self.normalize_code_ptr(value)
            if target is None or not self.plausible_code_target(target):
                break
            count += 1
            scan += ps
        return count

    def mark_itanium_vtable(self, ea: int, fn_count: int, seg_name: str, buf: bytes, off: int, base: int) -> None:
        ps = self.ptr_size
        self.stats.vtables_found += 1
        self.set_auto_name(ea, self.safe_name("sp_vtable_hdr", ea))
        address_point = ea + 2 * ps
        self.set_auto_name(address_point, self.safe_name("sp_vtable", address_point))
        if len(self.stats.interesting["vtables"]) < 500:
            self.stats.interesting["vtables"].append(f"0x{ea:X} funcs={fn_count} seg={seg_name}")

        # offset-to-top as raw pointer-sized integer; typeinfo and function slots as offsets.
        try:
            if ps == 8:
                ida_bytes.create_qword(ea, 8, True)
            else:
                ida_bytes.create_dword(ea, 4, True)
        except Exception:
            pass
        typeinfo = self.read_ptr_from_buf(buf, off + ps)
        if typeinfo:
            self.make_ptr_data(ea + ps, typeinfo)

        for i in range(fn_count):
            slot_ea = address_point + i * ps
            value = self.read_ptr_from_buf(buf, off + (2 + i) * ps)
            target, thumb = self.normalize_code_ptr(value)
            if target is None:
                continue
            self.make_ptr_data(slot_ea, target)
            self.make_code_and_function(target, f"vtable slot @ 0x{slot_ea:X}", thumb=thumb)

    def mark_raw_fnptr_table(self, ea: int, fn_count: int, seg_name: str, buf: bytes, off: int, base: int) -> None:
        ps = self.ptr_size
        self.stats.fnptr_tables_found += 1
        self.set_auto_name(ea, self.safe_name("sp_fnptr_table", ea))
        if len(self.stats.interesting["fnptr_tables"]) < 500:
            self.stats.interesting["fnptr_tables"].append(f"0x{ea:X} funcs={fn_count} seg={seg_name}")
        for i in range(fn_count):
            slot_ea = ea + i * ps
            value = self.read_ptr_from_buf(buf, off + i * ps)
            target, thumb = self.normalize_code_ptr(value)
            if target is None:
                continue
            self.make_ptr_data(slot_ea, target)
            self.make_code_and_function(target, f"function pointer table @ 0x{slot_ea:X}", thumb=thumb)

    def recover_strings(self) -> None:
        if not self.cfg.enable_string_recovery:
            return
        self.progress("Scanning for missed ASCII/UTF-16 strings...", True)
        for seg in self.iter_segments():
            name = self.seg_name(seg)
            if not self.is_readable_data_seg(seg):
                continue
            try:
                buf = self.read_seg_bytes(seg)
                base = int(seg.start_ea)
                self.progress(f"String scan {name or hex(base)}")
                self.scan_ascii_strings(buf, base, name)
                self.scan_utf16_strings(buf, base, name)
            except Cancelled:
                raise
            except Exception as exc:
                self.record_error(f"string scan {name}", exc)

    def byte_is_ascii_string_char(self, b: int) -> bool:
        return b in (9, 10, 13) or 32 <= b <= 126

    def string_has_signal(self, raw: bytes) -> bool:
        if not self.cfg.only_strings_with_alpha_or_path_chars:
            return True
        # Reject pure punctuation or repeated filler. Keep paths, format strings, URLs, symbol-ish data.
        has_alpha = any((65 <= c <= 90) or (97 <= c <= 122) for c in raw)
        has_path_or_fmt = any(c in b"/_\\.%:-{}[]()<>=$@" for c in raw)
        printable = sum(1 for c in raw if self.byte_is_ascii_string_char(c))
        if printable < len(raw):
            return False
        unique = len(set(raw))
        return (has_alpha or has_path_or_fmt) and unique >= 2

    def region_is_safe_for_string(self, ea: int, size: int) -> bool:
        if size <= 0:
            return False
        # Avoid clobbering code, pointer tables, and existing complex data. Unknown/byte/string tails are fair game.
        cur = ea
        end = ea + size
        checks = 0
        while cur < end and checks < 32:
            flags = ida_bytes.get_full_flags(cur)
            if ida_bytes.is_code(flags):
                return False
            if ida_bytes.is_data(flags) and not (ida_bytes.is_byte(flags) or ida_bytes.is_strlit(flags)):
                return False
            item_end = self.get_item_end(cur)
            cur = max(cur + 1, item_end)
            checks += 1
        return True

    def create_string(self, ea: int, size: int, strtype: int, kind: str, preview: bytes) -> bool:
        if not self.region_is_safe_for_string(ea, size):
            return False
        try:
            # Undefine byte-array noise, but don't delete names.
            flags = ida_bytes.get_full_flags(ea)
            if ida_bytes.is_data(flags) and ida_bytes.is_byte(flags):
                ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
        except Exception:
            pass
        try:
            ok = ida_bytes.create_strlit(ea, size, strtype)
        except Exception:
            ok = False
        if ok:
            if kind == "ascii":
                self.stats.strings_created_ascii += 1
            else:
                self.stats.strings_created_utf16 += 1
            if len(self.stats.interesting["strings"]) < 200:
                safe = preview[:80].decode("latin1", errors="replace").replace("\n", "\\n").replace("\r", "\\r")
                self.stats.interesting["strings"].append(f"0x{ea:X} {kind} {safe!r}")
            return True
        return False

    def scan_ascii_strings(self, buf: bytes, base: int, seg_name: str) -> None:
        i = 0
        n = len(buf)
        min_len = self.cfg.min_ascii_len
        while i < n:
            self.check_cancel()
            if not self.byte_is_ascii_string_char(buf[i]):
                i += 1
                continue
            j = i
            cap = min(n, i + self.cfg.max_string_len)
            while j < cap and self.byte_is_ascii_string_char(buf[j]):
                j += 1
            length = j - i
            if length >= min_len:
                if j < n and buf[j] == 0:
                    raw = buf[i:j]
                    if self.string_has_signal(raw):
                        ea = base + i
                        if self.create_string(ea, length + 1, ida_nalt.STRTYPE_C, "ascii", raw):
                            i = j + 1
                            continue
                    # It was a string-looking run with a terminator, just not worth creating. Skip past it.
                    i = j + 1
                    continue
                # Long printable run without NUL: don't rescan every byte like a caveman with a stopwatch.
                i = j
                continue
            i += 1

    def scan_utf16_strings(self, buf: bytes, base: int, seg_name: str) -> None:
        n = len(buf)
        min_chars = self.cfg.min_utf16_chars
        i = 0
        nul_pair = b"\x00\x00"
        while i + 2 <= n:
            self.check_cancel()
            # Use database endianness. For ARM Linux this is almost always little endian, but not always.
            if self.endian == "little":
                ch = buf[i]
                hi = buf[i + 1]
            else:
                hi = buf[i]
                ch = buf[i + 1]
            if hi != 0 or not self.byte_is_ascii_string_char(ch):
                i += 2
                continue
            j = i
            chars = bytearray()
            max_end = min(n, i + self.cfg.max_string_len)
            while j + 2 <= max_end:
                if self.endian == "little":
                    c = buf[j]
                    h = buf[j + 1]
                else:
                    h = buf[j]
                    c = buf[j + 1]
                if h != 0 or not self.byte_is_ascii_string_char(c):
                    break
                chars.append(c)
                j += 2
            if len(chars) >= min_chars and j + 2 <= n and buf[j:j + 2] == nul_pair and self.string_has_signal(bytes(chars)):
                ea = base + i
                if self.create_string(ea, (j - i) + 2, ida_nalt.STRTYPE_C_16, "utf16", bytes(chars)):
                    i = j + 2
                    continue
            i += 2

    # ---------- prologue sweep ----------

    def recover_prologues(self) -> None:
        if not self.cfg.enable_prologue_sweep:
            return
        self.progress("Sweeping executable segments for missed function prologues...", True)
        stride = self.cfg.prologue_sweep_stride_aarch64 if self.is_aarch64 else self.cfg.prologue_sweep_stride_arm32
        stride = max(1, int(stride))
        for seg in self.iter_segments():
            if not self.is_exec_seg(seg):
                continue
            name = self.seg_name(seg)
            count = 0
            ea = int(seg.start_ea)
            end = int(seg.end_ea)
            # Align start for AArch64/ARM. Thumb sweep still uses 2.
            if stride > 1:
                ea += (-ea) % stride
            while ea < end:
                self.check_cancel()
                if count >= self.cfg.max_prologue_candidates_per_segment:
                    break
                if self.looks_like_function_start(ea):
                    self.stats.prologue_candidates += 1
                    if self.make_code_and_function(ea, f"prologue sweep in {name}", from_prologue=True):
                        count += 1
                ea += stride
            self.progress(f"Prologue sweep {name}: created {count}")

    def looks_like_function_start(self, ea: int) -> bool:
        if not self.is_exec_ea(ea):
            return False
        if ida_funcs.get_func(ea):
            return False
        flags = ida_bytes.get_full_flags(ea)
        if not ida_bytes.is_unknown(flags) and not ida_bytes.is_code(flags):
            return False

        if self.is_aarch64:
            return self.looks_like_aarch64_prologue(ea)
        return self.looks_like_arm32_or_thumb_prologue(ea)

    def looks_like_aarch64_prologue(self, ea: int) -> bool:
        try:
            w0 = ida_bytes.get_wide_dword(ea)
            w1 = ida_bytes.get_wide_dword(ea + 4)
            w2 = ida_bytes.get_wide_dword(ea + 8)
        except Exception:
            return False

        # BTI C; PACIASP; common compiler hardening prologue markers.
        if w0 in (0xD503245F, 0xD503233F):
            if self.aarch64_word_is_frame_stp(w1) or self.aarch64_word_is_frame_stp(w2) or self.aarch64_word_is_sub_sp(w1):
                return True

        if self.aarch64_word_is_frame_stp(w0):
            return True

        # Leaf function: SUB SP, SP, #imm followed by a decodable instruction.
        if self.aarch64_word_is_sub_sp(w0) and self.plausible_code_target(ea + 4):
            return True

        return False

    def aarch64_word_is_frame_stp(self, w: int) -> bool:
        # stp x29, x30, [sp, #-imm]!
        return (w & 0xFFC07FFF) == 0xA9807BFD

    def aarch64_word_is_sub_sp(self, w: int) -> bool:
        # sub sp, sp, #imm (immediate form), accepts both 12-bit shift variants.
        return (w & 0xFFC003FF) == 0xD10003FF

    def looks_like_arm32_or_thumb_prologue(self, ea: int) -> bool:
        try:
            h0 = ida_bytes.get_wide_word(ea) & 0xFFFF
            w0 = ida_bytes.get_wide_dword(ea) & 0xFFFFFFFF
        except Exception:
            return False

        # Thumb PUSH {..., LR}: 1011 0101 rlist
        if (h0 & 0xFF00) == 0xB500:
            self.set_thumb_at(ea)
            return True

        # Thumb-2 STMDB SP!, {..., LR}, common as 2-byte/4-byte encodings are messy; require decode + mnemonic.
        try:
            mnem = ida_ua.print_insn_mnem(ea).lower()
            line = ida_lines.generate_disasm_line(ea, 0) or ""
            lline = line.lower()
            if mnem in ("push", "stmdb") and ("lr" in lline or "r14" in lline):
                return True
        except Exception:
            pass

        # ARM mode: STMFD/STMDB SP!, {..., LR}. Encoded as E92Dxxxx with LR bit set.
        if (w0 & 0xFFFF0000) == 0xE92D0000 and (w0 & (1 << 14)):
            return True

        # ARM mode: STR LR, [SP, #-imm]! often used by small functions.
        if (w0 & 0xFFFFF000) == 0xE52DE000:
            return True

        return False

    # ---------- orchestration ----------

    def record_error(self, where: str, exc: Exception) -> None:
        text = f"{where}: {type(exc).__name__}: {exc}"
        self.stats.errors.append(text)
        self.msg(f"ERROR {text}")

    def run_initial_autoanalysis(self) -> None:
        self.progress("Waiting for existing autoanalysis...", True)
        try:
            ida_auto.auto_wait()
        except Exception:
            pass
        self.progress("Planning second-pass analysis for executable segments...", True)
        for start, end, name in self.exec_ranges:
            try:
                ida_auto.plan_and_wait(start, end, True)
            except Exception:
                try:
                    ida_auto.auto_mark_range(start, end, ida_auto.AU_CODE)
                except Exception:
                    pass

    def final_autoanalysis(self) -> None:
        if not self.cfg.run_final_autoanalysis:
            return
        self.progress("Final autoanalysis/reanalysis pass...", True)
        try:
            ida_auto.auto_wait()
        except Exception:
            pass
        for ea in sorted(self.created_funcs):
            try:
                f = ida_funcs.get_func(ea)
                if f:
                    ida_funcs.reanalyze_function(f)
            except Exception:
                pass
        try:
            ida_auto.auto_wait()
        except Exception:
            pass
        if self.cfg.rebuild_string_list:
            try:
                ida_strlist.clear_strlist()
                ida_strlist.build_strlist()
            except Exception as exc:
                self.record_error("string list rebuild", exc)

    def write_report(self, elapsed: float) -> Optional[str]:
        if not self.cfg.create_report_file:
            return None
        try:
            idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
            if not idb_path:
                return None
            report_path = os.path.splitext(idb_path)[0] + ".secondpass_report.json"
            payload = {
                "plugin": PLUGIN_NAME,
                "version": PLUGIN_VERSION,
                "elapsed_seconds": elapsed,
                "processor": self.arch_name,
                "ptr_size": self.ptr_size,
                "endian": self.endian,
                "stats": self.stats.__dict__,
            }
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, sort_keys=True)
            return report_path
        except Exception as exc:
            self.record_error("write report", exc)
            return None

    def validate_processor(self) -> bool:
        if "arm" not in self.arch_name and "aarch64" not in self.arch_name:
            answer = ida_kernwin.ask_yn(
                ida_kernwin.ASKBTN_NO,
                f"This database processor is '{self.arch_name}', not ARM/AArch64. Run {PLUGIN_NAME} anyway?"
            )
            return answer == ida_kernwin.ASKBTN_YES
        return True

    def run(self) -> Stats:
        start_time = time.monotonic()
        try:
            if not self.validate_processor():
                return self.stats
            if self.cfg.ask_before_run:
                answer = ida_kernwin.ask_yn(
                    ida_kernwin.ASKBTN_YES,
                    f"{PLUGIN_NAME} will create functions, strings, pointer data, offsets, names, and xrefs.\n"
                    "Run it on this database now?"
                )
                if answer != ida_kernwin.ASKBTN_YES:
                    return self.stats

            try:
                ida_kernwin.show_wait_box(f"HIDECANCEL\n{PLUGIN_NAME}\nStarting...")
            except Exception:
                pass

            self.msg(f"starting v{PLUGIN_VERSION}; processor={self.arch_name}, ptr={self.ptr_size}, endian={self.endian}")
            if self.cfg.create_undo_point:
                try:
                    ida_undo.create_undo_point("ARM Linux second pass", "Before ARM Linux second pass")
                except Exception:
                    pass

            self.index_segments()
            self.run_initial_autoanalysis()

            self.recover_entries()
            self.recover_named_exec_locations()
            self.recover_fixups()
            self.recover_arm_exidx()
            self.recover_eh_frame_hdr()
            self.recover_data_pointers()
            self.recover_vtables()
            self.recover_strings()
            self.recover_prologues()
            self.final_autoanalysis()

        except Cancelled:
            self.msg("cancelled by user")
        except Exception as exc:
            self.record_error("fatal", exc)
            self.msg(traceback.format_exc())
        finally:
            try:
                ida_kernwin.hide_wait_box()
            except Exception:
                pass
            elapsed = time.monotonic() - start_time
            report = self.write_report(elapsed)
            self.print_summary(elapsed, report)
        return self.stats

    def print_summary(self, elapsed: float, report: Optional[str]) -> None:
        s = self.stats
        self.msg("done")
        self.msg(
            "summary: "
            f"elapsed={elapsed:.2f}s, segments={s.segments_seen}, exec={s.exec_segments}, data={s.data_segments}, "
            f"functions_created={s.functions_created}, prologue_created={s.prologue_functions_created}, "
            f"ascii_strings={s.strings_created_ascii}, utf16_strings={s.strings_created_utf16}, "
            f"vtables={s.vtables_found}, fnptr_tables={s.fnptr_tables_found}, "
            f"ptrs_made={s.pointers_made}, names_set={s.names_set}, errors={len(s.errors)}"
        )
        if report:
            self.msg(f"report written: {report}")
        if s.errors:
            self.msg("errors:")
            for err in s.errors[:50]:
                self.msg(f"  {err}")


class ArmLinuxSecondPassPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_MOD
    comment = "Second-pass recovery for ARM/AArch64 Linux ELF binaries"
    help = "Find missed functions, strings, vtables, pointer tables, and unwind-derived function starts"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Ctrl-Alt-Shift-A"

    def init(self):
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        cfg = SecondPassConfig()
        if arg == 1:
            cfg.ask_before_run = False
        SecondPassAnalyzer(cfg).run()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return ArmLinuxSecondPassPlugin()


# Allows File -> Script file... execution without installing as a plugin.
if __name__ == "__main__":
    cfg = SecondPassConfig(ask_before_run=False)
    SecondPassAnalyzer(cfg).run()
