# ida93_arm_linux_secondpass.py
# IDA Pro 9.3 / Python 3.13 plugin
# Second-pass recovery for ARM/AArch64 Linux ELF binaries.
# v1.4.0: string-safe rebuild; existing string literals are never deleted/recreated.
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
try:
    import ida_hexrays
except Exception:
    ida_hexrays = None
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_lines
import ida_loader
import ida_name
import ida_nalt
import ida_offset
import ida_problems
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
PLUGIN_VERSION = "1.4.0"
LOG_PREFIX = "[arm-linux-secondpass]"


@dataclass
class SecondPassConfig:
    # General behavior
    create_undo_point: bool = True
    ask_before_run: bool = True
    rename_auto_items: bool = True
    rebuild_string_list: bool = True
    # Do not clear IDA's cached string list by default. clear_strlist()+build_strlist()
    # can make IDA's Strings window look like it lost everything if the current
    # string-list options only include explicit string literals. Build refreshes; clear is opt-in.
    clear_string_list_before_rebuild: bool = False
    run_final_autoanalysis: bool = True
    create_report_file: bool = True

    # Existing function audit / realignment / optional decompiler recovery
    # This pass checks functions IDA already created during initial autoanalysis.
    # It re-runs function-bound discovery and repairs obvious bad starts/ends.
    # Hex-Rays/decompiler probing is OFF by default because full-database
    # decompilation is painfully slow on large ARM firmware/userland blobs.
    enable_existing_function_audit: bool = True
    audit_decompile_current_functions: bool = False
    audit_decompile_only_suspicious: bool = True
    audit_retry_decompile_after_repair: bool = False
    audit_rebuild_undecompilable_functions: bool = False
    audit_rebuild_user_named_functions: bool = False
    audit_repair_function_starts: bool = True
    audit_repair_function_ends: bool = True
    audit_split_embedded_prologues: bool = True
    audit_reset_stack_analysis_flags: bool = True
    audit_max_start_realign_back: int = 0x40
    audit_max_start_realign_forward: int = 0x80
    audit_min_embedded_function_gap: int = 0x20
    audit_max_functions: int = 0  # 0 means no cap
    audit_new_functions_after_recovery: bool = True

    # Red navigation-band cleanup / unresolved area recovery
    # IDA's nav band red often means unexplored bytes. Some red markers are real analysis
    # problems, so this pass tries to fix/classify first and only removes stale markers.
    enable_red_band_cleanup: bool = True
    red_cleanup_executable_unknowns: bool = True
    red_cleanup_data_unknowns: bool = True
    red_cleanup_problem_list: bool = True
    red_cleanup_make_alignment: bool = True
    red_cleanup_make_remaining_bytes: bool = False
    red_cleanup_forget_stale_problems: bool = True
    # Default is now aggressive: after repair/reanalysis attempts, remaining problem
    # markers are removed but recorded in the JSON report first. Set this False if
    # you want IDA's problem window to preserve unresolved warnings.
    red_cleanup_forget_unresolved_problem_markers: bool = False

    # Stronger cleanup. IDA's red navigation band can come from BSS/NOBITS, non-readable
    # loader-created segments, or stubborn unknown bytes left after decoding fails. These
    # options classify those areas as byte/alignment data after every smarter pass has had
    # a chance to recover code, strings, pointers, and tables.
    red_cleanup_include_bss_segments: bool = True
    red_cleanup_include_nonreadable_segments: bool = True
    red_cleanup_aggressive_final_sweep: bool = False
    red_cleanup_repeat_after_final_autoanalysis: bool = True
    red_cleanup_wait_after_requeue: bool = True
    red_cleanup_aggressive_exec_tail_bytes: bool = True
    red_cleanup_aggressive_chunk_size: int = 1024 * 1024
    red_cleanup_max_aggressive_bytes: int = 0  # 0 means no cap
    red_cleanup_report_remaining_samples: int = 200
    max_red_cleanup_unknown_runs_per_segment: int = 250000

    # String safety. The red cleanup must never flatten string-looking bytes into
    # giant byte arrays without first giving string recovery another chance.
    preserve_existing_strings: bool = True
    restore_preserved_strings_after_cleanup: bool = True
    recover_strings_after_red_cleanup: bool = True
    scan_byte_arrays_for_strings: bool = True
    # v1.4.0 hard safety: never destroy or resize existing string literals while rescanning.
    # Red cleanup is allowed to report leftovers, but not flatten anything that overlaps a string.
    never_delete_existing_strings: bool = True
    report_string_safety_skips: bool = True

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
    functions_audited: int = 0
    functions_reanalyzed: int = 0
    functions_suspicious: int = 0
    functions_decompile_attempted: int = 0
    functions_decompile_failed: int = 0
    functions_decompile_recovered: int = 0
    functions_bounds_recomputed: int = 0
    functions_start_repaired: int = 0
    functions_end_repaired: int = 0
    functions_rebuilt: int = 0
    functions_rebuild_failed: int = 0
    embedded_prologues_found: int = 0
    embedded_functions_created: int = 0
    functions_already_existing: int = 0
    function_candidates_rejected: int = 0
    prologue_candidates: int = 0
    prologue_functions_created: int = 0
    strings_created_ascii: int = 0
    strings_created_utf16: int = 0
    strings_preserved: int = 0
    strings_restored: int = 0
    strings_restore_failed: int = 0
    strings_existing_skipped: int = 0
    string_overlap_skips: int = 0
    protected_string_ranges_seen: int = 0
    vtables_found: int = 0
    fnptr_tables_found: int = 0
    names_set: int = 0
    red_unknown_runs_seen: int = 0
    red_unknown_bytes_seen: int = 0
    red_exec_insns_created: int = 0
    red_exec_funcs_created: int = 0
    red_data_bytes_created: int = 0
    red_alignments_created: int = 0
    red_remaining_unknown_runs: int = 0
    red_remaining_unknown_bytes: int = 0
    red_remaining_unknown_segments: Dict[str, int] = field(default_factory=dict)
    red_remaining_unknown_samples: List[str] = field(default_factory=list)
    red_aggressive_sweeps: int = 0
    red_aggressive_bytes_created: int = 0
    red_unloaded_unknown_bytes_seen: int = 0
    red_bss_unknown_bytes_seen: int = 0
    problem_entries_seen: int = 0
    problem_entries_requeued: int = 0
    problem_entries_fixed_or_stale: int = 0
    problem_entries_forgotten_unresolved: int = 0
    problem_entries_remaining: int = 0
    problem_entries_remaining_by_type: Dict[str, int] = field(default_factory=dict)
    problem_entries_remaining_samples: List[str] = field(default_factory=list)
    problem_entries_forgotten_samples: List[str] = field(default_factory=list)
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
        self.audited_func_starts: Set[int] = set()
        self.preserved_strings: Dict[int, Tuple[int, int, bytes]] = {}
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

    def get_item_head(self, ea: int) -> int:
        try:
            head = ida_bytes.get_item_head(ea)
            if head != BADADDR:
                return int(head)
        except Exception:
            pass
        return ea

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

    def range_overlaps_existing_string(self, ea: int, size: int) -> bool:
        """Return True if [ea, ea+size) overlaps an existing string literal item.

        This is deliberately conservative. The plugin's string recovery may scan
        across areas IDA already knows are strings; those must be treated as
        protected territory, not as convenient raw material for del_items().
        """
        if size <= 0:
            return False
        end = ea + size
        cur = ea
        checked = 0
        while cur < end and checked < 4096:
            checked += 1
            try:
                head = self.get_item_head(cur)
                if head == BADADDR:
                    cur += 1
                    continue
                flags = ida_bytes.get_full_flags(head)
                item_end = self.get_item_end(head)
                if item_end <= head:
                    item_end = head + 1
                if ida_bytes.is_strlit(flags) and item_end > ea and head < end:
                    self.stats.protected_string_ranges_seen += 1
                    return True
                cur = max(cur + 1, item_end)
            except Exception:
                cur += 1
        return False

    def string_at_exact_start(self, ea: int) -> bool:
        try:
            head = self.get_item_head(ea)
            if head != ea:
                return False
            return bool(ida_bytes.is_strlit(ida_bytes.get_full_flags(ea)))
        except Exception:
            return False

    def region_is_safe_for_string(self, ea: int, size: int) -> bool:
        if size <= 0:
            return False
        if self.cfg.never_delete_existing_strings and self.range_overlaps_existing_string(ea, size):
            # Existing string literals are already useful analysis objects. Do not
            # reinterpret or resize them during a broad rescan. This was the bug
            # that could make the Strings window collapse to almost nothing.
            self.stats.string_overlap_skips += 1
            return False
        # Avoid clobbering code, pointer tables, and existing complex data. Unknown/byte tails are fair game.
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
        # If IDA already has a string item at this exact address, keep it. Rescanning
        # should not delete/recreate existing strings just to prove it owns a shovel.
        if self.cfg.never_delete_existing_strings and self.string_at_exact_start(ea):
            self.stats.strings_existing_skipped += 1
            return True

        if not self.region_is_safe_for_string(ea, size):
            return False

        # If a previous sweep created one huge byte array, the string start may be in
        # the middle of that item. Delete/trim only plain byte data. Never delete an
        # existing string literal item, even if IDA also reports it as byte-sized data.
        try:
            head = self.get_item_head(ea)
            flags = ida_bytes.get_full_flags(head)
            if (
                ida_bytes.is_data(flags)
                and ida_bytes.is_byte(flags)
                and not ida_bytes.is_strlit(flags)
            ):
                ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND | ida_bytes.DELIT_NOUNAME | ida_bytes.DELIT_NOCMT, size)
        except Exception:
            pass

        try:
            ok = ida_bytes.create_strlit(ea, size, strtype)
        except Exception:
            ok = False
        if ok:
            if kind in ("ascii", "restored") and strtype == ida_nalt.STRTYPE_C:
                self.stats.strings_created_ascii += 1
            elif kind in ("utf16", "restored"):
                self.stats.strings_created_utf16 += 1
            if len(self.stats.interesting["strings"]) < 200:
                safe = preview[:80].decode("latin1", errors="replace").replace("\n", "\\n").replace("\r", "\\r")
                self.stats.interesting["strings"].append(f"0x{ea:X} {kind} {safe!r}")
            return True
        return False

    def preserve_existing_strings(self) -> None:
        if not self.cfg.preserve_existing_strings:
            return
        try:
            # build_strlist() updates the cache. Do not clear it here; clearing is the exact
            # kind of 'help' that makes the Strings window look nuked. Humanity perseveres.
            ida_strlist.build_strlist()
            qty = ida_strlist.get_strlist_qty()
            si = ida_strlist.string_info_t()
            added = 0
            for i in range(qty):
                self.check_cancel()
                if not ida_strlist.get_strlist_item(si, i):
                    continue
                ea = int(si.ea)
                length = int(si.length)
                stype = int(si.type)
                if ea == BADADDR or length <= 0:
                    continue
                raw = ida_bytes.get_bytes(ea, length)
                if raw is None:
                    continue
                if ea not in self.preserved_strings:
                    added += 1
                self.preserved_strings[ea] = (length, stype, bytes(raw))
            self.stats.strings_preserved = len(self.preserved_strings)
            if added:
                self.msg(f"preserved {added} string-list entries before cleanup")
        except Exception as exc:
            self.record_error("preserve strings", exc)

    def restore_preserved_strings(self) -> None:
        if not (self.cfg.preserve_existing_strings and self.cfg.restore_preserved_strings_after_cleanup):
            return
        restored = 0
        failed = 0
        for ea, (length, stype, raw) in sorted(self.preserved_strings.items()):
            self.check_cancel()
            try:
                flags = ida_bytes.get_full_flags(ea)
                if ida_bytes.is_code(flags):
                    continue
                if ida_bytes.is_strlit(flags):
                    continue
                now = ida_bytes.get_bytes(ea, length)
                if now is None or bytes(now) != raw:
                    continue
                if self.create_string(ea, length, stype, "restored", raw):
                    restored += 1
                else:
                    failed += 1
            except Exception:
                failed += 1
        self.stats.strings_restored += restored
        self.stats.strings_restore_failed += failed
        if restored or failed:
            self.msg(f"restored preserved strings: restored={restored}, failed={failed}")

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


    # ---------- existing function audit / rebuild pass ----------

    def audit_existing_functions(self, only_new: bool = False) -> None:
        """Validate and repair functions IDA already created.

        This is deliberately separate from discovery. Discovery finds missing starts;
        this pass checks whether current function objects are malformed, badly bounded,
        misaligned, or still undecompilable after autoanalysis. It is conservative about
        touching user-named functions unless audit_rebuild_user_named_functions is enabled.
        """
        if not self.cfg.enable_existing_function_audit:
            return
        if self.cfg.audit_decompile_current_functions:
            self.progress("Auditing existing functions for bad starts, bad ends, and optional decompiler failures...", True)
        else:
            self.progress("Auditing existing functions for bad starts, bad ends, and embedded prologues; Hex-Rays decompile checks disabled...", True)
        starts = [int(ea) for ea in idautils.Functions()]
        starts.sort()
        if self.cfg.audit_max_functions and self.cfg.audit_max_functions > 0:
            starts = starts[: int(self.cfg.audit_max_functions)]

        for idx, start in enumerate(starts, 1):
            self.check_cancel()
            if only_new and start in self.audited_func_starts:
                continue
            pfn = ida_funcs.get_func(start)
            if not pfn:
                continue
            if not self.is_exec_ea(int(pfn.start_ea)):
                continue
            self.audited_func_starts.add(start)
            self.stats.functions_audited += 1
            if idx == 1 or (idx % 250) == 0:
                self.progress(f"Function audit {idx}/{len(starts)} @ 0x{int(pfn.start_ea):X}")
            try:
                self.audit_one_function(pfn)
            except Cancelled:
                raise
            except Exception as exc:
                self.record_error(f"audit function 0x{int(start):X}", exc)

    def audit_one_function(self, pfn: ida_funcs.func_t) -> None:
        start = int(pfn.start_ea)
        end = int(pfn.end_ea)
        suspicious_reasons = self.function_suspicion_reasons(pfn)
        if suspicious_reasons:
            self.stats.functions_suspicious += 1

        failed_before = False
        attempted_decompile = False
        if self.should_decompile_for_audit(pfn, suspicious_reasons):
            attempted_decompile = True
            ok, reason = self.try_decompile_function(pfn)
            if not ok:
                failed_before = True
                self.stats.functions_decompile_failed += 1
                if not suspicious_reasons:
                    suspicious_reasons.append(f"hexrays_failed:{reason}")

        changed = False
        if suspicious_reasons:
            changed |= self.reset_and_reanalyze_function(pfn, suspicious_reasons)
            pfn = ida_funcs.get_func(start) or pfn

            if self.cfg.audit_repair_function_starts:
                new_start = self.find_better_function_start(pfn)
                if new_start is not None and new_start != int(pfn.start_ea):
                    if self.move_function_start_safely(pfn, new_start):
                        self.stats.functions_start_repaired += 1
                        changed = True
                        pfn = ida_funcs.get_func(new_start) or pfn
                        start = int(pfn.start_ea)

            if self.cfg.audit_repair_function_ends:
                if self.recompute_and_apply_function_end(pfn):
                    self.stats.functions_end_repaired += 1
                    changed = True
                    pfn = ida_funcs.get_func(int(pfn.start_ea)) or pfn

            if self.cfg.audit_split_embedded_prologues:
                changed |= self.split_embedded_prologues(pfn)

        if changed:
            try:
                ida_auto.auto_wait_range(int(pfn.start_ea), min(int(pfn.end_ea), int(pfn.start_ea) + 0x20000))
            except Exception:
                try:
                    ida_auto.auto_wait()
                except Exception:
                    pass

        if attempted_decompile and failed_before and self.cfg.audit_retry_decompile_after_repair:
            pfn = ida_funcs.get_func(start) or ida_funcs.get_func(int(getattr(pfn, "start_ea", start)))
            if pfn:
                ok_after, _reason_after = self.try_decompile_function(pfn)
                if ok_after:
                    self.stats.functions_decompile_recovered += 1
                elif self.cfg.audit_rebuild_undecompilable_functions:
                    if self.rebuild_function_safely(pfn, suspicious_reasons):
                        self.stats.functions_rebuilt += 1
                        pfn2 = ida_funcs.get_func(int(pfn.start_ea))
                        if pfn2:
                            ok_final, _ = self.try_decompile_function(pfn2)
                            if ok_final:
                                self.stats.functions_decompile_recovered += 1
                    else:
                        self.stats.functions_rebuild_failed += 1

    def should_decompile_for_audit(self, pfn: ida_funcs.func_t, suspicious_reasons: List[str]) -> bool:
        if not self.cfg.audit_decompile_current_functions:
            return False
        if ida_hexrays is None:
            return False
        if self.cfg.audit_decompile_only_suspicious and not suspicious_reasons:
            return False
        # Imports/thunks/library stubs are often intentionally odd and waste time.
        try:
            flags = int(pfn.flags)
            if flags & getattr(ida_funcs, "FUNC_LIB", 0):
                return False
        except Exception:
            pass
        return True

    def try_decompile_function(self, pfn: ida_funcs.func_t) -> Tuple[bool, str]:
        self.stats.functions_decompile_attempted += 1
        if ida_hexrays is None:
            return False, "ida_hexrays module unavailable"
        try:
            if not ida_hexrays.init_hexrays_plugin():
                return False, "hexrays unavailable for this processor/license"
        except Exception as exc:
            return False, f"hexrays init failed: {exc}"
        try:
            hf = ida_hexrays.hexrays_failure_t()
        except Exception:
            hf = None
        try:
            cfunc = ida_hexrays.decompile_func(pfn, hf, 0)
            if cfunc:
                return True, "ok"
            if hf is not None:
                errea = int(getattr(hf, "errea", BADADDR))
                desc = ""
                try:
                    desc = hf.desc()
                except Exception:
                    desc = str(hf)
                return False, f"{desc} @ 0x{errea:X}"
            return False, "decompile returned None"
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"

    def function_suspicion_reasons(self, pfn: ida_funcs.func_t) -> List[str]:
        reasons: List[str] = []
        start = int(pfn.start_ea)
        end = int(pfn.end_ea)
        if end <= start:
            reasons.append("empty_or_negative_bounds")
        if not self.is_exec_ea(start):
            reasons.append("start_outside_exec_segment")
        if end != BADADDR and end > start:
            last = max(start, end - 1)
            if not self.is_exec_ea(last):
                reasons.append("end_outside_exec_segment")
        try:
            flags = ida_bytes.get_full_flags(start)
            if not ida_bytes.is_code(flags):
                reasons.append("function_start_not_code")
            elif not ida_ua.can_decode(start):
                reasons.append("function_start_not_decodable")
        except Exception:
            reasons.append("function_start_flags_failed")
        try:
            fflags = int(pfn.flags)
            if fflags & getattr(ida_funcs, "FUNC_FUZZY_SP", 0):
                reasons.append("fuzzy_sp")
            if fflags & getattr(ida_funcs, "FUNC_REANALYZE", 0):
                reasons.append("needs_reanalysis")
            if hasattr(pfn, "need_prolog_analysis") and pfn.need_prolog_analysis():
                reasons.append("needs_prolog_analysis")
        except Exception:
            pass
        try:
            item_count = 0
            bad_code = 0
            unknowns = 0
            for ea in idautils.FuncItems(start):
                item_count += 1
                fl = ida_bytes.get_full_flags(ea)
                if ida_bytes.is_unknown(fl):
                    unknowns += 1
                elif not ida_bytes.is_code(fl):
                    bad_code += 1
                if item_count >= 4096:
                    break
            if item_count == 0:
                reasons.append("no_function_items")
            if unknowns:
                reasons.append(f"unknown_items:{unknowns}")
            if bad_code:
                reasons.append(f"noncode_items:{bad_code}")
        except Exception:
            pass
        return reasons

    def reset_and_reanalyze_function(self, pfn: ida_funcs.func_t, reasons: Sequence[str]) -> bool:
        changed = False
        try:
            if self.cfg.audit_reset_stack_analysis_flags:
                flags = int(pfn.flags)
                clear = 0
                for n in ("FUNC_SP_READY", "FUNC_FUZZY_SP", "FUNC_PROLOG_OK"):
                    clear |= int(getattr(ida_funcs, n, 0))
                new_flags = (flags & ~clear) | int(getattr(ida_funcs, "FUNC_REANALYZE", 0))
                if new_flags != flags:
                    pfn.flags = new_flags
                    ida_funcs.update_func(pfn)
                    changed = True
        except Exception:
            pass
        try:
            ida_funcs.reanalyze_function(pfn)
            ida_auto.plan_ea(int(pfn.start_ea))
            self.stats.functions_reanalyzed += 1
            changed = True
        except Exception as exc:
            self.record_error(f"reanalyze function 0x{int(pfn.start_ea):X}", exc)
        return changed

    def find_function_bounds_candidate(self, start: int) -> Tuple[Optional[int], int]:
        try:
            nfn = ida_funcs.func_t(start)
            flags = ida_funcs.FIND_FUNC_DEFINE | ida_funcs.FIND_FUNC_IGNOREFN
            res = ida_funcs.find_func_bounds(nfn, flags)
            new_end = int(nfn.end_ea)
            if res in (ida_funcs.FIND_FUNC_OK, ida_funcs.FIND_FUNC_EXIST) and new_end > start and self.is_exec_ea(new_end - 1):
                return new_end, int(res)
        except Exception:
            pass
        try:
            end = idc.find_func_end(start)
            if end != BADADDR and end > start and self.is_exec_ea(int(end) - 1):
                return int(end), -1
        except Exception:
            pass
        return None, -1

    def recompute_and_apply_function_end(self, pfn: ida_funcs.func_t) -> bool:
        start = int(pfn.start_ea)
        old_end = int(pfn.end_ea)
        new_end, _res = self.find_function_bounds_candidate(start)
        if new_end is None or new_end == old_end:
            return False
        if not self.function_end_change_is_safe(start, old_end, new_end):
            return False
        try:
            if ida_funcs.set_func_end(start, new_end):
                self.stats.functions_bounds_recomputed += 1
                return True
        except Exception as exc:
            self.record_error(f"set function end 0x{start:X}->0x{new_end:X}", exc)
        return False

    def function_end_change_is_safe(self, start: int, old_end: int, new_end: int) -> bool:
        if new_end <= start:
            return False
        if not self.is_exec_ea(new_end - 1):
            return False
        # Never extend into another function start. That is how one bogus function eats the village.
        lo = min(old_end, new_end)
        hi = max(old_end, new_end)
        for other in idautils.Functions(lo, hi):
            other = int(other)
            if other != start:
                return False
        # Avoid wild expansions from bad data. ARM functions can be large, but a sudden multi-MB
        # extension from a repair pass is usually a hallucination wearing a cape.
        if new_end > old_end and (new_end - old_end) > 0x40000:
            return False
        return True

    def looks_like_function_start_for_audit(self, ea: int, owning_func: Optional[ida_funcs.func_t] = None) -> bool:
        if not self.is_exec_ea(ea):
            return False
        f = ida_funcs.get_func(ea)
        if f and owning_func and int(f.start_ea) != int(owning_func.start_ea):
            return False
        flags = ida_bytes.get_full_flags(ea)
        if not ida_bytes.is_unknown(flags) and not ida_bytes.is_code(flags):
            return False
        if self.is_aarch64:
            return self.looks_like_aarch64_prologue(ea)
        return self.looks_like_arm32_or_thumb_prologue(ea)

    def find_better_function_start(self, pfn: ida_funcs.func_t) -> Optional[int]:
        start = int(pfn.start_ea)
        end = int(pfn.end_ea)
        # If current start already looks like a real prologue, keep it. Tiny/leaf functions do not
        # always have canonical prologues, so lack of prologue alone is not proof of corruption.
        if self.looks_like_function_start_for_audit(start, pfn):
            return None
        if ida_bytes.is_code(ida_bytes.get_full_flags(start)) and ida_ua.can_decode(start):
            return None

        stride = self.cfg.prologue_sweep_stride_aarch64 if self.is_aarch64 else self.cfg.prologue_sweep_stride_arm32
        stride = max(1, int(stride))
        scan_start = max(self.segment_start_for_ea(start), start - int(self.cfg.audit_max_start_realign_back))
        scan_end = min(end, start + int(self.cfg.audit_max_start_realign_forward))
        if stride > 1:
            scan_start += (-scan_start) % stride
        best: Optional[int] = None
        for ea in range(scan_start, scan_end, stride):
            if ea == start:
                continue
            if self.looks_like_function_start_for_audit(ea, pfn):
                best = ea
                break
        return best

    def segment_start_for_ea(self, ea: int) -> int:
        seg = ida_segment.getseg(ea)
        return int(seg.start_ea) if seg else ea

    def move_function_start_safely(self, pfn: ida_funcs.func_t, new_start: int) -> bool:
        old_start = int(pfn.start_ea)
        if new_start == old_start:
            return False
        # Do not realign user-named functions unless explicitly permitted.
        if not self.cfg.audit_rebuild_user_named_functions and self.has_user_meaningful_name(old_start):
            return False
        if new_start < old_start:
            prev = ida_funcs.get_func(new_start)
            if prev and int(prev.start_ea) != old_start:
                return False
        try:
            if not ida_bytes.is_code(ida_bytes.get_full_flags(new_start)):
                ida_ua.create_insn(new_start)
        except Exception:
            pass
        try:
            res = ida_funcs.set_func_start(old_start, new_start)
            if res == ida_funcs.MOVE_FUNC_OK:
                return True
        except Exception as exc:
            self.record_error(f"move function start 0x{old_start:X}->0x{new_start:X}", exc)
        # If start movement failed, use a full rebuild as a fallback for auto-named functions.
        if self.cfg.audit_rebuild_undecompilable_functions:
            f = ida_funcs.get_func(old_start) or pfn
            return self.rebuild_function_safely(f, [f"realign_start:0x{new_start:X}"], forced_start=new_start)
        return False

    def has_user_meaningful_name(self, ea: int) -> bool:
        try:
            name = ida_name.get_name(ea) or ""
            if not name:
                return False
            auto_prefixes = ("sub_", "loc_", "nullsub_", "j_", "thunk_", "sp_func_")
            return not name.startswith(auto_prefixes)
        except Exception:
            return False

    def split_embedded_prologues(self, pfn: ida_funcs.func_t) -> bool:
        start = int(pfn.start_ea)
        end = int(pfn.end_ea)
        if end <= start + int(self.cfg.audit_min_embedded_function_gap):
            return False
        stride = self.cfg.prologue_sweep_stride_aarch64 if self.is_aarch64 else self.cfg.prologue_sweep_stride_arm32
        stride = max(1, int(stride))
        ea = start + int(self.cfg.audit_min_embedded_function_gap)
        if stride > 1:
            ea += (-ea) % stride
        changed = False
        while ea < end:
            self.check_cancel()
            # Do not split at an address that is already a head with inbound fallthrough only.
            if self.looks_like_function_start_for_audit(ea, pfn) and self.has_nonfallthrough_code_xref(ea, start):
                self.stats.embedded_prologues_found += 1
                try:
                    if ida_funcs.set_func_end(start, ea):
                        if self.make_code_and_function(ea, f"embedded prologue split from 0x{start:X}", from_prologue=True):
                            self.stats.embedded_functions_created += 1
                            changed = True
                            break
                except Exception as exc:
                    self.record_error(f"split embedded prologue 0x{ea:X}", exc)
            ea += stride
        return changed

    def has_nonfallthrough_code_xref(self, ea: int, owner_start: int) -> bool:
        try:
            for xr in idautils.XrefsTo(ea, 0):
                frm = int(xr.frm)
                if not self.is_exec_ea(frm):
                    continue
                if frm + self.get_item_size_safe(frm) == ea:
                    continue
                return True
        except Exception:
            pass
        # Named labels and pointer-confirmed starts are also decent signals.
        try:
            name = ida_name.get_name(ea) or ""
            if name and not name.startswith(("loc_", "sub_")):
                return True
        except Exception:
            pass
        return ea in self.ptr_code_targets or ea in self.created_funcs

    def get_item_size_safe(self, ea: int) -> int:
        try:
            sz = ida_bytes.get_item_size(ea)
            return int(sz) if sz and sz > 0 else 1
        except Exception:
            return 1

    def rebuild_function_safely(self, pfn: ida_funcs.func_t, reasons: Sequence[str], forced_start: Optional[int] = None) -> bool:
        old_start = int(pfn.start_ea)
        old_end = int(pfn.end_ea)
        new_start = int(forced_start) if forced_start is not None else old_start
        if not self.is_exec_ea(new_start):
            return False
        if not self.cfg.audit_rebuild_user_named_functions and self.has_user_meaningful_name(old_start):
            return False

        old_name = ida_name.get_name(old_start) or ""
        old_cmt = ""
        old_rep_cmt = ""
        try:
            old_cmt = ida_funcs.get_func_cmt(pfn, False) or ""
            old_rep_cmt = ida_funcs.get_func_cmt(pfn, True) or ""
        except Exception:
            pass

        new_end, _res = self.find_function_bounds_candidate(new_start)
        if new_end is None:
            new_end = BADADDR
        elif not self.function_end_change_is_safe(new_start, old_end, new_end):
            new_end = BADADDR

        try:
            ida_funcs.del_func(old_start)
        except Exception:
            return False

        try:
            if not ida_bytes.is_code(ida_bytes.get_full_flags(new_start)):
                ida_ua.create_insn(new_start)
        except Exception:
            pass

        ok = False
        try:
            if new_end != BADADDR:
                ok = bool(ida_funcs.add_func(new_start, new_end))
            else:
                ok = bool(ida_funcs.add_func(new_start))
        except Exception:
            ok = False

        if not ok:
            # Try to put back something close to the old function so the database is not left worse.
            try:
                ida_funcs.add_func(old_start, old_end)
            except Exception:
                pass
            return False

        try:
            nf = ida_funcs.get_func(new_start)
            if nf:
                if old_cmt:
                    ida_funcs.set_func_cmt(nf, old_cmt, False)
                if old_rep_cmt:
                    ida_funcs.set_func_cmt(nf, old_rep_cmt, True)
                ida_funcs.reanalyze_function(nf)
                self.stats.functions_reanalyzed += 1
        except Exception:
            pass
        if old_name and old_name.startswith(("sub_", "sp_func_", "nullsub_", "j_", "thunk_")):
            self.set_auto_name(new_start, self.safe_name("sp_rebuilt", new_start))
        return True


    # ---------- red nav-band / undefined area cleanup ----------

    def recover_red_nav_band(self) -> None:
        """Try to eliminate red nav-band regions by classifying unexplored bytes and stale problems.

        In IDA's navigation band, red is most commonly unexplored bytes, but problem-list
        addresses can also paint the UI like a crime scene. This pass does not blindly turn
        executable junk into functions first; high-signal passes above already ran. Here we
        mop up the remaining unknowns as code, alignment, or data bytes, then requeue/fix
        problem addresses and optionally remove stale markers.
        """
        if not self.cfg.enable_red_band_cleanup:
            return
        self.progress("Cleaning red navigation-band regions / unexplored bytes...", True)
        try:
            if self.cfg.red_cleanup_executable_unknowns:
                self.cleanup_executable_unknowns()
            if self.cfg.red_cleanup_data_unknowns:
                self.cleanup_data_unknowns()
            if self.cfg.red_cleanup_problem_list:
                self.cleanup_problem_lists()
            if self.cfg.red_cleanup_aggressive_final_sweep:
                self.aggressive_final_unknown_sweep()
                if self.cfg.red_cleanup_problem_list:
                    self.cleanup_problem_lists()
            if self.cfg.red_cleanup_wait_after_requeue:
                try:
                    ida_auto.auto_wait()
                except Exception:
                    pass
            self.count_remaining_unknowns()
        except Cancelled:
            raise
        except Exception as exc:
            self.record_error("red nav-band cleanup", exc)

    def unknown_runs_in_segment(self, seg: ida_segment.segment_t) -> Iterable[Tuple[int, int]]:
        start = int(seg.start_ea)
        end = int(seg.end_ea)
        ea = ida_bytes.next_unknown(start - 1 if start > 0 else start, end)
        runs = 0
        while ea != BADADDR and ea < end:
            self.check_cancel()
            run_start = int(ea)
            cur = run_start
            # Walk the unknown run. Using flags here is cheaper and more reliable than repeatedly
            # asking next_unknown(), which happily makes humans invent infinite loops by accident.
            while cur < end and ida_bytes.is_unknown(ida_bytes.get_full_flags(cur)):
                cur += 1
            run_end = max(run_start + 1, cur)
            yield run_start, run_end
            runs += 1
            if runs >= self.cfg.max_red_cleanup_unknown_runs_per_segment:
                self.record_error(
                    f"unknown-run cleanup {self.seg_name(seg)}",
                    RuntimeError("stopped after max_red_cleanup_unknown_runs_per_segment")
                )
                return
            ea = ida_bytes.next_unknown(run_end - 1, end)

    def bytes_are_alignment_fill(self, raw: bytes) -> bool:
        if not raw:
            return False
        if len(raw) == 1:
            return raw[0] in (0x00, 0xFF)
        if all(b == 0x00 for b in raw) or all(b == 0xFF for b in raw):
            return True
        # Common ARM/AArch64 NOP fill patterns. These appear in executable padding.
        patterns = []
        if self.endian == "little":
            patterns.extend([b"\x00\xf0\x20\xe3", b"\x1f\x20\x03\xd5", b"\x00\xbf"])
        else:
            patterns.extend([b"\xe3\x20\xf0\x00", b"\xd5\x03\x20\x1f", b"\xbf\x00"])
        for pat in patterns:
            if len(raw) >= len(pat) and len(raw) % len(pat) == 0:
                if all(raw[i:i + len(pat)] == pat for i in range(0, len(raw), len(pat))):
                    return True
        return False

    def make_alignment_or_bytes(self, ea: int, size: int, raw: Optional[bytes] = None) -> bool:
        if size <= 0:
            return False
        if self.cfg.never_delete_existing_strings and self.range_overlaps_existing_string(ea, size):
            self.stats.string_overlap_skips += 1
            return False
        if raw is None:
            raw = ida_bytes.get_bytes(ea, size) or b""
        if self.cfg.red_cleanup_make_alignment and self.bytes_are_alignment_fill(raw):
            try:
                if ida_bytes.create_align(ea, size, 0):
                    self.stats.red_alignments_created += 1
                    return True
            except Exception:
                pass
        if self.cfg.red_cleanup_make_remaining_bytes:
            try:
                if ida_bytes.create_byte(ea, size, True):
                    self.stats.red_data_bytes_created += size
                    return True
            except Exception:
                pass
        return False

    def cleanup_executable_unknowns(self) -> None:
        for seg in self.iter_segments():
            if not self.is_exec_seg(seg):
                continue
            name = self.seg_name(seg)
            self.progress(f"Resolving unexplored executable bytes in {name or hex(int(seg.start_ea))}", True)
            for run_start, run_end in self.unknown_runs_in_segment(seg):
                self.stats.red_unknown_runs_seen += 1
                self.stats.red_unknown_bytes_seen += run_end - run_start
                self.cleanup_executable_unknown_run(run_start, run_end, name)

    def cleanup_executable_unknown_run(self, start: int, end: int, seg_name: str) -> None:
        # First classify obvious fill/padding. IDA's red bar is not improved by pretending NOP sleds are literature.
        raw = ida_bytes.get_bytes(start, end - start) or b""
        if self.bytes_are_alignment_fill(raw):
            self.make_alignment_or_bytes(start, end - start, raw)
            return

        stride = self.cfg.prologue_sweep_stride_aarch64 if self.is_aarch64 else self.cfg.prologue_sweep_stride_arm32
        stride = max(1, int(stride))
        ea = start
        if stride > 1:
            ea += (-ea) % stride

        while ea < end:
            self.check_cancel()
            flags = ida_bytes.get_full_flags(ea)
            if not ida_bytes.is_unknown(flags):
                ea = self.get_item_end(ea)
                continue

            if self.looks_like_function_start(ea):
                before = self.stats.functions_created
                if self.make_code_and_function(ea, f"red cleanup prologue in {seg_name}", from_prologue=True):
                    self.stats.red_exec_funcs_created += max(0, self.stats.functions_created - before)
                    new_end = self.get_item_end(ea)
                    ea = max(ea + stride, new_end)
                    continue

            # Aggressive but bounded: create a single instruction only if IDA's decoder accepts it.
            # This helps when autoanalysis stopped at a bad branch target and left valid fallthrough red.
            try:
                insn_len = ida_ua.create_insn(ea)
            except Exception:
                insn_len = 0
            if insn_len and insn_len > 0:
                self.stats.red_exec_insns_created += 1
                try:
                    ida_auto.auto_mark(ea, ida_auto.AU_CODE)
                except Exception:
                    pass
                ea += int(insn_len)
                continue

            # Decoder refused it. Consume a small alignment/filler run if present, otherwise make bytes.
            next_ea = min(end, ea + stride)
            chunk = ida_bytes.get_bytes(ea, next_ea - ea) or b""
            self.make_alignment_or_bytes(ea, next_ea - ea, chunk)
            ea = next_ea

    def cleanup_data_unknowns(self) -> None:
        for seg in self.iter_segments():
            if self.is_exec_seg(seg):
                continue
            is_bss = self.is_bss_seg(seg)
            if is_bss and not (self.cfg.scan_bss_segments or self.cfg.red_cleanup_include_bss_segments):
                continue
            try:
                readable = bool(seg.perm & ida_segment.SEGPERM_READ) if seg.perm else True
            except Exception:
                readable = True
            if not readable and not self.cfg.red_cleanup_include_nonreadable_segments:
                continue
            name = self.seg_name(seg)
            self.progress(f"Resolving unexplored data bytes in {name or hex(int(seg.start_ea))}", True)
            for run_start, run_end in self.unknown_runs_in_segment(seg):
                self.stats.red_unknown_runs_seen += 1
                self.stats.red_unknown_bytes_seen += run_end - run_start
                size = run_end - run_start
                loaded = True
                try:
                    loaded = ida_bytes.is_loaded(run_start)
                except Exception:
                    pass

                # BSS/NOBITS and non-readable loader ranges can be enormous. Do not drag
                # them through string scanners or giant get_bytes() calls just to discover
                # that zero is still zero.
                if is_bss or not readable or not loaded:
                    pos = run_start
                    chunk_limit = max(1, int(self.cfg.red_cleanup_aggressive_chunk_size))
                    while pos < run_end:
                        take = min(chunk_limit, run_end - pos)
                        sub_raw = ida_bytes.get_bytes(pos, take) or b""
                        self.make_alignment_or_bytes(pos, take, sub_raw)
                        pos += take
                    continue

                raw = ida_bytes.get_bytes(run_start, size) or b""
                # Re-check for strings in ordinary loaded data only, because earlier passes
                # may have exposed new gaps.
                self.scan_ascii_strings(raw, run_start, name)
                self.scan_utf16_strings(raw, run_start, name)
                # Pointer scan already ran. Whatever remains should become alignment or byte data.
                # Recompute unresolved sub-runs so we don't stomp strings we just created.
                sub_ea = ida_bytes.next_unknown(run_start - 1 if run_start > 0 else run_start, run_end)
                while sub_ea != BADADDR and sub_ea < run_end:
                    sub_start = int(sub_ea)
                    cur = sub_start
                    while cur < run_end and ida_bytes.is_unknown(ida_bytes.get_full_flags(cur)):
                        cur += 1
                    sub_size = cur - sub_start
                    sub_raw = ida_bytes.get_bytes(sub_start, sub_size) or b""
                    self.make_alignment_or_bytes(sub_start, sub_size, sub_raw)
                    sub_ea = ida_bytes.next_unknown(max(sub_start, cur) - 1, run_end)

    def should_cleanup_unknowns_in_segment(self, seg: ida_segment.segment_t, aggressive: bool = False) -> bool:
        if self.is_exec_seg(seg):
            return True
        is_bss = self.is_bss_seg(seg)
        if is_bss and not (self.cfg.scan_bss_segments or self.cfg.red_cleanup_include_bss_segments or aggressive):
            return False
        try:
            readable = bool(seg.perm & ida_segment.SEGPERM_READ) if seg.perm else True
        except Exception:
            readable = True
        if not readable and not (self.cfg.red_cleanup_include_nonreadable_segments or aggressive):
            return False
        return True

    def protect_strings_in_unknown_range(self, ea: int, size: int, seg_name: str) -> None:
        if not (self.cfg.enable_string_recovery and self.cfg.recover_strings_after_red_cleanup):
            return
        if size <= 0:
            return
        try:
            raw = ida_bytes.get_bytes(ea, size) or b""
        except Exception:
            raw = b""
        if not raw:
            return
        # Run both scanners before byte-array fallback. This is intentionally done on
        # unknown ranges only, so it won't rummage through valid pointers or code.
        self.scan_ascii_strings(raw, ea, seg_name)
        self.scan_utf16_strings(raw, ea, seg_name)

    def create_unknown_bytes_forcefully(self, ea: int, size: int, raw: Optional[bytes] = None) -> int:
        """Classify leftover unknown bytes as alignment or byte arrays.

        Returns the number of bytes that became defined. This is intentionally boring:
        after code/string/pointer/function recovery, boring is exactly what remaining
        red bands deserve.
        """
        if size <= 0:
            return 0
        end = ea + size
        before_unknown = size
        # This method is normally called with a known unknown run. Do one cheap sanity
        # check rather than walking giant BSS ranges byte by byte like a doomed monk.
        try:
            if not ida_bytes.is_unknown(ida_bytes.get_full_flags(ea)):
                before_unknown = 0
                sub = ida_bytes.next_unknown(ea - 1 if ea > 0 else ea, end)
                while sub != BADADDR and sub < end:
                    run_start = int(sub)
                    cur = run_start
                    while cur < end and ida_bytes.is_unknown(ida_bytes.get_full_flags(cur)):
                        cur += 1
                    before_unknown += max(0, cur - run_start)
                    sub = ida_bytes.next_unknown(max(run_start, cur) - 1, end)
        except Exception:
            before_unknown = size
        if before_unknown <= 0:
            return 0

        ok = False
        try:
            if raw is None:
                raw = ida_bytes.get_bytes(ea, size) or b""
            ok = self.make_alignment_or_bytes(ea, size, raw)
        except Exception:
            ok = False

        if not ok:
            # create_byte() can fail on odd ranges/items. Fall back to smaller chunks, then
            # finally one byte at a time. Glamorous? No. Effective? Usually.
            pos = ea
            while pos < end:
                self.check_cancel()
                if not ida_bytes.is_unknown(ida_bytes.get_full_flags(pos)):
                    pos = self.get_item_end(pos)
                    continue
                remaining = end - pos
                made = False
                for chunk_size in (0x1000, 0x400, 0x100, 0x40, 0x10, 4, 2, 1):
                    if chunk_size > remaining:
                        continue
                    chunk_raw = ida_bytes.get_bytes(pos, chunk_size) or b""
                    try:
                        if self.make_alignment_or_bytes(pos, chunk_size, chunk_raw):
                            pos += chunk_size
                            made = True
                            break
                    except Exception:
                        pass
                if not made:
                    break

        after_unknown = 0
        sub = ida_bytes.next_unknown(ea - 1 if ea > 0 else ea, end)
        while sub != BADADDR and sub < end:
            run_start = int(sub)
            cur = run_start
            while cur < end and ida_bytes.is_unknown(ida_bytes.get_full_flags(cur)):
                cur += 1
            after_unknown += max(0, cur - run_start)
            sub = ida_bytes.next_unknown(max(run_start, cur) - 1, end)
        created = max(0, before_unknown - after_unknown)
        if created:
            self.stats.red_aggressive_bytes_created += created
        return created

    def aggressive_final_unknown_sweep(self) -> None:
        """Last red-band pass: define remaining unknown bytes in every relevant segment.

        Earlier passes try to recover meaning. This pass is for the leftovers: BSS, loader
        holes, padding, opaque blobs, and bytes IDA refused to decode. It does not delete
        existing code/data and it still respects the explicit max byte cap if configured.
        """
        self.stats.red_aggressive_sweeps += 1
        budget = int(self.cfg.red_cleanup_max_aggressive_bytes or 0)
        used = 0
        self.progress("Aggressive final sweep for remaining red/unknown regions...", True)
        for seg in self.iter_segments():
            if not self.should_cleanup_unknowns_in_segment(seg, aggressive=True):
                continue
            name = self.seg_name(seg) or f"seg_{int(seg.start_ea):X}"
            is_exec = self.is_exec_seg(seg)
            is_bss = self.is_bss_seg(seg)
            for run_start, run_end in self.unknown_runs_in_segment(seg):
                self.check_cancel()
                size = run_end - run_start
                if size <= 0:
                    continue
                if is_bss:
                    self.stats.red_bss_unknown_bytes_seen += size
                try:
                    if not ida_bytes.is_loaded(run_start):
                        self.stats.red_unloaded_unknown_bytes_seen += size
                except Exception:
                    pass

                if is_exec and not self.cfg.red_cleanup_aggressive_exec_tail_bytes:
                    continue

                pos = run_start
                chunk_limit = max(1, int(self.cfg.red_cleanup_aggressive_chunk_size))
                while pos < run_end:
                    if budget and used >= budget:
                        self.record_error("aggressive red cleanup", RuntimeError("stopped after red_cleanup_max_aggressive_bytes"))
                        return
                    take = min(chunk_limit, run_end - pos)
                    if budget:
                        take = min(take, budget - used)
                    raw = ida_bytes.get_bytes(pos, take) or b""
                    if not is_exec and raw and self.cfg.recover_strings_after_red_cleanup:
                        self.protect_strings_in_unknown_range(pos, take, name)
                    # Recompute the current chunk's unknown sub-runs after string rescue so
                    # the byte fallback cannot flatten freshly-created strings.
                    sub = ida_bytes.next_unknown(pos - 1 if pos > 0 else pos, pos + take)
                    created = 0
                    while sub != BADADDR and sub < pos + take:
                        sub_start = int(sub)
                        cur = sub_start
                        chunk_end = pos + take
                        while cur < chunk_end and ida_bytes.is_unknown(ida_bytes.get_full_flags(cur)):
                            cur += 1
                        sub_raw = ida_bytes.get_bytes(sub_start, cur - sub_start) or b""
                        created += self.create_unknown_bytes_forcefully(sub_start, cur - sub_start, sub_raw)
                        sub = ida_bytes.next_unknown(max(sub_start, cur) - 1, chunk_end)
                    used += take
                    if created:
                        self.progress(f"Defined {created} leftover red bytes in {name} @ 0x{pos:X}")
                    pos += take

    def problem_type_ids(self) -> List[int]:
        # These are the public problem-list IDs exposed by IDA 9.3. Use explicit names instead of
        # range(PR_END), because SWIG constants are not guaranteed to be pleasant company.
        names = (
            "PR_NOBASE", "PR_NONAME", "PR_NOFOP", "PR_NOCMT", "PR_NOXREFS",
            "PR_JUMP", "PR_DISASM", "PR_HEAD", "PR_ILLADDR", "PR_MANYLINES",
            "PR_BADSTACK", "PR_ATTN", "PR_FINAL", "PR_ROLLED", "PR_COLLISION", "PR_DECIMP",
        )
        out: List[int] = []
        for n in names:
            try:
                out.append(int(getattr(ida_problems, n)))
            except Exception:
                pass
        return out

    def cleanup_problem_lists(self) -> None:
        self.progress("Rechecking IDA problem-list addresses...", True)
        min_ea = int(ida_ida.inf_get_min_ea())
        max_ea = int(ida_ida.inf_get_max_ea())
        for ptype in self.problem_type_ids():
            try:
                pname = ida_problems.get_problem_name(ptype, True) or str(ptype)
            except Exception:
                pname = str(ptype)
            ea = ida_problems.get_problem(ptype, min_ea)
            seen_this_type = 0
            while ea != BADADDR and ea < max_ea:
                self.check_cancel()
                cur = int(ea)
                seen_this_type += 1
                self.stats.problem_entries_seen += 1
                self.try_repair_problem_at(ptype, cur, pname)
                ea = ida_problems.get_problem(ptype, cur + 1)
            if seen_this_type:
                self.progress(f"Problem list {pname}: checked {seen_this_type}")

    def try_repair_problem_at(self, ptype: int, ea: int, pname: str) -> None:
        mapped = self.is_mapped(ea)
        if not mapped:
            # Address no longer exists in the database. That is stale, not actionable.
            try:
                if self.cfg.red_cleanup_forget_stale_problems and ida_problems.forget_problem(ptype, ea):
                    self.stats.problem_entries_fixed_or_stale += 1
            except Exception:
                pass
            return

        try:
            if self.is_exec_ea(ea):
                flags = ida_bytes.get_full_flags(ea)
                if ida_bytes.is_unknown(flags):
                    try:
                        ida_ua.create_insn(ea)
                    except Exception:
                        pass
                try:
                    ida_auto.auto_mark(ea, ida_auto.AU_CODE)
                    ida_auto.plan_ea(ea)
                    self.stats.problem_entries_requeued += 1
                except Exception:
                    pass
                f = ida_funcs.get_func(ea)
                if f:
                    try:
                        ida_funcs.reanalyze_function(f)
                    except Exception:
                        pass
            else:
                flags = ida_bytes.get_full_flags(ea)
                if ida_bytes.is_unknown(flags):
                    self.make_alignment_or_bytes(ea, 1, ida_bytes.get_bytes(ea, 1) or b"")
                try:
                    ida_auto.plan_ea(ea)
                    self.stats.problem_entries_requeued += 1
                except Exception:
                    pass
        except Exception as exc:
            self.record_error(f"repair problem {pname} @ 0x{ea:X}", exc)

        # Let autoanalysis update the situation. If the problem disappeared or the item is now defined,
        # remove only stale markers by default. Some lists like bad stack can be real warnings.
        try:
            flags = ida_bytes.get_full_flags(ea)
            now_defined = not ida_bytes.is_unknown(flags)
            still_present = ida_problems.is_problem_present(ptype, ea)
            if still_present and self.cfg.red_cleanup_forget_stale_problems and now_defined:
                if ptype in (ida_problems.PR_DISASM, ida_problems.PR_HEAD, ida_problems.PR_ILLADDR, ida_problems.PR_FINAL, ida_problems.PR_ROLLED):
                    if ida_problems.forget_problem(ptype, ea):
                        self.stats.problem_entries_fixed_or_stale += 1
                        return
            if still_present and self.cfg.red_cleanup_forget_unresolved_problem_markers:
                if len(self.stats.problem_entries_forgotten_samples) < int(self.cfg.red_cleanup_report_remaining_samples):
                    desc = ""
                    try:
                        desc = ida_problems.get_problem_desc(ptype, ea) or ""
                    except Exception:
                        pass
                    self.stats.problem_entries_forgotten_samples.append(f"{pname} @ 0x{ea:X} {desc}".rstrip())
                if ida_problems.forget_problem(ptype, ea):
                    self.stats.problem_entries_forgotten_unresolved += 1
                    return
            if still_present:
                self.stats.problem_entries_remaining += 1
                self.stats.problem_entries_remaining_by_type[pname] = self.stats.problem_entries_remaining_by_type.get(pname, 0) + 1
                if len(self.stats.problem_entries_remaining_samples) < int(self.cfg.red_cleanup_report_remaining_samples):
                    desc = ""
                    try:
                        desc = ida_problems.get_problem_desc(ptype, ea) or ""
                    except Exception:
                        pass
                    self.stats.problem_entries_remaining_samples.append(f"{pname} @ 0x{ea:X} {desc}".rstrip())
        except Exception:
            pass

    def count_remaining_unknowns(self) -> None:
        remaining_runs = 0
        remaining_bytes = 0
        by_segment: Dict[str, int] = {}
        samples: List[str] = []
        sample_limit = int(self.cfg.red_cleanup_report_remaining_samples)
        for seg in self.iter_segments():
            if not self.should_cleanup_unknowns_in_segment(seg, aggressive=True):
                continue
            name = self.seg_name(seg) or f"seg_{int(seg.start_ea):X}"
            for run_start, run_end in self.unknown_runs_in_segment(seg):
                size = max(0, run_end - run_start)
                remaining_runs += 1
                remaining_bytes += size
                by_segment[name] = by_segment.get(name, 0) + size
                if len(samples) < sample_limit:
                    samples.append(f"{name}: 0x{run_start:X}-0x{run_end:X} ({size} bytes)")
                if remaining_runs > 1000000:
                    break
        self.stats.red_remaining_unknown_runs = remaining_runs
        self.stats.red_remaining_unknown_bytes = remaining_bytes
        self.stats.red_remaining_unknown_segments = by_segment
        self.stats.red_remaining_unknown_samples = samples
        if remaining_runs:
            self.msg(f"remaining unknown/red runs={remaining_runs}, bytes={remaining_bytes}; see JSON report samples")

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
            self.rebuild_string_list_cache()

    def rebuild_string_list_cache(self) -> None:
        try:
            if self.cfg.clear_string_list_before_rebuild:
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
                    f"{PLUGIN_NAME} v{PLUGIN_VERSION} will create functions, strings, pointer data, offsets, names, and xrefs.\n"
                    "String-safe mode is enabled: existing string literals are protected from delete/recreate passes.\n"
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
            self.preserve_existing_strings()
            self.audit_existing_functions()

            self.recover_entries()
            self.recover_named_exec_locations()
            self.recover_fixups()
            self.recover_arm_exidx()
            self.recover_eh_frame_hdr()
            self.recover_data_pointers()
            self.recover_vtables()
            self.recover_strings()
            self.preserve_existing_strings()
            self.recover_prologues()
            self.recover_red_nav_band()
            self.restore_preserved_strings()
            if self.cfg.audit_new_functions_after_recovery:
                self.audit_existing_functions(only_new=True)
            self.final_autoanalysis()
            self.restore_preserved_strings()
            if self.cfg.red_cleanup_repeat_after_final_autoanalysis:
                self.recover_red_nav_band()
                self.restore_preserved_strings()
                self.rebuild_string_list_cache()

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
            f"functions_audited={s.functions_audited}, suspicious={s.functions_suspicious}, "
            f"decompile_failed={s.functions_decompile_failed}, decompile_recovered={s.functions_decompile_recovered}, "
            f"starts_fixed={s.functions_start_repaired}, ends_fixed={s.functions_end_repaired}, rebuilt={s.functions_rebuilt}, "
            f"ascii_strings={s.strings_created_ascii}, utf16_strings={s.strings_created_utf16}, "
            f"existing_strings_skipped={s.strings_existing_skipped}, string_overlap_skips={s.string_overlap_skips}, "
            f"strings_preserved={s.strings_preserved}, strings_restored={s.strings_restored}, "
            f"vtables={s.vtables_found}, fnptr_tables={s.fnptr_tables_found}, "
            f"ptrs_made={s.pointers_made}, names_set={s.names_set}, "
            f"red_unknown_runs={s.red_unknown_runs_seen}, red_exec_insns={s.red_exec_insns_created}, "
            f"red_data_bytes={s.red_data_bytes_created}, red_alignments={s.red_alignments_created}, "
            f"aggressive_bytes={s.red_aggressive_bytes_created}, remaining_red_runs={s.red_remaining_unknown_runs}, "
            f"remaining_red_bytes={s.red_remaining_unknown_bytes}, problems_seen={s.problem_entries_seen}, "
            f"problems_cleared={s.problem_entries_fixed_or_stale}, problems_remaining={s.problem_entries_remaining}, "
            f"errors={len(s.errors)}"
        )
        if report:
            self.msg(f"report written: {report}")
        if s.errors:
            self.msg("errors:")
            for err in s.errors[:50]:
                self.msg(f"  {err}")


class ArmLinuxSecondPassPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_MOD
    comment = "Second-pass recovery, function audit, and aggressive red-band cleanup for ARM/AArch64 Linux ELF binaries"
    help = "Find and repair missed/misaligned functions, strings, vtables, pointer tables, unwind-derived starts, and stubborn red-band regions"
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
