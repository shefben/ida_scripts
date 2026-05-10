IDA 9.3 ARM Linux Second Pass Plugin
=====================================

File:
  ida93_arm_linux_secondpass.py

Install:
  Copy ida93_arm_linux_secondpass.py into your IDA 9.3 plugins directory, then restart IDA.

Run:
  Edit -> Plugins -> ARM Linux Second Pass
  Hotkey: Ctrl-Alt-Shift-A

Script-mode test:
  File -> Script file... -> select ida93_arm_linux_secondpass.py

What it recovers:
  - Entry/export functions
  - Named executable labels not already converted to functions
  - Relocation/fixup-derived function pointers
  - ARM32 .ARM.exidx PREL31 function starts
  - .eh_frame_hdr FDE function starts for common Linux DW_EH_PE encodings
  - Data-segment code pointers, including Thumb-bit normalization on ARM32
  - Itanium C++ ABI-style vtables
  - Raw function-pointer tables
  - Missed ASCII and UTF-16 C strings
  - Conservative AArch64, ARM, and Thumb prologue sweep candidates
  - Pointer-sized data items, offset operands, and data xrefs

Output:
  - IDA database modifications: functions, strings, pointer data, names, xrefs
  - JSON report beside the IDB: <database>.secondpass_report.json

Notes:
  - The plugin is intentionally conservative about not splitting existing functions.
  - It avoids clobbering code and existing non-byte data during string creation.
  - For ARM32 Thumb function pointers, it clears the low bit and attempts to set the T segment register at the target.
  - If you want more aggressive scanning, edit SecondPassConfig at the top of the file.
