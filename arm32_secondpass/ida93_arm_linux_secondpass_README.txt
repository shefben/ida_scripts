IDA 9.3 ARM Linux Second Pass Plugin
====================================

Version: 1.4.0
Target: IDA Pro 9.3, Python 3.13, ARM/AArch64 Linux ELF binaries

Install
-------
Copy ida93_arm_linux_secondpass.py into your IDA 9.3 plugins directory, restart IDA, then run:

    Edit -> Plugins -> ARM Linux Second Pass

Or run once with:

    File -> Script file... -> ida93_arm_linux_secondpass.py

Hotkey
------
Ctrl+Alt+Shift+A

Important v1.4.0 string-safety changes
--------------------------------------
This build protects existing string literals from broad rescans and red cleanup:

* Existing string literals are not deleted/recreated during string recovery.
* Ranges overlapping existing strings are skipped by string creation and alignment/byte fallback.
* `ida_strlist.clear_strlist()` is disabled by default.
* Aggressive red cleanup remains disabled by default.
* Unknown-byte fallback remains disabled by default.
* The run confirmation dialog now displays the actual plugin version and string-safe mode notice.
* The JSON report and summary include string-safety counters.

Useful config defaults
----------------------
Inside SecondPassConfig:

    audit_decompile_current_functions = False
    audit_rebuild_undecompilable_functions = False
    clear_string_list_before_rebuild = False
    red_cleanup_make_remaining_bytes = False
    red_cleanup_aggressive_final_sweep = False
    red_cleanup_forget_unresolved_problem_markers = False
    never_delete_existing_strings = True

Outputs
-------
When enabled, the plugin writes this report beside the IDB:

    <database>.secondpass_report.json

Rescue script
-------------
If an older build damaged your Strings window, run ida93_string_rescue.py once through:

    File -> Script file... -> ida93_string_rescue.py

