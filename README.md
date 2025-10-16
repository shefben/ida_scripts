# IDA Resource Tools

This repository contains two complementary IDA Pro 9.2 scripts for working with the `.rsrc` section of Windows PE binaries.  
Together, they allow both **formatting and visualization** of Windows resources directly inside IDA.

NOTE:
This can be run as either a python script within IDA or as a plugin!
---

## 🧠 Scripts Overview

### `format_rsrc.py`
An **IDA in-database formatter** that dissects and annotates the `.rsrc` section in PE files.  
It identifies resource directories, names, and data entries, applying type-aware parsing for common resource types such as dialogs, menus, icons, cursors, and version information.

**Key features:**
- Walks the `.rsrc` tree recursively and adds structure names and comments.  
- Recognizes standard resource types (`DIALOG`, `MENU`, `STRING`, `VERSION`, `ICON`, etc.).  
- Creates IDA string literals, defines words/dwords, and sets readable labels for each entry.  
- Annotates version info blocks, dialog templates, and accelerator tables.  
- Requires no external dependencies — it runs entirely inside IDA using its native modules (`ida_bytes`, `ida_segment`, `ida_kernwin`, etc.):contentReference[oaicite:0]{index=0}:contentReference[oaicite:1]{index=1}.

---

### `resource_viewer.py`
A **GUI-based resource browser and previewer** built with PySide6.  
It scans the parsed `.rsrc` section and displays a navigable tree of resource entries, allowing interactive previews of embedded icons, cursors, bitmaps, dialogs, and menus.

**Key features:**
- PySide6 GUI for interactive viewing.  
- Previews icons and cursors (including legacy monochrome and PNG/DIB formats):contentReference[oaicite:2]{index=2}.  
- Displays dialogs and menus using live Win32 previews.  
- Decodes version information, accelerators, and string tables.  
- Integrates with IDA logging and runs as either a standalone script or plugin (`run()` entrypoint).  
- Depends on `PySide6` and optionally `Pillow` for image handling.

---

## ⚙️ Installation

### Requirements
Each script includes its own `requirements.txt`:
- `format_rsrc.py` → *no external dependencies*  
- `resource_viewer.py` → requires `PySide6` and `Pillow`

Install them using IDA's bundled Python interpreter:

<pre><code>"C:\Program Files\IDA 9.2\python\python.exe" -m pip install -r requirements.txt
</code></pre>

### Plugin Setup (optional)
To use `resource_viewer.py` as a plugin:
1. Place the scripts in IDA’s `plugins/` directory (e.g. `plugins/`).
3. Restart IDA — the plugins will appear in the plugin menu.

---

## 🧩 Example Workflow
1. Run `format_rsrc.py` in IDA to annotate the `.rsrc` tree with labels and structures.  
2. Launch `resource_viewer.py` to browse and preview icons, dialogs, and other resource items interactively.  

---

## 📄 License
Use freely at your own risk. These scripts interact directly with PE resource structures inside IDA; expect quirks with malformed binaries or unusual encodings.
