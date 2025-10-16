# Resource Viewer for IDA 9.2

A Windows-only .rsrc browser with live previews for IDA Pro 9.2 (PySide6).  
Provides tree navigation of resources and previewing for icons, cursors, bitmaps, dialogs, menus, version info, accelerators, string tables and more.

This viewer was implemented as a single module: `resource_viewer.py`.

---

## Features
- Parse `.rsrc` section and build a resource index (types / names / langs).
- Preview icons, cursors (legacy monochrome and PNG/DIB), bitmaps (via Pillow), dialogs via a real native Windows dialog host (threaded), and menus (native window).
- RC-style dumps for dialogs & menus (best-effort).
- Thumbnail strip for icon/cursor groups.
- Uses PySide6 for the main UI; optionally uses Pillow (`PIL`) for richer image support.

---

## Requirements
- IDA Pro 9.2 (Windows). This was written for IDA’s bundled Python environment.
- PySide6 (IDA 9.2 typically ships with PySide6).
- Pillow (for image payloads)

### Pip installation command:
```
python -m pip install -r requirements.txt
```
---

## Installing as an IDA plugin
1. Place `resource_viewer.py` somewhere IDA can import it (recommended: `<IDA_INSTALL_DIR>/plugins/resource_viewer.py`).
2. Restart IDA. The plugin will register under Plugins and can be launched from IDA's Plugins menu or via the plugin manager.
3. An entry is automtically added into the view menu for viewing the window.

---

## Quick run (without making a plugin)
1. Open IDA 9.2 on a Windows PE binary that contains a `.rsrc` section.
2. In IDA's Python script window, just press run and the resource dialog will be visible



