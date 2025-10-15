# rsrc_parser

A compact IDA Python script that parses the **.rsrc** section of PE executables in **IDA 9.2**.  
It types and comments all common Windows resources — dialogs, strings, menus, accelerators, versions, etc.  
No struct APIs, no dependencies, no nonsense.

---

### ✅ Features
- Parses `.rsrc` → directory → entries → data automatically  
- Supports:
  - Classic `DIALOG` and `DIALOGEX`
  - `STRING`, `MENU`, `ACCELERATOR`, `VERSION`, `DLGINIT`
  - `GROUP_ICON`, `RCDATA`, `HTML`, `MANIFEST`
- Detects and fixes the classic dialog **stray WORD before class (0000/0001, FFFF, 0080–0085)**  
- Annotates DIALOGEX font blocks:
  - `pointsize`, `weight`, `italic`, `charset`, `typeface`
- Writes proper UTF-16 strings, names every resource, and pads alignment bytes cleanly.

---

### 🧠 Usage

In IDA:
```python
File → Script file… → select rsrc_full_parser_ida92_nostructs.py
```
or paste in the console:
```python
import rsrc_full_parser_ida92_nostructs
rsrc_full_parser_ida92_nostructs.run()
```

---

### ⚙️ Options
At the top of the script:
```python
LOG = True            # Output to console
MAKE_COMMENTS = True  # Add comments
MAKE_NAMES = True     # Auto-name entries
SAFE_PREVIEW = 80     # Max chars shown in string comments
```

---

### 🧩 Example Output
```
dw 8                    ; pointsize
dw 0                    ; weight
db 0                    ; italic
db 1                    ; charset=DEFAULT_CHARSET
text "UTF-16LE", 'MS Sans Serif', 0
```

Classic dialog fix:
```
dw pad/align
dw 0FFFFh               ; ordinal
dw 80h                  ; BUTTON
text "UTF-16LE", '&Done', 0
```

---

### 📄 License
MIT. Use it, break it, fix it — just stop staring at untyped `.rsrc` bytes.
