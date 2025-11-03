# MFC/AFX Fast RTTI & VTable Rebuilder (IDA 9.2)

An aggressive, high-performance vtable and instance reconstructor for **IDA 9.2**, focused on **MFC/AFX binaries**, **MSVC RTTI**, and `.rsrc` identifier tracking.  
It detects vtable blocks, applies structured types, tags instances, resolves RTTI and MFC CRuntimeClass metadata, and adds comments + operand offset info for resource IDs.

This script bridges **low-level vtable recovery**, **RTTI demangling**, **resource indexing**, and **structure application** to dramatically improve analysis clarity on Windows GUI binaries.

**Supports**
- x86 & x64 PE binaries  
- MSVC RTTI (`.?AVFoo@@`)  
- MFC `CRuntimeClass` mapping  
- Local type batching for major performance gains  
- Optional Hex-Rays naming pass  

## Usage

### Script menu
~~~
File → Script file… → select this script
~~~

### IDAPython
~~~python
import mfc_afx_rebuilder_ida92_fast_rtti_mfc
mfc_afx_rebuilder_ida92_fast_rtti_mfc.run()
~~~

## Highlights
- Fast block-scan vtable discovery  
- Struct creation + instance typing  
- RTTI-backed class name resolution  
- `.rsrc` ID detection & operand->offset tagging  
- Hex-Rays integration (optional)  

## License
Use it, break it, fix it, forget it — whatever.  
Just don’t blame the script when IDA decides to act like Windows ME.
