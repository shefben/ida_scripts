# UltraFixup Second Pass (IDA 9.2)

A focused second-pass auto-analysis helper for IDA 9.2.  
It digs deeper after initial analysis to identify missed functions, recover strings, and create real vtable structs.

NOTE:
THIS SCRIPT CAN RUN FOR A VERY LONG TIME IF THE BINARY IS LARGE!
It took over 3 minnutes for the script to run through a 3mb binary; but it does help and the time taken is worth it!

## Features
- Expands unknown executable regions into instructions  
- Detects function prologs & long linear code runs  
- Auto-creates functions where IDA slacked  
- Reanalyzes functions across multiple passes  
- Recovers ASCII & UTF-16 strings  
- Builds vtable structs & applies proper types  
- Stops when no more progress is possible (wish some people did that)

## Usage

### Menu
~~~
File → Script file… → select this script
~~~

### IDAPython Console
~~~python
import ultrafixup_second_pass
ultrafixup_second_pass.run()
~~~

## Notes
- Supports x86 & x64 binaries  
- Respects existing labels unless told otherwise  
- Uses public IDA 9.2 APIs only  
- Run after initial auto-analysis finishes

## License
Do whatever you want.  
If it breaks, congratulations: you own two broken halves.
