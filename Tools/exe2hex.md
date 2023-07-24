
Inline file transfer using in-built Windows tools (DEBUG.exe or PowerShell)  

Usage:
```bash
exe2hex [options]  
```
  

Options:  
**-h, --help** - Show this help message and exit  
**-x** EXE - The EXE binary file to convert  
**-s** - Read from STDIN  
**-b** BAT - BAT output file (DEBUG.exe method - x86)  
**-p** POSH - PoSh output file (PowerShell method - x86/x64)  
**-e** - URL encode the output  
**-r** TEXT - pRefix - text to add before the command on each line  
**-f** TEXT - suFfix - text to add after the command on each line  
**-l** INT - Maximum HEX values per line  
**-c** - Clones and compress the file before converting (-cc for higher compression)  
**-t** - Create a Expect file, to automate to a Telnet session.  
**-w** - Create a Expect file, to automate to a WinEXE session.  
**-v** - Enable verbose mode