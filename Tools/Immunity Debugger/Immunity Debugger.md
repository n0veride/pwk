

Proxy between an application and the CPU allowing us to stop the execution flow to inspect the content of the registers and the process memory space.  
  
No Linux app support.  
  
  
When opening file (BO vuln binary), can add arguments at bottom of Open Box.  
  
![[ImmunityDebugger.png]]

App divided into 4 panes:  
	**Upper Left** - Shows assembly instructions. (Disassembly window)  
			Instruction highlighted with blue bar is next to be executed.  
	**Upper Right** - Shows all registers, their data, and their addresses  
	**Lower Right** - Shows the stack and its contents  
			Columns: memory address, hex data (DWORD) contained there, data in ASCII, & dynamic commentary on additional info (when available).  
	**Lower Left** - Shows contents of memory at any given address.  
			Columns: memory address, hex dump, data in ASCII  
			Can Rt-click to view data in different formats  
  
  
  
When opening binary, the execution flow will be paused at the _entry point_ - not always _main_!  
Must find where _main_ function is located in memory  
Rt-Click in Disassembly window > Search For > All referenced text strings  
Double clicking on line returns to Disassembly windows and within the _main_ function  
  
**F7** / **Debug > Step into** -- Follow execution flow step by step into a given function call (As it's within a function, the memory addresses will be different)  
**F8** / **Debug > Step over** -- Execute the entire function and return from it.  
**F2** -- Set a Breakpoint on selected line (memory address of line will highlight in light blue)  
**F9** / **Debug > Run** -- Continue execution flow  
**Ctrl F9** / **Debug > Execute till return** -- Finishes execution of function until return call to _main_  
  
  
Double clicking on a stack item's memory allows monitoring of write operations occurring at that address and will change addresses to show relative offsets  
  
  
Can use [mona](mona.py.md) module to search for return addresses for [Buffer Overflows](11%20-%20BO%20Win.md).