
GNU Debugger  
  
  
Proxy between an application and the CPU allowing us to stop the execution flow to inspect the content of the registers and the process memory space.  
  
Computerphile shows use of GDB for buffer overflows: [https://youtu.be/1S0aBV-Waeo?t=373](https://youtu.be/1S0aBV-Waeo?t=373)  
  
  
Most usual way to run GDB:  
```bash
gdb <program/ pid> <core_file>
```


**b / break** _\<file\>_**:**_<function/ line #>_ - Set a breakpoint at _\<function/ line#\>_  
	- If working w/ multiple files, always good to specify file\:function/ line #  
	- When breaking at a memory address use *****: **break *0x08048499**  
**c** / **continue** - Continue running  
**disas** / **disassemble** _\<function\>_ - Disassemble's the _\<function\>_  
**disable** - Disables all breakpoints  
**l** / **list** _<#>_- Print out source code centered around line we're currently on.  
	 - **l** / **list** again shows next set of lines.  
	 - Can add line _#_ to specifically list code from that line  
**make** - Utilize C's **make** cmd within GDB  
**n** / **next** - Execute and goto next line of code  
**p** / **print** _\<var\>_- Prints current _variable_. Can set a variable: p var = 1  
**r** / **run** - Run program  
	 - Can use python w/in GDB in order to print multiple characters to test the buffer boundaries.  
	 - **run $(python -c 'print “A” * 506)**  
**x** / **examine**  
**q** / **quit** - Quit  
  
**info locals** - Prints all in-scope local variables  
**info func** - Prints all the functions and their addresses  
**info registers** - Prints all register info (addresses, etc)  
  
  
Hitting enter w/o typing anything, GDB will repeat last command used.  
  
  
To find out where memory-address-wise the stack starts/ where the buffer starts to overflow:  
	- **x/20x $esp** - Print out the first 20 addresses (hex values, offset first) in the upper region of the stack (using the stack pointer register)