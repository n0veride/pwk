


Searches the addresses within a DLL file for the JMP ESP instructions for RET addr for a Buffer Overflow  
  
  
Usage:  
```bash
./msfpescan <input> <mode> <options>
```

  
  
Inputs:  
**-f** _\<file\>_ - Read in PE file  
**-d** _\<dir\>_ - Process memdump output  
  
Modes:  
**-j** _\<reg\>_ - Search for jump equivalent instructions  
**-s** - Search for _pop+pop+ret_ combinations  
**-x** _\<regex\>_ - Search for regex match  
**-a** _\<addr\>_ - Show code at specified virtual addr  
**-D** - Display detailed PE info  
**-S** - Attempt to ID the packer/ compiler  
  
Options:  
**-A** _\<count\>_ - Number of bytes to show after match  
**-B** _\<count\>_ - Number of bytes to show before match  
**-I** _\<addr\>_ - Specify an alternate ImageBase  
**-n** - Print disassembly of matched data