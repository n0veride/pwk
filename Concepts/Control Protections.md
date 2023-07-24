

EIP control protections implemented by Microsoft. Designed to make Buffer Overflows more difficult to exploit.  
  
  
  
### DEP
Set of hardware and software technologies that perform additional checks on memory to help prevent malicious code from running on a system.  
Helps prevent code execution from data pages by raising an exception when attempts are made.  
  
Ex name?: NXCompat  
  
  
  
### ASLR
Randomizes the base addresses of loaded applications and DLLs every time the OS is booted.  
  
  
  
### CFG
Control-Flow Integrity.  
  
Performs validation of indirect code branching, preventing overwrites of function pointers.  
  
  
  
### SafeSEH  
  
Structured Exception Handler Overwrite  
  
An exploit-preventative memory protection technique  
  
  
  
  
### Stack Canaries
  
Tell-tale values added to the stack during binary compilation taht changes every time the program is started as a way to protect critical stack values like the Return Pointer