

4 techniques to obfuscate files on-disk:  
  
#### Packers: 
- Originally designed to reduce the size of an executable while maintaining a functionally equivalent/ completely new binary structure.  
	- Ex: [upx](upx.md) is a [PE](Portable%20Executable.md) tool  
- Results in new signature  
- Not sufficient on its own for evasion of modern AV scanners.  
  
  
#### Obfuscators:  
- Reorganize & mutate code to make it difficult to re-engineer  
	- Replacing instructions w/ semantically equivalent ones  
	- Inserting _dead code_  
	- Splitting/ reordering functions  
	- etc  
- Marginally effective against sig-based AVs  
  
  
#### Crypters:
- Cryptographically alters code  
- Adds decrypting stub that restores OG code upon execution.  
	- Decryption happens _in-memory_  
- One of the most effective evasion techniques.  
  
  
#### Software Protectors:
- A range of features and technologies to help protect the executable file from hacking, analysis, modification and disassembly.  
- Designed for legit purposes, but can be utilized for AV evasion  
  
Highly effective antivirus evasion requires a combination of all of the above techniques + other advanced ones, including anti-reversing, anti-debugging, virtual machine emulation detection, etc.