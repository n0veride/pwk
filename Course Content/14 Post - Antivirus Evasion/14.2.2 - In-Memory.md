
AKA: [PE](Portable%20Executable.md) _Injection_  
  
- Focuses on the manipulation of volatile memory  
- Doesn't write any files to disk - one the main areas of focus for most antivirus products.  
- Main benefits of executing a script, rather than a PE, is that it's difficult for AVs to determine if the script's malicious or not as it's run inside an interpreter and the script itself isn't executable code  
- Even if marked malicious, variable names, comments, and logic can be altered w/o having to re-compile  
  
\*\*\*Several techniques available, but mats only cover PowerShell as the others rely on low level programming like C/C++***  
  
  
#### Remote Process Injection:  
- Injecting payload into valid/ non-malicious PE  
- Most commond method by using Win APIs:  
	→ _OpenProcess_  
- Used to obtain a valid Handle to target a process we have perms to access.  
	→ _VirtualAllocEx_  
- Used to allocate RAM in the context of that process  
	→ _WriteProcessMemory_  
- Copy malicious payload to newly allocated RAM  
	→ _CreateRemoteThread_  
- Executed in RAM in separate thread  
  
  
#### [Reflective DLL](https://andreafortuna.org/2017/12/08/what-is-reflective-dll-injection-and-how-can-be-detected/) Injection: 
- Attempts to load a DLL stored by the attacker in the process memory.  
- Difficult as attacker must write their own version of _LoadLibrary_ that does not rely on a loading a disk-based DLL.  
  
  
#### Process Hollowing: 
- First launch a non-malicious process in a suspended state  
- Image of the process is removed from RAM and replaced w/ the malicious image  
- Process is resumed & malicious code is executed  
  
  
#### Inline Hooking:
- Modifies RAM and introduces a hook into a function to point the execution flow to malicious code  
	→ Hook: Instructions that redirect code exectution.  
- After execution of malicious code, flow returns back to modified function and resumes normal code execution