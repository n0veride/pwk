
Pass the Hash tool  
  

Usage:  
```bash
winexe -U <domain/username>%<password> //<targetIP> cmd.exe
```


To execute an application like cmd on the remote computer using the SMB protocol,  
admin privileges are required due to auth'ing to the administrative share C$ and subsequent creation of a Windows service.  


Behind the scenes, the format of the NTLM hash we provided was changed into a NetNTLM version 1 or 2 format during the auth process.  
We can capture these hashes using MITM or poisoning attacks & either crack them or relay them.  
  
For example, some apps like IE and Windows Defender use the Web Proxy Auto-Discovery Protocol (WPAD) to detect proxy settings.  
If we are on the local network, we could poison these requests and force NetNTLM auth with a tool like _Responder.py_,  
which creates a rogue WPAD server designed to exploit this security issue.  
Since poisoning is highly disruptive to other users, tools like Responder.py should never be used in the labs.