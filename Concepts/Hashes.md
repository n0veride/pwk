
[PW Attacks](15.x%20-%20PW%20Attacks.md)  
  
In Linux, they're stored in the _/etc/shadow_ file (duh)  
  
In Windows, they're stored in the SAM (Security Accounts Manager)  
To deter from pw attacks, MS introduced the SYSKEY feature (partially encrypts the SAM file)  
  
Win NT-based OS's (Up to & incl Win 2003) store 2 diff pw hashes:  
• LM - LAN Manager (based on DES)  
• NTLM - NT LAN Manager (uses MD4)  
  
LM is SUPER weak: converted to upper-case, no salts, & any pw longer than 7 chars is padded to 14, split into 2 strings, & then separately hashed.  
  
Win Vista & on disables LM by default & uses NTLM  
• Case sensitive  
• Supports Unicode chars  
• Not split  
• Still not salted  
  
SAM can't be copied while OS is running as there's a kernel system lock on it, but mimikatz can dump it.  
  
  
Windows hash format:  
  
User : LM : NTLM  
Ex:  
```bash
offsec:aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425
```


Passwords that are hashed in anything other than LM or NTLM, are divided into subfields (denoted by ‘**$**’):  
  
Ex:  
```bash
kali@kali:~$ sudo grep root /etc/shadow  
	root:$6$Rw99zZ2B$AZwfboPWM6z2tiBeK.EL74sivucCa8YhCrXGCBoVdeYUGsf8iwNxJkr.wTLDjI5poygaUcLaWtP/gewQkO7jT/:17564:0:99999:7:::
```

no $ - DES
$1 - MD5
$2 - Blowfish
$5 - SHA-256
$6 - SHA-512  
$y - Crypt
$Rw99zZ2B - Salt used