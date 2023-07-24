
Various scripts can be used to automate target enumeration.  
  
Although these tools perform many automated checks, bear in mind that every system is different, and unique one-off system changes will often be missed by these types of tools.  
For this reason, it's important to watch out for unique configurations that can only be caught by manual inspection.  
  
  
Win example: [windows-privesc-check](Windows-Privesc-Check.md)  
  
List info about user groups on the system:  
```powershell
c:\Tools\privilege_escalation\windows-privesc-check-master>windows-privesc-check2.exe --dump -G  
  
windows-privesc-check v2.0 (http://pentestmonkey.net/windows-privesc-check)  
  
[i] TSUserEnabled registry value is 0. Excluding TERMINAL SERVER USER  
  
Considering these users to be trusted:  
* BUILTIN\Power Users  
* BUILTIN\Administrators  
* NT SERVICE\TrustedInstaller  
* NT AUTHORITY\SYSTEM  
  
[i] Running as current user.  No logon creds supplied (-u, -D, -p).  
...  
============ Starting Audit at 2019-09-22 12:45:56 ============  
  
[+] Running: dump_misc_checks  
[+] Host is not in domain  
 [+] Checks completed  
  
[+] Running: dump_groups  
[+] Dumping group list:  
BUILTIN\Administrators has member: CLIENT251\Administrator  
BUILTIN\Administrators has member: CLIENT251\admin  
BUILTIN\Administrators has member: [unknown]\S-1-5-21-2715734670-1758985447-1278008508  
BUILTIN\Administrators has member: [unknown]\S-1-5-21-2715734670-1758985447-1278008508  
BUILTIN\Guests has member: CLIENT251\Guest  
BUILTIN\IIS_IUSRS has member: NT AUTHORITY\IUSR  
BUILTIN\Remote Desktop Users has member: CLIENT251\student  
BUILTIN\Users has member: NT AUTHORITY\INTERACTIVE  
BUILTIN\Users has member: NT AUTHORITY\Authenticated Users  
BUILTIN\Users has member: CLIENT251\student  
BUILTIN\Users has member: [unknown]\S-1-5-21-2715734670-1758985447-1278008508-513  
[+] Checks completed
```

  
Linux example: [unix_privesc_check](Unix-Privesc-Check.md)  
```bash
student@debian:~$ ./unix-privesc-check standard > output.txt  
  
...  
Checking for writable config files  
############################################  
    Checking if anyone except root can change /etc/passwd  
WARNING: /etc/passwd is a critical config file. World write is set for /etc/passwd  
    Checking if anyone except root can change /etc/group  
    Checking if anyone except root can change /etc/fstab  
    Checking if anyone except root can change /etc/profile  
    Checking if anyone except root can change /etc/sudoers  
    Checking if anyone except root can change /etc/shadow  
...
```
	Lots of output, so best to save to file & **grep -i warning**  
  
  
This output reveals that anyone on the system can edit the _/etc/passwd_ file!  
This is quite significant as it allows attackers to easily elevate their privileges or create user accounts on the target.