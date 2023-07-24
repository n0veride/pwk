
Access level that the system processes, users, and groups have to files/ directories
![[permissions.png]]

From [GeekDiary](https://www.thegeekdiary.com/linux-unix-examples-of-find-command-to-find-files-with-specific-sets-of-permissions/):  
  
1st bit is for special permission e.g. [SUID(4)](Perms%20-%20SUID.md) [SGID(2)](Perms%20-%20SGID.md) or [sticky bit(1)](Perms%20-%20Sticky%20Bit.md)  
2nd bit is for owner permission  
3rd bit is for group permission  
4th bit is for others permission  
  
4 - Read Permission (r)  
2 - Write Permission (w)  
1 - Executable Permission (x)  
  
  
Find existing binaries w/ SUID or GUID perms on them:  
```bash
find / -perm -u=s -type f 2>/dev/null; find / -perm -4000 -o- -perm -2000 -o- -perm -6000
```

1. Command to find files with (group or other or both) writable permission and SET UID set .  
```bash
find / -perm /022 -and -perm -4000 -exec ls -ldb {} ;
``` 
						^^^^           ^  
						| | | |        |-- So the SUID is 4  
						| | | |-- Other is writable (2)  
						| | |--Group permission is writable (2)  
						| |-- No owner permission mentioned (0)  
						|-- As the logic is OR - group or other or both  
So the logic is : ( group writable OR other writable ) AND SUID set  

2. Command to list files with other writable excluding sticky bit set.  
```bash
find / -perm -002 -not -perm -1000 -exec ls -ldb {} ;
```  
						^^^^           ^  
						| | | |        |-- So the sticky bit is set (1)  
						| | | |-- Other is writable (2)  
						| | |--No group permission mentioned (0)  
						| |-- No owner permission mentioned (0)  
						|-- Well it does not matter if it is "-" or "/" as there is only one condition mentioned  
Now the logic here is : Other writable NOT sticky bit set  
  
  
  
****  
It is often the case that admins aren't familiar with their apps but still assign the SUID/GUID bits, which leads to a high-security risk.  

Such programs may contain functions that allow the execution of a shell from the pager, such as the application "journalctl."  

If the admin sets the SUID bit to "journalctl", any user with access to this application could execute a shell as root.