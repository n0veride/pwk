
Various scripts can be used to automate target enumeration.  
  
Although these tools perform many automated checks, bear in mind that every system is different, and unique one-off system changes will often be missed by these types of tools.  
For this reason, it's important to watch out for unique configurations that can only be caught by manual inspection.  

  
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