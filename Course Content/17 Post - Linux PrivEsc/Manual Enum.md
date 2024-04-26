

Allows for more control and can help identify more exotic privilege escalation methods that are often missed by automated tools.  

### Enumerate Users:

_Discover the current user + details about said user:_  

  
Linux Ex:  
```bash
id  
uid=1000(student) gid=1000(student) groups=1000(student)
```

We are operating as the _student_ user, which has a User Identifier (UID) and Group Identifier (GID) of 1000  

_Discover other user accounts on the system:_  

  
Linux Ex:
```bash
cat /etc/passwd  
	root:x:0:0:root:/root:/bin/bash  
	daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin  
	bin:x:2:2:bin:/bin:/usr/sbin/nologin  
	...  
	www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin  
	...  
	student:x:1000:1000:Student,PWK,,:/home/student:/bin/bash  
	mysql:x:115:121:MySQL Server,,,:/nonexistent:/bin/false
```
	Lists several user accounts + accounts used by various services such as _www-data_, indicating that a web server is likely installed.  
  
  
  
### Enumerate Hostname:

_**hostname**_ can often provide clues about its functional roles. More often than not, they'll will include identifiable abbreviations - **web** for a web server, **db** for a databaseserver, **dc** for a domain controller, etc.  
  
Linux Ex:  
```bash
student@debian:~$ hostname  
debian
```


The fairly generic name of the Windows machine does point to a possible naming convention within the network that could help us find additional workstations.  
The hostname of the Linux client provides us with information about the OS in use (Debian).  
  
  
  
### Enumerate OS v & Architecture:

At some point, we may need to rely on _kernel exploits_ that specifically exploit vulns in the core of a target's operating system.  

These types of exploits are built for a very specific type of target, specified by a particular operating system & version combination.  

Since attacking a target with a mismatched kernel exploit can lead to system instability (causing loss of access and likely alerting sysadmins), we must gather precise information about the target.  
  
Linux Ex:
```bash
cat /etc/issue  
Debian GNU/Linux 9 \n \l  
  
student@debian:~$ cat /etc/*-release  
PRETTY_NAME="Debian GNU/Linux 9 (stretch)"  
NAME="Debian GNU/Linux"  
VERSION_ID="9"  
VERSION="9 (stretch)"  
ID=debian  
...  
  
uname -a  
Linux debian 4.9.0-6-686 #1 SMP Debian 4.9.82-1+deb9u3 (2018-03-02) i686 GNU/Linux
```
	- **/etc/issue** - Text file containing a message or system identification to be printed before the login prompt  
	- **/etc/*-release** - Machine parsable version/OS identifiers  
	- **uname -a** - Outputs kernel version & architecture  
  
  

### Enumerate Running Processes & Services:

Look at running processes and services that may allow us to elevate our privileges.  
For this to occur, the process must run in the context of a privileged account & must either have insecure permissions or allow us to interact with it in unintended ways.  
  
Linux Ex:  
```bash
ps axu  
USER       PID %CPU %MEM    VSZ   RSS STAT START   TIME COMMAND  
root         1  0.0  0.6  28032  6256 Ss   Nov07   0:03 /sbin/init  
...  
systemd+   309  0.0  0.3  16884  3940 Ssl  Nov07   0:07 /lib/systemd/systemd-timesyncd  
...  
root       514  0.0  1.5  53964 16272 Ss   Nov07   0:00 /usr/bin/VGAuthService  
root       515  0.0  0.2   5256  2816 Ss   Nov07   0:00 /usr/sbin/cron -f  
...  
student   8868  0.0  0.3   7664  3336 pts/0    R+   14:25   0:00 ps axu
```
.
	- **-a** - Select all processes of all users  
	- **-u** - Select by effective user ID (EUID) or name. User-oriented format that provides detailed information about the processes  
	- **-x** - List the processes without a controlling terminal  


  
### Enumerate Networking Info:

Review available network interfaces, routes, and open ports to help determine if the compromised target  
is connected to multiple networks and therefore could be used as a pivot.  

In addition, the presence of specific virtual interfaces may indicate the existence of virtualization or antivirus software.  
  
Also investigate port bindings to see if a running service is only available on a loopback address, rather than on a routable one.  

Investigating a privileged program or service listening on the loopback interface could expand our attack surface and increase our probability of a privilege escalation attack.  

**Linux Ex:**  
```bash
ip a  
...  
4: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group  
    link/ether 00:50:56:8a:4d:48 brd ff:ff:ff:ff:ff:ff  
    inet 10.11.0.128/24 brd 10.11.0.255 scope global ens192  
       valid_lft forever preferred_lft forever  
    inet6 fe80::250:56ff:fe8a:4d48/64 scope link   
       valid_lft forever preferred_lft forever  
5: ens224: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group  
    link/ether 00:50:56:8a:5c:5e brd ff:ff:ff:ff:ff:ff  
    inet 192.168.1.112/24 brd 192.168.1.255 scope global ens224  
       valid_lft forever preferred_lft forever  
    inet6 fe80::250:56ff:fe8a:5c5e/64 scope link   
       valid_lft forever preferred_lft forever
```
	Can see it's also connected to multiple networks: 10.11.0.128 & 192.168.1.112  
  
  
View routing tables (Depending on version: **route** or **routel**):  
```bash
/sbin/route  
Kernel IP routing table  
Destination     Gateway         Genmask         Flags Metric Ref   Use Iface  
default         192.168.1.254   0.0.0.0         UG    0      0       0 ens192  
10.11.0.0       0.0.0.0         255.255.255.0   U     0      0       0 ens224  
192.168.1.0     0.0.0.0         255.255.255.0   U     0      0       0 ens192
```


View all active connections & listening ports:  
```bash
ss -anp  
Netid State   Recv-Q Send-Q  Local Address:Port  Peer Address:Port  
...  
tcp   LISTEN  0      80  127.0.0.1:3306     *:*  
tcp   LISTEN  0      128     *:22                *:*  
tcp   ESTAB   0      48852   10.11.0.128:22      10.11.0.4:52804  
...
```
.  
	-  **-a** - List all connections  
	- **-n** - Avoid hostname resolution  
	- **-p** - List process name the conn belongs to  

  
  
### Enumerate Firewall Status & Rules:

Can be useful during privesc.  
- If a network service is not remotely accessible because it is blocked by the firewall, it is generally accessible locally via the loopback interface.  
- If we can interact with these services locally, we may be able to exploit them to escalate our privileges on the local system.  
- In addition, we can gather information about inbound and outbound port filtering during this phase to facilitate port forwarding and tunneling when it's time to pivot to an internal network.  

  
Linux must have _root_ priv to view firewall rules via  
	We _may_ be able to glean rules through unpriv'd users:  
  
The [iptables-persistent](https://packages.debian.org/search?keywords=iptables-persistent) package on Debian Linux saves firewall rules in specific files under the _/etc/iptables_ directory by default.  

These files are used by the system to restore [netfilter](https://www.netfilter.org/) rules at boot time & are often left with weak permissions, allowing them to be read by any local user on the target system.  
  
We can also search for files created by the **iptables-save** command, which is used to dump the firewall configuration to a file specified by the user.  

This file is then usually used as input for the **iptables-restore** command and used to restore the firewall rules at boot time.  

If a system administrator had ever run this command, we could search the configuration directory (**/etc**) or **grep** the file system for iptables commands to locate the file.  

If the file has insecure permissions, we could use the contents to infer the firewall configuration rules running on the system.  
  
Ex:  
```bash
grep -Hs iptables /etc/*  
/etc/iptables-backup:# Generated by iptables-save v1.6.0 on Tue Jan 21 09:52:22 2020  
  
cat /etc/iptables-backup   
# Generated by iptables-save v1.6.0 on Tue Jan 21 09:52:22 2020  
*filter  
:INPUT DROP [1:36]  
:FORWARD DROP [0:0]  
:OUTPUT ACCEPT [98:9402]  
-A INPUT -i lo -j ACCEPT  
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT  
-A INPUT -p tcp -m tcp --dport 3389 -m state --state NEW -j ACCEPT  
-A INPUT -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT  
-A INPUT -p tcp -m tcp --dport 8080 -m state --state NEW -j ACCEPT  
-A INPUT -i lo -j ACCEPT  
COMMIT  
# Completed on Tue Jan 21 09:52:22 2020  
```
.
	- **-H** - Show file name  
	- **-s** - Supress errors  

  
  
### Enumerate Scheduled Tasks

Systems that act as servers often periodically execute various automated, scheduled tasks.

The scheduling systems on these servers often have somewhat confusing syntax, which is used to execute user-created executable files or scripts.  

When these systems are misconfigured, or the user-created files are left with insecure perms, we can modify these files that will be executed by the scheduling system at a high privilege level.  
  
Linux Ex:  
```bash
ls -lah /etc/cron*  
-rw-r--r-- 1 root root  722 Oct  7  2017 /etc/crontab  
  
/etc/cron.d:  
-rw-r--r--   1 root root  285 May 29  2017 anacron  
-rw-r--r--   1 root root  712 Jan  1  2017 php  
-rw-r--r--   1 root root  102 Oct  7  2017 .placeholder  
  
/etc/cron.daily:  
-rwxr-xr-x   1 root root  311 May 29  2017 0anacron  
...  
-rwxr-xr-x   1 root root  249 May 17  2017 passwd  
-rw-r--r--   1 root root  102 Oct  7  2017 .placeholder  
  
/etc/cron.hourly:  
-rw-r--r--   1 root root  102 Oct  7  2017 .placeholder  
  
/etc/cron.monthly:  
-rwxr-xr-x   1 root root  313 May 29  2017 0anacron  
-rw-r--r--   1 root root  102 Oct  7  2017 .placeholder  
  
/etc/cron.weekly:  
-rwxr-xr-x   1 root root  312 May 29  2017 0anacron  
-rwxr-xr-x   1 root root  723 Dec 13  2016 man-db  
-rw-r--r--   1 root root  102 Oct  7  2017 .placeholder
```

****NOTE:** Sysadmins often add their own scheduled tasks in the _/etc/crontab_ file.  
These tasks should be inspected carefully for insecure file permissions as most jobs in this particular file will run as root.  
```bash
cat /etc/crontab   
...  
  
SHELL=/bin/sh  
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin  
  
# m h dom mon dow user command  
17 * * * * root    cd / && run-parts --report /etc/cron.hourly  
25 6 * * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )  
47 6 * * 7 root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )  
52 6 1 * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )  
5 0 * * * root /var/scripts/user_backups.sh
```


  
### Enumerate Installed Apps & Patches  
  
Linux Ex:  
```bash
dpkg -l | more  
Desired=Unknown/Install/Remove/Purge/Hold  
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend  
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)  
||/ Name                Version           Architecture  Description  
+++-===================-=================-=============-=============================  
ii  acl                 2.2.52-3+b1       i386          Access control list utilities  
ii  adduser             3.115             all           add and remove users and grou  
ii  adwaita-icon-theme  3.22.0-1+deb9u1   all           default icon theme of GNOME  
ii  alsa-utils          1.1.3-1           i386          Utilities for configuring and  
ii  anacron             2.3-24            i386          cron-like program that doesn'  
ii  ant                 1.9.9-1           all           Java based build tool like ma  
ii  ant-optional        1.9.9-1           all           Java based build tool like ma  
ii  apache2             2.4.25-3+deb9u4   i386          Apache HTTP Server
```



### Enumerate RW Files & Directories:

Files with insufficient access restrictions can create a vulnerability that can grant an attacker elevated privileges.

This most often happens when an attacker can modify scripts or binary files that are executed under the context of a privileged account.

In addition, sensitive files that are readable by an unprivileged user may contain important information such as hardcoded credentials for a database or a service account.  
  

  
Linux Ex:
```bash
find / -writable -type d 2>/dev/null  
	/usr/local/james/bin  
	/usr/local/james/bin/lib  
	/proc/16195/task/16195/fd  
	/proc/16195/fd  
	/proc/16195/map_files  
	/home/student  
	/home/student/.gconf  
	/home/student/.gconf/apps  
	/home/student/.gconf/apps/gksu  
	/home/student/Music
	```



### Enumerate Unmounted Disks

List drives that are currently mounted & drives physically connected but not mounted & check mount permissions.    
  
Linux Ex:
```bash
cat /etc/fstab   
# /etc/fstab: static file system information.  
...  
# <file system> <mount point>   <type>  <options>       <dump>  <pass>  
# / was on /dev/sda1 during installation  
UUID=fa336f7a-8cf8-4cd2-9547-22b08cf58b72 /     ext4    errors=remount-ro 0       1  
# swap was on /dev/sda5 during installation  
UUID=8b701d25-e290-49dc-b61b-1b9047088150 none  swap    sw              0       0  
/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0  
  
student@debian:~$ mount  
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)  
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)  
udev on /dev type devtmpfs (rw,nosuid,relatime,size=505664k,nr_inodes=126416,mode=755)  
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)  
tmpfs on /run type tmpfs (rw,nosuid,noexec,relatime,size=102908k,mode=755)  
/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro,data=ordered)  
securityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)  
...
```

*****NOTE:** Keep in mind that the sysadmin might have used custom configs or scripts to mount drives that are not listed in the_/etc/fstab_ file.  
Because of this, it's good practice to notonly scan _/etc/fstab_, but to also gather information about mounted drives with **mount**.  
  
  
Output reveals a swap partition and the primary ext4 disk of this Linux system.  
Furthermore, we can use [lsblk](OS%20Commands.md#lsblk) to view all available disks.  
  
```bash
/bin/lsblk  
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT  
fd0      2:0    1    4K  0 disk   
sda      8:0    0    5G  0 disk   
├─sda1   8:1    0  4.7G  0 part /  
├─sda2   8:2    0    1K  0 part   
└─sda5   8:5    0  334M  0 part [SWAP]
```


The sda drive consists of three different partitions, which are numbered.  
In some situations, showing information for all local disks on the system might reveal partitions that are not mounted.  

Depending on the system configuration (or misconfiguration), we then might be able to mount those partitions and search for  
interesting documents, credentials, or other information that could allow us to escalate our privileges or get a better foothold in the network.  


  
### Enumerate Device Drivers & Kernel Modules
  
Similar to enumerating through apps & their patches, this is useful for finding exploits online for privesc.  
  

Linux list kernel modules Ex:  
```bash
lsmod  
Module                  Size  Used by  
fuse                   90112  3  
appletalk              32768  0  
ax25                   49152  0  
ipx                    28672  0  
p8023                  16384  1 ipx  
p8022                  16384  1 ipx  
psnap                  16384  2 appletalk,ipx  
llc                    16384  2 p8022,psnap  
evdev                  20480  5  
vmw_balloon            20480  0  
crc32_pclmul           16384  0  
...  
i2c_piix4              20480  0  
libata                192512  2 ata_piix,ata_generic  
scsi_mod              180224  4 sd_mod,libata,sg,vmw_pvscsi  
floppy                 57344  0
```

Similar to **driverquery.exe** in Windows, this only lists kernel modules. For more info on a specific module:  
```bash
/sbin/modinfo libata  
filename:       /lib/modules/4.9.0-6-686/kernel/drivers/ata/libata.ko  
version:        3.00  
license:        GPL  
description:    Library module for ATA devices  
author:         Jeff Garzik  
srcversion:     7D8076C4A3FEBA6219DD851  
depends:        scsi_mod  
retpoline:      Y  
intree:         Y  
vermagic:       4.9.0-6-686 SMP mod_unload modversions 686  
parm:           zpodd_poweroff_delay:Poweroff delay for ZPODD in seconds (int)  
...
```



### Enumerate AutoElevate Binaries

Interesting OS-specific"shortcuts" to privilege escalation....  
  
Should check the status of the _AlwaysInstallElevated_ registry setting. 

If this key is enabled (set to 1) in either HKEY_CURRENT_USER or HKEY_LOCAL_MACHINE, any user can run Windows Installer packages with elevated privileges.  
  
  
Linux Ex:  
```bash
find / -perm -u=s -type f 2>/dev/null  
/usr/lib/eject/dmcrypt-get-device  
/usr/lib/openssh/ssh-keysign  
/usr/lib/policykit-1/polkit-agent-helper-1  
/usr/lib/dbus-1.0/dbus-daemon-launch-helper  
/usr/lib/xorg/Xorg.wrap  
/usr/sbin/userhelper  
/usr/bin/passwd  
/usr/bin/sudo  
/usr/bin/chfn  
/usr/bin/newgrp  
/usr/bin/pkexec  
/usr/bin/gpasswd  
/usr/bin/chsh  
/bin/mount  
/bin/su  
/bin/fusermount  
/bin/umount  
...
```


Normally, when running an executable, it inherits the permissions of the user that runs it.  
However, if the SUID permissions are set, the binary will run with the permissions of the file owner.  
Meaning, that if a binary has the SUID bit set and the file is owned by root, any local user will be able to execute that binary with elevated privileges.  
  
Exploitation of _SUID_ binaries will vary based on several factors. For example, if **/bin/cp** (the _copy_ command) were [SUID](Perms%20-%20SUID.md), we could copy and overwrite sensitive files such as _/etc/passwd_.