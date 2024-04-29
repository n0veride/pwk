  
### Enumerate Firewall Status & Rules:
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
  
Exploitation of _SUID_ binaries will vary based on several factors. For example, if **/bin/cp** (the _copy_ command) were [SUID](Perms.md#SUID), we could copy and overwrite sensitive files such as _/etc/passwd_.