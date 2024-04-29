  
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



Normally, when running an executable, it inherits the permissions of the user that runs it.  
However, if the SUID permissions are set, the binary will run with the permissions of the file owner.  
Meaning, that if a binary has the SUID bit set and the file is owned by root, any local user will be able to execute that binary with elevated privileges.  
  
Exploitation of _SUID_ binaries will vary based on several factors. For example, if **/bin/cp** (the _copy_ command) were [SUID](Perms.md#SUID), we could copy and overwrite sensitive files such as _/etc/passwd_.