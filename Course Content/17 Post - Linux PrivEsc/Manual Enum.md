

Allows for more control and can help identify more exotic privilege escalation methods that are often missed by automated tools.  



### Enumerate Users:

_Discover the current user + details about said user:_  
  
Windows Ex:  
```powershell
C:\Users\student>whoami  
  
client251\student  
  
C:\Users\student>net user student  
  
User name                    student  
Full Name  
Comment  
User's comment  
Country/region code          000 (System Default)  
Account active               Yes  
Account expires              Never  
  
Password last set            3/31/2018 10:37:35 AM  
Password expires             Never  
Password changeable          3/31/2018 10:37:35 AM  
Password required            No  
User may change password     Yes  
  
Workstations allowed         All  
Logon script  
User profile  
Home directory  
Last logon                   11/8/2019 12:56:15 PM  
  
Logon hours allowed          All  
  
Local Group Memberships      *Remote Desktop Users *Users  
Global Group memberships     *None  
The command completed successfully.
```

We are running as the _student_ user and have gathered additional information including the groups the user belongs to.  
  
Linux Ex:  
```bash
id  
uid=1000(student) gid=1000(student) groups=1000(student)
```

We are operating as the _student_ user, which has a User Identifier (UID) and Group Identifier (GID) of 1000  

_Discover other user accounts on the system:_  
  
  
Windows Ex:  
```powershell
C:\Users\student>net user  
  
User accounts for \\CLIENT251  
  
-------------------------------------------------------------------------------  
admin                    Administrator            DefaultAccount  
Guest                    student                  WDAGUtilityAccount  
The command completed successfully.
```
	Found an _admin_ account  
  
  
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
  
Win Ex:  
```powershell
C:\Users\student>hostname  
client251
```


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
  
  
Win Ex:  
```powershell
C:\Users\student>systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"  
OS Name:                   Microsoft Windows 10 Pro  
OS Version:                10.0.16299 N/A Build 16299  
System Type:               X86-based PC
```
	- **systeminfo** - Gathers OS & architecture info  
	- **findstr** - Similar to **grep**  
		- **/B** - Match patterns at beginning of a line  
		- **/C** - Specify a specific search string  
  
  
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
  
  
Win Ex:  
```powershell
C:\Users\student>tasklist /SVC  
  
Image Name                     PID Services  
========================= ======== =======================================  
...  
lsass.exe                      564 KeyIso, Netlogon, SamSs, VaultSvc  
svchost.exe                    676 BrokerInfrastructure, DcomLaunch, LSM,  
fontdrvhost.exe                684 N/A  
svchost.exe                    776 RpcEptMapper, RpcSs  
dwm.exe                        856 N/A  
svchost.exe                    944 Appinfo, BITS, DsmSvc, gpsvc, IKEEXT,  
...  
svchost.exe                    952 TermService  
...  
mysqld.exe                    1816 mysql
```
	- **tasklist** - View running processes  
	- **/SVC** - Return processes mapped to a specific Windows service.  
		- *****NOTE:** Doesn't list processes run by privileged users. Reqs higher perms  
	  
		(Can also use powershell:)  

```powershell
PS C:\Users\student> Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}
```

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

**Win Ex:**  
```powershell
C:\Users\student>ipconfig /all  
  
Windows IP Configuration  
  
   Host Name . . . . . . . . . . . . : client251  
   Primary Dns Suffix  . . . . . . . : corp.com  
   Node Type . . . . . . . . . . . . : Hybrid  
   IP Routing Enabled. . . . . . . . : No  
   WINS Proxy Enabled. . . . . . . . : No  
   DNS Suffix Search List. . . . . . : corp.com  
  
Ethernet adapter Ethernet0:  
  
   Connection-specific DNS Suffix  . :  
   Description . . . . . . . . . . . : Intel(R) 82574L Gigabit Network Connection  
   Physical Address. . . . . . . . . : 00-0C-29-C1-ED-B0  
   DHCP Enabled. . . . . . . . . . . : No  
   Autoconfiguration Enabled . . . . : Yes  
   Link-local IPv6 Address . . . . . : fe80::bc64:ab2f:a10f:edc9%15(Preferred)  
   IPv4 Address. . . . . . . . . . . : 10.11.0.22(Preferred)  
   Subnet Mask . . . . . . . . . . . : 255.255.255.0  
   Default Gateway . . . . . . . . . :   
   DHCPv6 IAID . . . . . . . . . . . : 83889193  
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-25-55-82-FF-00-0C-29-C1-ED-B0  
   DNS Servers . . . . . . . . . . . : 10.11.0.2  
   NetBIOS over Tcpip. . . . . . . . : Enabled  
  
Ethernet adapter Ethernet1:  
  
   Connection-specific DNS Suffix  . :  
   Description . . . . . . . . . . . : Intel(R) 82574L Gigabit Network Connection #2  
   Physical Address. . . . . . . . . : 00-0C-29-C1-ED-BA  
   DHCP Enabled. . . . . . . . . . . : No  
   Autoconfiguration Enabled . . . . : Yes  
   Link-local IPv6 Address . . . . . : fe80::9d3e:158a:241b:beb7%4(Preferred)  
   IPv4 Address. . . . . . . . . . . : 192.168.1.111(Preferred)  
   Subnet Mask . . . . . . . . . . . : 255.255.255.0  
   Default Gateway . . . . . . . . . : 192.168.1.1  
   DHCPv6 IAID . . . . . . . . . . . : 167775273  
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-25-55-82-FF-00-0C-29-C1-ED-B0  
   DNS Servers . . . . . . . . . . . : fec0:0:0:ffff::1%1  
                                       fec0:0:0:ffff::2%1  
                                       fec0:0:0:ffff::3%1  
   NetBIOS over Tcpip. . . . . . . . : Enabled 
``` 
	Can see multiple network interfaces & both the 10.11.0.22 & 192.168.1.111 IPs  
  
View routing tables:  
```powershell
C:\Users\student>route print  
===========================================================================  
Interface List  
 15...00 0c 29 c1 ed b0 ......Intel(R) 82574L Gigabit Network Connection  
  4...00 0c 29 c1 ed ba ......Intel(R) 82574L Gigabit Network Connection #2  
  1...........................Software Loopback Interface 1  
===========================================================================  
  
IPv4 Route Table  
===========================================================================  
Active Routes:  
Network Destination        Netmask          Gateway       Interface  Metric  
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.111    281  
          0.0.0.0          0.0.0.0        10.11.0.2       10.11.0.22    281  
        10.11.0.0    255.255.255.0         On-link        10.11.0.22    281  
       10.11.0.22  255.255.255.255         On-link        10.11.0.22    281  
...  
===========================================================================  
Persistent Routes:  
  Network Address          Netmask  Gateway Address  Metric  
          0.0.0.0          0.0.0.0      192.168.1.1  Default  
          0.0.0.0          0.0.0.0        10.11.0.2  Default  
===========================================================================  
  
IPv6 Route Table  
===========================================================================  
Active Routes:  
 If Metric Network Destination      Gateway  
  1    331 ::1/128                  On-link  
  4    281 fe80::/64                On-link  
 15    281 fe80::/64                On-link  
  4    281 fe80::9d3e:158a:241b:beb7/128  
...  
===========================================================================  
Persistent Routes:  
  None
```



View active connections:  
```powershell
C:\Users\student>netstat -ano  
  
Active Connections  
  
  Proto  Local Address          Foreign Address        State           PID  
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       7432  
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       776  
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4  
...  
  TCP    127.0.0.1:49689        127.0.0.1:49690        ESTABLISHED     2284  
  TCP    127.0.0.1:49690        127.0.0.1:49689        ESTABLISHED     2284  
...
```
.  
	- **-a** - Display all active TCP connections  
	- **-n** - Display address & port number in numerical form  
	- **-o** - Display owner PID of each connProvided a list of all the listening ports & included information about established connections that could reveal other users connected to this machine  
  
  
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
  
  
Win Ex:  
```powershell
C:\Users\student>netsh advfirewall show currentprofile  
  
Public Profile Settings:  
---------------------------------------------------------------  
State                          ON  
Firewall Policy                BlockInbound,AllowOutbound  
LocalFirewallRules             N/A (GPO-store only)  
LocalConSecRules               N/A (GPO-store only)  
InboundUserNotification        Enable  
RemoteManagement               Disable  
UnicastResponseToMulticast     Enable  
  
Logging:  
LogAllowedConnections          Disable  
LogDroppedConnections          Disable  
FileName                       %systemroot%\system32\LogFiles\Firewall\pfirewall.log  
MaxFileSize                    4096  
  
Ok.
```


List FW rules:  
```powershell
C:\Users\student>netsh advfirewall firewall show rule name=all | more  
  
Rule Name:         @{Microsoft.Windows.Photos_2018.18022.15810.1000_x86__8wekyb3d8bbw  
---------------------------------------------------  
Enabled:           Yes  
Direction:         In  
Profiles:          Domain,Private,Public  
Grouping:          Microsoft Photos  
LocalIP:           Any  
RemoteIP:          Any  
Protocol:          Any  
Edge traversal:    Yes  
Action:            Allow  
  
Rule Name:         @{Microsoft.Windows.Photos_2018.18022.15810.1000_x86__8wekyb3d8bbw  
----------------------------------------------------------------------  
Enabled:           Yes  
Direction:         Out  
Profiles:          Domain,Private,Public  
Grouping:          Microsoft Photos  
LocalIP:           Any  
RemoteIP:          Any  
Protocol:          Any  
Edge traversal:    No  
Action:            Allow  
  
Rule Name:         @{Microsoft.XboxIdentityProvider_12.39.13003.1000_x86__8wekyb3d8bb  
----------------------------------------------------------------------  
...
```
	*Def pipe to **more** as this can produce a LOT of output. <space> to display next page.  
  
According to the two firewall rules listed above, the Microsoft Photos app is allowed to establish both inbound and outbound conns to/ from any IP address using any protocol.  

Keep inmind that not all firewall rules are useful but some configurations may help us expand our attack surface.  
  
  
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

When these systems aremisconfigured, or the user-created files are left with insecure perms, we can modify these files that will be executed by the scheduling system at a high privilege level.  
  
  
Win Ex:  
```powershell
c:\Users\student>schtasks /query /fo LIST /v | more  
  
Folder: \  
INFO: There are no scheduled tasks presently available at your access level.  
  
Folder: \Microsoft  
INFO: There are no scheduled tasks presently available at your access level.  
  
Folder: \Microsoft\Office  
HostName:                             CLIENT251  
TaskName:                             \Microsoft\Office\Office 15 Subscription Heartbeat  
Next Run Time:                        11/12/2019 3:18:24 AM  
Status:                               Ready  
Logon Mode:                           Interactive/Background  
Last Run Time:                        11/11/2019 3:49:25 AM  
Last Result:                          0  
Author:                               Microsoft Office  
Task To Run:                          %ProgramFiles%\Common Files\Microsoft Shared\Office16\OLicenseHeartbeat.exe  
...  
Schedule Type:                        Daily  
Start Time:                           12:00:00 AM  
Start Date:                           1/1/2010  
End Date:                             N/A  
Days:                                 Every 1 day(s)  
...
```
	Again, pipe to **more**
.
	- **/query** - Displays tasks  
	- **/FO LIST** - Sets output format to a simple list  
	-  **/V** - Verbose output  
  
Output includes a lot of useful information such as the task to run, the next time it is due to run, the last time it ran, and details about how often it will run.  
  
  
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


  
### Enumerate Installed Apps & Patches:

Useful for finding matching exploits to help elevate privileges. Uses [wmic](OS%20Commands.md#wmic)  
  
Win Ex:  
```powershell
c:\Users\student>wmic product get name, version, vendor  
Name                                       Vendor                      Version  
Microsoft OneNote MUI (English) 2016       Microsoft Corporation       16.0.4266.1001  
Microsoft Office OSM MUI (English) 2016    Microsoft Corporation       16.0.4266.1001  
Microsoft Office Standard 2016             Microsoft Corporation       16.0.4266.1001  
Microsoft Office OSM UX MUI (English) 2016 Microsoft Corporation       16.0.4266.1001  
Microsoft Office Shared Setup Metadata MUI Microsoft Corporation       16.0.4266.1001  
Microsoft Excel MUI (English) 2016         Microsoft Corporation       16.0.4266.1001  
Microsoft PowerPoint MUI (English) 2016    Microsoft Corporation       16.0.4266.1001  
Microsoft Publisher MUI (English) 2016     Microsoft Corporation       16.0.4266.1001  
Microsoft Outlook MUI (English) 2016       Microsoft Corporation       16.0.4266.1001  
Microsoft Groove MUI (English) 2016        Microsoft Corporation       16.0.4266.1001  
Microsoft Word MUI (English) 2016          Microsoft Corporation       16.0.4266.1001  
....
```


Can also be used to list system-wide updates by querying the [Win32_QuickFixEngineering(qfe)](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-quickfixengineering) WMI class:  
```powershell
c:\Users\student>wmic qfe get Caption, Description, HotFixID, InstalledOn  
Caption                                     Description      HotFixID   InstalledOn  
                                            Update           KB2693643  4/7/2018  
http://support.microsoft.com/?kbid=4088785  Security Update  KB4088785  3/31/2018  
http://support.microsoft.com/?kbid=4090914  Update           KB4090914  3/31/2018  
http://support.microsoft.com/?kbid=4088776  Security Update  KB4088776  3/31/2018
```

 
Provide us with a precise indication of the security posture of the target Windows operating system. 

According to this output, this system has not been updated recently, which might make it easier to exploit.  
  
  
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
  
  
Can use **AccessChk** from SysInternals to automate the search on Win:  
```powershell
c:\Tools\privilege_escalation\SysinternalsSuite>accesschk.exe -uws "Everyone" "C:\Program Files"  
  
Accesschk v6.12 - Reports effective permissions for securable objects  
Copyright (C) 2006-2017 Mark Russinovich  
Sysinternals - www.sysinternals.com  
  
RW C:\Program Files\TestApplication\testapp.exe
```
.  
	- **-u** - Suppress errors  
	- **-w** - Search for write access perms  
	- **-s** - Recursive search  
  
AccessChk successfully identified one executablefile that is world-writable.  
	If this file were to be executed by a privileged user or a service account,  
we could attempt to overwrite it with a malicious file of our choice, such as a reverse shell, in order to elevate our privileges.  
  
We can also accomplish this in powershell:
```powershell
PS C:\Tools\privilege_escalation\SysinternalsSuite>Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}  
  
  
    Directory: C:\Program Files\TestApplication  
  
  
Path        Owner                  Access  
----        -----                  ------  
testapp.exe BUILTIN\Administrators Everyone Allow  Modify, Synchronize....
```
.
	- **Get-ACL** - Retrieves all permissions for a given file or directory. However,since Get-ACL cannot be run recursively, we are also using:  
	- **Get-ChildItem** - Enumerate everything under the Program Files directory. This will effectively retrieve every single object in our target directory along with all associated accesspermissions  
	- **AccessToString** & **-match** - Narrows down the results to the specific access properties we're looking for. In our case, we are searching for any object can be modified (Modify) by members of the Everyone group.  
  
  
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



### Enumerate Unmounted Disks:

List drives that are currently mounted & drives physically connected but not mounted & check mount permissions.  
  
  
Win Ex:  
```powershell
c:\Users\student>mountvol  
Creates, deletes, or lists a volume mount point.  
...  
Possible values for VolumeName along with current mount points are:  
  
    \\?\Volume{25721a7f-0000-0000-0000-100000000000}\  
        *** NO MOUNT POINTS ***  
  
    \\?\Volume{25721a7f-0000-0000-0000-602200000000}\  
        C:\  
  
    \\?\Volume{78fa00a6-3519-11e8-a4dc-806e6f6e6963}\  
        D:\

```

System has two mount points that map to the C: and D: drives respectively.  
Also a volume with the globally unique identifier (GUID) 25721a7f-0000-0000-0000-100000000000, which has no mount point.  
	This could be interesting and we might want to investigate further.  
  
  
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


  
### Enumerate Device Drivers & Kernel Modules:
  
Similar to enumerating through apps & their patches, this is useful for finding exploits online for privesc.  
  
Win Ex:  
```powershell
PS C:\Users\student> driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path  
  
Display Name                         Start Mode Path  
------------                         ---------- ----  
1394 OHCI Compliant Host Controller  Manual     C:\Windows\system32\drivers\1394ohci.s  
3ware                                Manual     C:\Windows\system32\drivers\3ware.sys  
Microsoft ACPI Driver                Boot       C:\Windows\system32\drivers\ACPI.sys  
ACPI Devices driver                  Manual     C:\Windows\system32\drivers\AcpiDev.sy  
Microsoft ACPIEx Driver              Boot       C:\Windows\system32\Drivers\acpiex.sys  
ACPI Processor Aggregator Driver     Manual     C:\Windows\system32\drivers\acpipagr.s  
ACPI Power Meter Driver              Manual     C:\Windows\system32\drivers\acpipmi.sy  
ACPI Wake Alarm Driver               Manual     C:\Windows\system32\drivers\acpitime.s  
ADP80XX                              Manual     C:\Windows\system32\drivers\ADP80XX.SY
```
.
	- **/v** - Verbose output  
	- **/fo csv** - Format output as CSV  
	- **Select-Object** - Select specific object properties or sets of objects  
  
  
This only lists drivers, so we'll still need the versions:  
```powershell

PS C:\Users\student> Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}  
  
DeviceName               DriverVersion Manufacturer  
----------               ------------- ------------  
VMware VMCI Host Device  9.8.6.0       VMware, Inc.  
VMware PVSCSI Controller 1.3.10.0      VMware, Inc.  
VMware SVGA 3D           8.16.1.24     VMware, Inc.  
VMware VMCI Bus Device   9.8.6.0       VMware, Inc.  
VMware Pointing Device   12.5.7.0      VMware, Inc.
```
.
	- **Get-WmiObject** - Get the _Win32_PnPSignedDriver_ WMI instance  
		- Provides digital signature information about drivers.  
	- **Select-Object** - Enumerate specific properties  
	- **Where-Object** - Target drivers based on their name  
  

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



### Enumerate AutoElevate Binaries:

Interesting OS-specific"shortcuts" to privilege escalation....  
  
Should check the status of the _AlwaysInstallElevated_ registry setting. 

If this key is enabled (set to 1) in either HKEY_CURRENT_USER or HKEY_LOCAL_MACHINE, any user can run Windows Installer packages with elevated privileges.  
  
Win Ex:  
```powershell
c:\Users\student>reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer  
  
HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer  
    AlwaysInstallElevated    REG_DWORD    0x1  
  
c:\Users\student>reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer  
  
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer  
    AlwaysInstallElevated    REG_DWORD    0x1
```
If this setting is enabled, we could craft an _MSI_ file and run it toelevate our privileges.  
  
  
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