
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




