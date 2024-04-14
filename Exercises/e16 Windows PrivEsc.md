
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