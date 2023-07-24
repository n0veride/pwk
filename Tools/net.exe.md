

Enumerate all local accounts:
```powershell
net user
```

Enumerate all users in a the entire domain:
```powershell
net user /domain
```

Query a specific user:
```powershell
net user <username> /domain
```

Enumerate list of groups:
	Add group name to enumerate users in that group
```powershell
net localgroup
```

Enumerate all groups within a domain:
```powershell
net group /domain
```

Examine running services:
```powershell
net start/ stop
```

Enumerate list of domains, computers, or resources being shared by the specified computer
```powershell
net view
```

Connect/ Disconnect one comp to a shared resource (drives/ printers/ etc) or displays info about connections:
```powershell
net use
```

Delete a session:
```powershell
net use /delete
```

Specify IP address to connect to w/ **net use**:
```powershell
net use \\<IP>
```

Terminate outbound session:
```powershell
net use /del
```

Enumerate inbound sessions:
```powershell
net session
```

Terminate inbound session:
```powershell
net session \\<ip> /del
```


See [MS's reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc730899(v=ws.11)) for cmd line syntax & usage:

ACCOUNTS     Set the policy settings on local computer
COMPUTER     Adds or deletes a computer from a domain db
CONFIG          
CONTINUE     
FILE               
GROUP               Adds, displays, or mods global groups in domains.
HELP               
HELPMSG          
LOCALGROUP     Adds, displays, or mods local groups.
NAME     
PAUSE     
PRINT               Displays info about a specified printer queue or specified print job, or controls a specified print job
SEND               
SESSION          Manages server computer connections
SHARE               Manages shared resources
START     
STATISTICS     
STOP     
TIME     
USE                    Connects a comp to/ disconnects from a shared resource,  displays info about comp connections, or controls persistent net conns
USER                    Adds/ modifies user accounts or displays user account info
VIEW                    Displays list of domains, computers, or resources being shared by the specified comp.