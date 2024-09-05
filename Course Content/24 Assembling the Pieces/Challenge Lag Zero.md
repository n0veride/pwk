
##### Scenario

Company _BEYOND Finances_ has tasked us with conducting a penetration test of their IT infrastructure.
The client wants to determine if an attacker can breach the perimeter and get domain admin privileges in the internal _Active Directory_ (AD) environment.
In this assessment, the client's goals for us are to obtain domain administrator privileges and access the domain controller.

Once you have access to the domain controller, retrieve the NTLM hash of the domain administrator account _BEYOND\\Administrator_ and enter it as answer to this exercise.
> Please make sure you are dumping the NTLM hash of the domain admin user with RID 500 by utilizing dcsync attack via mimikatz not by extracting creds from SAM file.
> The hashes will be different.

## Endpoints

**192.168.194.250** - VM #6 - WINPREP  :  offsec / lab
**192.168.194.242** - VM #3 - MAILSRV1
**192.168.194.244** - VM #5 - WEBSRV1
**172.16.150.240** - VM #1
**172.16.150.243** - VM #4
**172.16.150.241** - VM #2

## Enumerating the public network

Client's provided two initial targets:
- WEBSRV1 - **192.168.194.244**
- MAILSRV1 - **192.168.194.242**

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