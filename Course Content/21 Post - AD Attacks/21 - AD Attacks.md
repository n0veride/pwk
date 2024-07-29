# Enumeration

See [AD](Active%20Directory.md) for a rundown on Active Directory

#### Scenario
- Enumerate *corp.com* domain
- Previously obtained user creds to domain user `stephanie:LegmanTeamBenzoin!!`
	- Has RDP access on a domain Win 11 workstation
	- Not local admin on machine.
- Will likely need to pivot and re-enumerate with each new user discovered

##### IPs
- 192.168.x.70 - *DC*
- 192.168.x.72
- 192.168.x.73
- 192.168.x.74
- 192.168.x.75 - RDP `stephanie`
- 192.168.x.76
  
#### Goal
- Enumerate full domian
- Elevate privs to highest possible (`domain admin` here)

*Can* use prev learned auto and manual enumerations techniques.


## Manual Enumeration

- RDP in
```bash
xfreerdp /cert-ignore /compression /auto-reconnect /u:stephanie /p:"LegmanTeamBenzoin\!\!" /d:corp.com /v:192.168.151.75
```
	- Need to either not include password and enter when prompted OR escape the `!` symbols


> Enumeration will be similar to [Windows PrivEsc Enumeration](16.1%20-%20PrivEsc%20Enumerating%20Windows.md#Situational%20Awareness) using [net.exe](OS%20Commands.md)

##### User Enum
```powershell
net user
	User accounts for \\CLIENT75
	-------------------------------------------------------------------------------
	Administrator            DefaultAccount           Guest
	offsec                   WDAGUtilityAccount
	The command completed successfully.
```


##### Domain Users Enum
```powershell
net user /domain
	The request will be processed at a domain controller for domain corp.com.
	User accounts for \\DC1.corp.com
	-------------------------------------------------------------------------------
	Administrator            dave                     Guest
	iis_service              jeff                     jeffadmin
	jen                      krbtgt                   pete
	stephanie
	The command completed successfully.
```
	Notice `jeffadmin` user.


##### Specific User Enum
```powershell
net user jeffadmin /domain
	The request will be processed at a domain controller for domain corp.com.
	
	User name                    jeffadmin
	Full Name
	...
	Local Group Memberships      *Administrators
	Global Group memberships     *Domain Users         *Domain Admins
	The command completed successfully.
```
	- Notice `jeffadmin` is a part of the Domain Admins group

##### Domain Group Enum
```powershell
net group /domain
	The request will be processed at a domain controller for domain corp.com.
	
	Group Accounts for \\DC1.corp.com
	
	-------------------------------------------------------------------------------
	*Cloneable Domain Controllers
	*Debug
	*Development Department
	*DnsUpdateProxy
	*Domain Admins
	*Domain Computers
	*Domain Controllers
	*Domain Guests
	*Domain Users
	*Enterprise Admins
	*Enterprise Key Admins
	*Enterprise Read-only Domain Controllers
	*Group Policy Creator Owners
	*Key Admins
	*Management Department
	*Protected Users
	*Read-only Domain Controllers
	*Sales Department
	*Schema Admins
	The command completed successfully.
```
	Note groups for Development, Management, and Sales Departmenst
		- A group (& all its members) can be added as a member

*Note:   [**net.exe**](OS%20Commands.md#net) can only show direct user members, not users of nested groups*

##### Domain Group Member Enum
```powershell
net group "Sales Departement" /domain
	The request will be processed at a domain controller for domain corp.com.
	Group name     Sales Department
	Comment
	Members
	-------------------------------------------------------------------------------
	pete                     stephanie
	The command completed successfully.
```

### PowerShell and .NET classes

### Cmdlets
```powershell
Get-ADUser
```
	Requires admin privs

>PowerShell cmdlets are only installed by default on domain controllers as part of the _Remote Server Administration Tools_ (RSAT).
>RSAT is very rarely present on clients in a domain and we must have administrative privileges to install them.


### [LDAP](LDAP.md)

_System.DirectoryServices.ActiveDirectory_
- Namespace found in Microsoft's .NET classes related to AD.

Focus on querying the *Domain Class* in order to discover for the `PDC`'s `PdcRoleOwner` property
```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
	Forest                  : corp.com
	DomainControllers       : {DC1.corp.com}
	Children                : {}
	DomainMode              : Unknown
	DomainModeLevel         : 7
	Parent                  :
	PdcRoleOwner            : DC1.corp.com
	RidRoleOwner            : DC1.corp.com
	InfrastructureRoleOwner : DC1.corp.com
	Name                    : corp.com
```
	- Domain class of the _System.DirectoryServices.ActiveDirectory_ namespace
		- Contains method GetCurrentDomain()
			- Retrieves Domain object for the currently logged in user
	 - Name = domain name (corp.com)
	- PdcRoleOwner = Primary domain controller (DC01.corp.com)


[Active Directory Services Interface](https://learn.microsoft.com/en-us/windows/win32/adsi/ldap-adspath?redirectedfrom=MSDN) (`ADSI`)
- Set of interfaces built on COM
- Gives us an LDAP provider we can use for communication with AD

##### Script man_enum.ps1 \<individual search loops>
```powershell
# Store the domain object in the $domainObj variable
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Store the PdcRoleOwner name to the $PDC variable
$PDC = $domainObj.PdcRoleOwner.Name

<######## Better command would be to streamline the two into one:
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
#>

# Store the Distinguished Name variable into the $DN variable
$DN = ([adsi]'').distinguishedName

# Construct the LDAP path
$LDAP = "LDAP://$PDC/$DN"
$LDAP

######## Build in Search Filter ########

# Use *DirectoryEntry* .NET class to encapsulate an object in the AD service hierarchy
$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

# Use *DirectorySearcher* .NET class to specify the AD service we want to query
$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)

######## Enumerate Domain Users ########
$dirsearcher.filter="samAccountType=805306368"

$dirsearcher.FindAll()

# Store results in $result variable
#Extract each result and store in $obj variable
Write-Host "All Domain Users"
Foreach($obj in $result)
{
	#Extract all properties in each object, store in $prop variable, & print w/ '------' separating each object
    Foreach($prop in $obj.Properties)
    {
        $prop
    }

    Write-Host "-------------------------------"
}

######## Examples of Other Potential Queries ########
<#
# Prints only members of the Domain Admins group
Write-Host "Members of Domain Admins group"
Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        if($prop.memberof -match 'Domain Admins')
        {
            $prop.name
        }
    }
}
#>

<#
# Prints only computers running Windows 10 - USE with line 39->  $Searcher.filter="ObjectClass=computer"
Write-Host "Computers running Win10"
Foreach($obj in $Result)
{
	if($obj.Properties.operatingsystem -match 'Windows 10')
	{
		$obj.Properties.name
		Write-Host "----------------------------"
	}
}
#>
```
	- Once LDAP provider path is build (using $SearchString), we can instantiate the DirectorySearcher class
	- Attributes of a User object are stored in the Properties field


##### Script enum_func.ps1 \<search function for use w/ args>
```powershell
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()
}
```

- Load function into powershell
```powershell
Import-Module .\enum_func.ps1
```

- Use the function `LDAPSearch` to obtain whatever info from AD
- [LDAPQuery examples](https://theitbros.com/ldap-query-examples-active-directory/#penci-LDAP-Query-Examples-for-Active-Directory)
```powershell
LDAPSearch -LDAPQuery "(samAccountType=805306368)"
	Path                                                         Properties
	----                                                         ----------
	LDAP://DC1.corp.com/CN=Administrator,CN=Users,DC=corp,DC=com {logoncount, codepage, objectcategory, description...}
	LDAP://DC1.corp.com/CN=Guest,CN=Users,DC=corp,DC=com         {logoncount, codepage, objectcategory, description...}
	LDAP://DC1.corp.com/CN=krbtgt,CN=Users,DC=corp,DC=com        {logoncount, codepage, objectcategory, description...}
	LDAP://DC1.corp.com/CN=dave,CN=Users,DC=corp,DC=com          {logoncount, codepage, objectcategory, dscorepropagatio...
	LDAP://DC1.corp.com/CN=stephanie,CN=Users,DC=corp,DC=com     {logoncount, codepage, objectcategory, dscorepropagatio...
	LDAP://DC1.corp.com/CN=jeff,CN=Users,DC=corp,DC=com          {logoncount, codepage, objectcategory, usnchanged...}
	LDAP://DC1.corp.com/CN=jeffadmin,CN=Users,DC=corp,DC=com     {logoncount, codepage, objectcategory, dscorepropagatio...
	...
```

- Can also search for *Object Classes*
```powershell
LDAPSearch -LDAPQuery "(objectclass=group)"
	Path                                                                                   Properties
	----                                                                                   ----------
	LDAP://DC1.corp.com/CN=Administrators,CN=Builtin,DC=corp,DC=com                        {objectcategory, usnchanged, ...
	LDAP://DC1.corp.com/CN=Users,CN=Builtin,DC=corp,DC=com                                 {usnchanged, distinguishednam...
	LDAP://DC1.corp.com/CN=Guests,CN=Builtin,DC=corp,DC=com                                {usnchanged, distinguishednam...
	LDAP://DC1.corp.com/CN=Print Operators,CN=Builtin,DC=corp,DC=com                       {iscriticalsystemobject, usnc...
	LDAP://DC1.corp.com/CN=Backup Operators,CN=Builtin,DC=corp,DC=com                      {iscriticalsystemobject, usnc...
	LDAP://DC1.corp.com/CN=Replicator,CN=Builtin,DC=corp,DC=com                            {iscriticalsystemobject, usnc...
	LDAP://DC1.corp.com/CN=Remote Desktop Users,CN=Builtin,DC=corp,DC=com                  {iscriticalsystemobject, usnc...
	...
```

- Print properties and attributes for objects.
	- Will need `Foreach` loops above
		- Allows us to select specific attributes we're interested in
```powershell
foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) { $group.properties | select {$_.cn}, {$_.member} }
	$_.cn                                   $_.member
	-----                                   ---------
	Administrators                          {CN=jeffadmin,CN=Users,DC=corp,DC=com, CN=Domain Admins,CN=Users,DC=corp,DC=...
	Users                                   {CN=Domain Users,CN=Users,DC=corp,DC=com, CN=S-1-5-11,CN=ForeignSecurityPrin...
	Guests                                  {CN=Domain Guests,CN=Users,DC=corp,DC=com, CN=Guest,CN=Users,DC=corp,DC=com}
	Print Operators
	Backup Operators
	Replicator
	Remote Desktop Users
	...
	Sales Department                       {CN=Development Department,DC=corp,DC=com, CN=pete,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}
	...
```
	- Can see (w/ Sales results) we get more results with this than net.exe
		- It's because it enumerates all AD objects including _Domain Local_ groups (not just global groups).

- Can store results in variables for easier querying
```powershell
$sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"

$sales.properties.member
	CN=Development Department,DC=corp,DC=com
	CN=pete,CN=Users,DC=corp,DC=com
	CN=stephanie,CN=Users,DC=corp,DC=com
```

### Nested Groups

```powershell
$dev_group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Development Department*))"
$dev_group.properties.member
	CN=Management Department,DC=corp,DC=com
	CN=pete,CN=Users,DC=corp,DC=com
	CN=dave,CN=Users,DC=corp,DC=com

$mgmt_group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Management Department*))"
$mgmt_group.properties.member
	CN=jen,CN=Users,DC=corp,DC=com
```

### User Properties
```powershell
$mic = LDAPSearch -LDAPQuery "(&(objectCategory=user)(cn=michelle*))"
$mic.properties
	Name                           Value
	----                           -----
	logoncount                     {0}
	codepage                       {0}
	objectcategory                 {CN=Person,CN=Schema,CN=Configuration,DC=corp,DC=com}
	description                    {OS{e195c57d8ac8695962dcf587fa4fb2e5}}
	usnchanged                     {557257}
	instancetype                   {4}
	name                           {michelle}
	badpasswordtime                {0}
	pwdlastset                     {133663381523214592}
	objectclass                    {top, person, organizationalPerson, user}
```


### PowerView
Uses .NET classes to obtain the required LDAP path and uses it to communicate with AD.
> 	NetSessionEnum likely won't work on any computers Win 10 16299 (build 1709) or Server 2019 (build 1809) or later.

### Domain Object Enum

- Get basic info about the domain
```powershell
Get-NetDomain
	Forest                  : corp.com
	DomainControllers       : {DC1.corp.com}
	Children                : {}
	DomainMode              : Unknown
	DomainModeLevel         : 7
	Parent                  :
	PdcRoleOwner            : DC1.corp.com
	RidRoleOwner            : DC1.corp.com
	InfrastructureRoleOwner : DC1.corp.com
	Name                    : corp.com
```

- Get a list of all users in the domain
```powershell
 Get-NetUser
	logoncount             : 566
	badpasswordtime        : 3/1/2023 3:18:15 AM
	description            : Built-in account for administering the computer/domain
	distinguishedname      : CN=Administrator,CN=Users,DC=corp,DC=com
	objectclass            : {top, person, organizationalPerson, user}
	lastlogontimestamp     : 7/25/2024 5:09:14 PM
	name                   : Administrator
	objectsid              : S-1-5-21-1987370270-658905905-1781884369-500
	samaccountname         : Administrator
	...
```
	- Will enumerate all attributes of each user object.

- Rather than use loops to print specific attributes, We can pipe to `select`
```powershell
Get-NetUser | select cn,pwdlastset,lastlogon
	cn            pwdlastset            lastlogon
	--            ----------            ---------
	Administrator 8/16/2022 5:27:22 PM  7/25/2024 5:19:47 PM
	Guest         12/31/1600 4:00:00 PM 12/31/1600 4:00:00 PM
	krbtgt        9/2/2022 4:10:48 PM   12/31/1600 4:00:00 PM
	dave          9/7/2022 9:54:57 AM   7/25/2024 5:21:35 PM
	stephanie     9/2/2022 4:23:38 PM   7/25/2024 5:09:48 PM
	jeff          9/2/2022 4:27:20 PM   12/18/2023 11:55:16 PM
	jeffadmin     9/2/2022 4:26:48 PM   1/8/2024 3:47:01 AM
	iis_service   9/7/2022 5:38:43 AM   3/1/2023 3:40:02 AM
	pete          9/6/2022 12:41:54 PM  2/1/2023 2:42:42 AM
	jen           9/6/2022 12:43:01 PM  1/8/2024 1:26:03 AM
	nathalie      7/25/2024 5:09:36 PM  12/31/1600 4:00:00 PM
	fred          7/25/2024 5:09:36 PM  12/31/1600 4:00:00 PM
	bob           7/25/2024 5:09:36 PM  12/31/1600 4:00:00 PM
	robert        7/25/2024 5:09:36 PM  12/31/1600 4:00:00 PM
	dennis        7/25/2024 5:09:36 PM  12/31/1600 4:00:00 PM
	michelle      7/25/2024 5:09:36 PM  12/31/1600 4:00:00 PM
```
	- pwdlastset - may show accounts with weaker pws than the current policy
	- lastlogon - may show dormant users --> causes less interference

- Enumerate groups
```powershell
Get-NetGroup | select cn
	cn
	--
	...
	Key Admins
	Enterprise Key Admins
	DnsAdmins
	DnsUpdateProxy
	Sales Department
	Management Department
	Development Department
	Debug
```

- Enumerate specific groups
```powershell
Get-NetGroup "Sales Department" | select member
	member
	------
	{CN=Development Department,DC=corp,DC=com, CN=pete,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}
```

- Enumerate computer objects
```powershell
Get-NetComputer
	pwdlastset                    : 7/25/2024 5:35:11 PM
	logoncount                    : 725
	msds-generationid             : {248, 50, 146, 113...}
	serverreferencebl             : CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=com
	badpasswordtime               : 12/31/1600 4:00:00 PM
	distinguishedname             : CN=DC1,OU=Domain Controllers,DC=corp,DC=com
	objectclass                   : {top, person, organizationalPerson, user...}
	lastlogontimestamp            : 7/25/2024 5:35:10 PM
	name                          : DC1
	objectsid                     : S-1-5-21-1987370270-658905905-1781884369-1000
	samaccountname                : DC1$
	localpolicyflags              : 0
	codepage                      : 0
	samaccounttype                : MACHINE_ACCOUNT
	whenchanged                   : 7/26/2024 12:35:11 AM
	accountexpires                : NEVER
	countrycode                   : 0
	operatingsystem               : Windows Server 2022 Standard
```

- Search for OS and hostname
```powershell
Get-NetComputer | select operatingsystem,dnshostname
	operatingsystem              dnshostname
	---------------              -----------
	Windows Server 2022 Standard DC1.corp.com
	Windows Server 2022 Standard web04.corp.com
	Windows Server 2022 Standard FILES04.corp.com
	Windows 11 Enterprise        client74.corp.com
	Windows 11 Enterprise        client75.corp.com
	Windows 10 Pro               CLIENT76.corp.com
```

### Domain Shares Enum

- Enumerate through domain shares
```powershell
Find-DomainShare

Name           Type Remark              ComputerName
----           ---- ------              ------------
ADMIN$   2147483648 Remote Admin        DC1.corp.com
C$       2147483648 Default share       DC1.corp.com
IPC$     2147483651 Remote IPC          DC1.corp.com
NETLOGON          0 Logon server share  DC1.corp.com
SYSVOL            0 Logon server share  DC1.corp.com     #<-- NOTE
ADMIN$   2147483648 Remote Admin        web04.corp.com
backup            0                     web04.corp.com
C$       2147483648 Default share       web04.corp.com
IPC$     2147483651 Remote IPC          web04.corp.com
ADMIN$   2147483648 Remote Admin        FILES04.corp.com
C                 0                     FILES04.corp.com
C$       2147483648 Default share       FILES04.corp.com
docshare          0 Documentation pu... FILES04.corp.com
IPC$     2147483651 Remote IPC          FILES04.corp.com
Tools             0                     FILES04.corp.com
Users             0                     FILES04.corp.com
Windows           0                     FILES04.corp.com
ADMIN$   2147483648 Remote Admin        client74.corp...
C$       2147483648 Default share       client74.corp...
IPC$     2147483651 Remote IPC          client74.corp...
ADMIN$   2147483648 Remote Admin        client75.corp...
C$       2147483648 Default share       client75.corp...
IPC$     2147483651 Remote IPC          client75.corp...
sharing           0                     client75.corp...
ADMIN$   2147483648 Remote Admin        CLIENT76.corp...
C$       2147483648 Default share       CLIENT76.corp...
IPC$     2147483651 Remote IPC          CLIENT76.corp...
```
	- Shows 3 different servers and a few clients


**SYSVOL** is typically used for various domain policies and scripts
- Default mapped to `%SystemRoot%\SYSVOL\Sysvol\domain-name`
```powershell
dir \\dc1.corp.com\SYSVOL\corp.com
	    Directory: \\dc1.corp.com\SYSVZOL\corp.com
	Mode                 LastWriteTime         Length Name
	----                 -------------         ------ ----
	d-----         9/21/2022   1:11 AM                Policies
	d-----          9/2/2022   4:08 PM                scripts


dir \\dc1.corp.com\SYSVOL\corp.com\Policies
	    Directory: \\dc1.corp.com\SYSVOL\corp.com\Policies
	Mode                 LastWriteTime         Length Name
	----                 -------------         ------ ----
	d-----         9/21/2022   1:13 AM                oldpolicy
	d-----          9/2/2022   4:08 PM                {31B2F340-016D-11D2-945F-00C04FB984F9}
	d-----          9/2/2022   4:08 PM                {6AC1786C-016F-11D2-945F-00C04fB984F9}


dir \\dc1.corp.com\SYSVOL\corp.com\Policies\oldpolicy\
	    Directory: \\dc1.corp.com\SYSVOL\corp.com\Policies\oldpolicy
	Mode                 LastWriteTime         Length Name
	----                 -------------         ------ ----
	-a----         9/21/2022   1:13 AM            742 old-policy-backup.xml


type \\dc1.corp.com\SYSVOL\corp.com\Policies\oldpolicy\old-policy-backup.xml
	<?xml version="1.0" encoding="utf-8"?>
	<Groups   clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
	  <User   clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"
	          name="Administrator (built-in)"
	          image="2"
	          changed="2012-05-03 11:45:20"
	          uid="{253F4D90-150A-4EFB-BCC8-6E894A9105F7}">
	    <Properties
	          action="U"
	          newName=""
	          fullName="admin"
	          description="Change local admin"
	          cpassword="+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
	          changeLogon="0"
	          noChange="0"
	          neverExpires="0"
	          acctDisabled="0"
	          userName="Administrator (built-in)"
	          expires="2016-02-10" />
	  </User>
	</Groups>
```

>Historically, system administrators often changed local workstation passwords through [_Group Policy Preferences_ (GPP)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581922(v=ws.11))

- Crack w/ gpp in Kali
```bash
gpp-decrypt +bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE                       
	P@$$w0rd
```


- Enumerate other interesting shares
```powershell
dir \\FILES04\docshare
	    Directory: \\FILES04\docshare
	Mode                 LastWriteTime         Length Name
	----                 -------------         ------ ----
	d-----         9/21/2022   2:02 AM                docs


dir \\FILES04\docshare\docs
	    Directory: \\FILES04\docshare\docs
	Mode                 LastWriteTime         Length Name
	----                 -------------         ------ ----
	d-----         9/21/2022   2:01 AM                do-not-share
	-a----         9/21/2022   2:03 AM            242 environment.txt


dir \\FILES04\docshare\docs\do-not-share\
	    Directory: \\FILES04\docshare\docs\do-not-share
	Mode                 LastWriteTime         Length Name
	----                 -------------         ------ ----
	-a----         9/21/2022   2:02 AM           1142 start-email.txt


PS C:\Tools> type \\FILES04\docshare\docs\do-not-share\start-email.txt
	Hi Jeff,
	
	We are excited to have you on the team here in Corp. As Pete mentioned, we have been without a system administrator
	since Dennis left, and we are very happy to have you on board.
	
	Pete mentioned that you had some issues logging in to your Corp account, so I''m sending this email to you on your personal address.
	
	The username I''m sure you already know, but here you have the brand new auto generated password as well: HenchmanPutridBonbon11     #--> NOTE
	
	As you may be aware, we are taking security more seriously now after the previous breach, so please change the password at first login.
	
	Best Regards
	Stephanie
	...............
	Hey Stephanie,
	
	Thank you for the warm welcome. I heard about the previous breach and that Dennis left the company.
	
	Fortunately he gave me a great deal of documentation to go through, although in paper format. I''m in the
	process of digitalizing the documentation so we can all share the knowledge. For now, you can find it in
	the shared folder on the file server.
	
	Thank you for reminding me to change the password, I will do so at the earliest convenience.
	
	Best regards
	Jeff
```

>The docshare share path uses the NetBIOS name of the server (FILES04) and the share name (docshare) to access the shared folder directly.
>This syntax is commonly used to access shares hosted on specific servers within the domain or network without specifying the domain name.
>This is based on the naming conventions and configurations set up in the Active Directory environment


### Permissions Enum

#### Object Perms Enum

An object in AD may have a set of permissions applied to it with multiple Access Control Entries (ACE)
- These ACEs make up the Access Control List (ACL)
- Each ACE defines whether access to the specific object is allowed or denied.

ACL validation:
- In an attempt to access the share, the user will send an _access token_, which consists of the user identity and permissions.
- The target object then validates the token against the list of permissions (the ACL). 
	- If the ACL allows the user to access the share, access is granted. Otherwise the request is denied.


**ActiveDirectoryRights properties**

| Perm Type              | Desc                                  |
| ---------------------- | ------------------------------------- |
| GenericAll             | Full permissions on object            |
| GenericWrite           | Edit certain attributes on the object |
| WriteOwner             | Change ownership of the object        |
| WriteDACL              | Edit ACE's applied to object          |
| AllExtendedRights      | Change password, reset password, etc. |
| ForceChangePassword    | Password change for object            |
| Self (Self-Membership) | Add ourselves to for example a group  |

- Enumerate ACEs of user `stephanie`
```powershell
Get-ObjectAcl -Identity stephanie
	ObjectDN               : CN=stephanie,CN=Users,DC=corp,DC=com
	ObjectSID              : S-1-5-21-1987370270-658905905-1781884369-1104     #<--- NOTE
	ActiveDirectoryRights  : ReadProperty
	ObjectAceFlags         : ObjectAceTypePresent
	ObjectAceType          : 4c164200-20c0-11d0-a768-00aa006e0529
	InheritedObjectAceType : 00000000-0000-0000-0000-000000000000
	BinaryLength           : 56
	AceQualifier           : AccessAllowed
	IsCallback             : False
	OpaqueLength           : 0
	AccessMask             : 16
	SecurityIdentifier     : S-1-5-21-1987370270-658905905-1781884369-553     #<--- NOTE
	AceType                : AccessAllowedObject
	AceFlags               : None
	IsInherited            : False
	InheritanceFlags       : None
	PropagationFlags       : None
	AuditFlags             : None
	...
```
	- Lists all ACEs.  output can be overwhelming
	- Notice two SIDs

- Convert `ObjectSID`
```powershell
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
	CORP\stephanie
```
	- ObjectSID in output above refers to user

- Convert SecurityIdentifier
```powershell
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553
	CORP\RAS and IAS Servers
```
	- RAS and IAS Servers group has ReadProperty access rights to the user stephanie

- List  any object that has `GenericAll` access w/in a specific group (eg: `Management Dept`)
```powershell
# Get list of all GenericAll SIDs
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
	SecurityIdentifier                            ActiveDirectoryRights
	------------------                            ---------------------
	S-1-5-21-1987370270-658905905-1781884369-512             GenericAll
	S-1-5-21-1987370270-658905905-1781884369-1104            GenericAll
	S-1-5-32-548                                             GenericAll
	S-1-5-18                                                 GenericAll
	S-1-5-21-1987370270-658905905-1781884369-519             GenericAll


# Convert SIDS
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
	CORP\Domain Admins
	CORP\stephanie
	BUILTIN\Account Operators
	Local System
	CORP\Enterprise Admins

Find-InterestingDomainAcl | select identityreferencename,activedirectoryrights,acetype,objectdn | ?{$_.IdentityReferenceName -NotContains "DnsAdmins"} | ft
	IdentityReferenceName ActiveDirectoryRights             AceType ObjectDN
	--------------------- ---------------------             ------- --------
	DC1$                             GenericAll AccessAllowedObject CN=DFSR-LocalSettings,CN=DC1,OU=Domain Controllers,DC=cor...
	DC1$                             GenericAll AccessAllowedObject CN=Domain System Volume,CN=DFSR-LocalSettings,CN=DC1,OU=D...
	DC1$                             GenericAll AccessAllowedObject CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-Lo...
	stephanie                        GenericAll       AccessAllowed CN=Management Department,DC=corp,DC=com
	stephanie                        GenericAll       AccessAllowed CN=robert,CN=Users,DC=corp,DC=com
```

> A regular user like `stephanie` shouldn't have `GenericAll` perms.  Likely a misconfiguration.
> When originally enumerated `Management Department` only had `jen` as its sole user.
> To prove misconfiguration, using her login, successfully add `stephanie` to the group



- Add & verify `stephanie` to group
```powershell
net group "Management Department" stephanie /add /domain
	The request will be processed at a domain controller for domain corp.com.
	
	The command completed successfully.


Get-NetGroup "Management Department" | select member
	member
	------
	{CN=jen,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}
```


#### User Perms Enum

_Find-LocalAdminAccess_ command scans the network in an attempt to determine if our current user has administrative permissions on any computers in the domain.
- The command relies on the [_OpenServiceW function_](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openservicew) which will connect to the _Service Control Manager_ (**SCM**) on the target machines.
	- The SCM essentially maintains a database of installed services and drivers on Windows computers.
- PowerView will attempt to open this database with the _SC_MANAGER_ALL_ACCESS_ access right, which require administrative privileges.
	- If the connection is successful, PowerView will deem that our current user has administrative privileges on the target machine


- Spray the current env to find possible local admin access on computers under the current user context
```powershell
Find-LocalAdminAccess
	web04.corp.com
	client74.corp.com
```


>While it may be tempting to log in to CLIENT74 and check permissions right away, this is a good opportunity to zoom out and generalize.
>
Penetration testing can lead us in many different directions and while we should definitely follow up on the many different paths based on our interactions, we should stick to our schedule/plan most of the time to keep a disciplined approach.
>
Let's continue by trying to visualize how computers and users are connected together. The first step in this process will be to obtain information such as which user is logged in to which computer.
>
Historically, the two most reliable Windows APIs that could (and still may) help us achieve these goals are [_NetWkstaUserEnum_](https://learn.microsoft.com/en-us/windows/win32/api/lmwksta/nf-lmwksta-netwkstauserenum) and [_NetSessionEnum_](https://learn.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netsessionenum).
The former requires administrative privileges, while the latter does not. However, Windows has undergone changes over the last couple of years, possibly making the discovery of logged in user enumeration more difficult for us.

- Look for logged in users (If no output, use `-Verbose` - May have 'access denied' error)
```powershell
Get-NetSession -ComputerName files04 -Verbose
	VERBOSE: [Get-NetSession] Error: Access is denied


Get-NetSession -ComputerName client74
	CName        : \\192.168.223.75
	UserName     : stephanie
	Time         : 0
	IdleTime     : 0
	ComputerName : client74
```
	- Notice IP address is for client75, NOT client74


According to the documentation for _NetSessionEnum_ there are five possible query levels: 0,1,2,10,502.
- Level 0 only returns the name of the computer establishing the session.
- Levels 1 and 2 return more information but require administrative privileges.
- Levels 10 and 502 should return information such as the name of the computer and name of the user establishing the connection
	- By default, PowerView uses query level 10 with _NetSessionEnum_, which should give us the information we are interested in.

The permissions required to enumerate sessions with _NetSessionEnum_ are defined in the **SrvsvcSessionInfo** registry key:
`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity`

- View perms for above reg key
```powershell
Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl
	Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultS
	         ecurity\
	Owner  : NT AUTHORITY\SYSTEM
	Group  : NT AUTHORITY\SYSTEM
	Access : BUILTIN\Users Allow  ReadKey
	         BUILTIN\Administrators Allow  FullControl
	         NT AUTHORITY\SYSTEM Allow  FullControl
	         CREATOR OWNER Allow  FullControl
	         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
	         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow
	         ReadKey
	...
```
	- BUILTIN, NT AUTHORITY groups, CREATOR OWNER, and APPLICATION PACKAGE AUTHORITY are defined by the system.
	- They do not allow NetSessionEnum to enumerate this registry key from a remote standpoint
	- Last long string `S-1-15...` at the end is a capability SID


**Capability SID**
- An _unforgeable_ token of authority that grants a Windows component or a Universal Windows Application access to various resources.
- Won't give us remote access to the registry key of interest

- Get OS & versions
```powershell
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
	dnshostname       operatingsystem              operatingsystemversion
	-----------       ---------------              ----------------------
	DC1.corp.com      Windows Server 2022 Standard 10.0 (20348)
	web04.corp.com    Windows Server 2022 Standard 10.0 (20348)
	FILES04.corp.com  Windows Server 2022 Standard 10.0 (20348)
	client74.corp.com Windows 11 Enterprise        10.0 (22000)
	client75.corp.com Windows 11 Enterprise        10.0 (22000)
	CLIENT76.corp.com Windows 10 Pro               10.0 (16299)
```

> NetSessionEnum likely won't work on any computers Win 10 16299 (build 1709) or Server 2019 (build 1809) or later.


### PsLoggedOn
- Sysinternal tool
- Enumerates the registry keys under **HKEY_USERS** to retrieve the _security identifiers_ (SID) of logged-in users and convert the SIDs to usernames.
- Will also use the _NetSessionEnum_ API to see who is logged on to the computer via resource shares.
- Relies on the _Remote Registry_ service in order to scan the associated key
	- Remote Registry service has not been enabled by default on Windows workstations since Windows 8
		- Sysadmins may enable it for various administrative tasks, for backwards compatibility, or for installing monitoring/deployment tools, scripts, agents, etc.
	- Enabled by default on later Windows Server Operating Systems such as Server 2012 R2, 2016 (1607), 2019 (1809), and Server 2022 (21H2).
		- If it is enabled, the service will stop after ten minutes of inactivity to save resources, but it will re-enable (with an _automatic trigger_) once we connect with PsLoggedOn.


- Attempt previous enumeration of logged on users of previously unaccessible endpoints
```powershell
.\PsLoggedon.exe \\files04
	PsLoggedon v1.35 - See who's logged on
	Copyright (C) 2000-2016 Mark Russinovich
	Sysinternals - www.sysinternals.com
	
	Users logged on locally:
	     <unknown time>             CORP\jeff
	Unable to query resource logons


.\PsLoggedon.exe \\web04
	PsLoggedon v1.35 - See who's logged on
	Copyright (C) 2000-2016 Mark Russinovich
	Sysinternals - www.sysinternals.com
	
	No one is logged on locally.
	
	Users logged on via resource shares:
	     7/26/2024 2:46:44 PM       CORP\dave
		...
	     7/26/2024 2:49:36 PM       CORP\dave
	     7/26/2024 2:49:41 PM       CORP\stephanie


PS C:\Tools\PSTools> .\PsLoggedon.exe \\client74
	PsLoggedon v1.35 - See who's logged on
	Copyright (C) 2000-2016 Mark Russinovich
	Sysinternals - www.sysinternals.com
	
	Users logged on locally:
	     <unknown time>             CORP\jeffadmin
	
	Users logged on via resource shares:
	     7/26/2024 2:49:59 PM       CORP\stephanie
```


### Service Accounts

May be members of high-privileged groups.

>Applications must be executed in the context of an operating system user.
>If a user launches an application, that user account defines the context. However, services launched by the system itself run in the context of a _Service Account_.
>
In other words, isolated applications can use a set of predefined service accounts, such as _LocalSystem_,[2](https://portal.offsec.com/courses/pen-200-44065/learning/active-directory-introduction-and-enumeration-45847/manual-enumeration-expanding-our-repertoire-46014/enumeration-through-service-principal-names-45857#fn-local_id_927-2) _LocalService_,[3](https://portal.offsec.com/courses/pen-200-44065/learning/active-directory-introduction-and-enumeration-45847/manual-enumeration-expanding-our-repertoire-46014/enumeration-through-service-principal-names-45857#fn-local_id_927-3) and _NetworkService_.[4](https://portal.offsec.com/courses/pen-200-44065/learning/active-directory-introduction-and-enumeration-45847/manual-enumeration-expanding-our-repertoire-46014/enumeration-through-service-principal-names-45857#fn-local_id_927-4)
>
For more complex applications, a domain user account may be used to provide the needed context while still maintaining access to resources inside the domain.
>
When applications like _Exchange_, MS SQL, or _Internet Information Services_ (IIS) are integrated into AD, a unique service instance identifier known as [_Service Principal Name_ (SPN)](https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names) associates a service to a specific service account in Active Directory.


- Obtain the IP address and port number of applications running on servers integrated with AD
	- Specifically `iis_service` here
```powershell
setspn -L iis_service
	Registered ServicePrincipalNames for CN=iis_service,CN=Users,DC=corp,DC=com:
	        HTTP/web04.corp.com
	        HTTP/web04
	        HTTP/web04.corp.com:80
```


- PowerView enumeration of SPNs
```powershell
Get-NetUser -SPN | select samaccountname,serviceprincipalname
	samaccountname serviceprincipalname
	-------------- --------------------
	krbtgt         kadmin/changepw
	iis_service    {HTTP/web04.corp.com, HTTP/web04, HTTP/web04.corp.com:80}
```

- Find IP
```powershell
nslookup.exe web04.corp.com
	Server:  UnKnown
	Address:  192.168.223.70
	
	Name:    web04.corp.com
	Address:  192.168.223.72
```


## Automatic AD Enum

### SharpHound

- Get info
```powershell
Get-Help Invoke-Bloodhound
```

- Gather all data (except for local group policies?)
```powershell
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
	2024-07-27T17:20:50.2790228-07:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
	2024-07-27T17:20:50.3883943-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
	2024-07-27T17:20:50.4196478-07:00|INFORMATION|Initializing SharpHound at 5:20 PM on 7/27/2024
	2024-07-27T17:20:50.4977719-07:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for corp.com : DC1.corp.com
	2024-07-27T17:20:50.5602707-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
	2024-07-27T17:20:50.6696450-07:00|INFORMATION|Beginning LDAP search for corp.com
	2024-07-27T17:20:50.7165232-07:00|INFORMATION|Producer has finished, closing LDAP channel
	2024-07-27T17:20:50.7165232-07:00|INFORMATION|LDAP channel closed, waiting for consumers
	2024-07-27T17:21:21.1546885-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 101 MB RAM
	2024-07-27T17:21:38.6554029-07:00|INFORMATION|Consumers finished, closing output channel
	Closing writers
	2024-07-27T17:21:38.6711676-07:00|INFORMATION|Output channel closed, waiting for output task to complete
	2024-07-27T17:21:38.7960258-07:00|INFORMATION|Status: 106 objects finished (+106 2.208333)/s -- Using 107 MB RAM
	2024-07-27T17:21:38.7960258-07:00|INFORMATION|Enumeration finished in 00:00:48.1272129
	2024-07-27T17:21:38.8428948-07:00|INFORMATION|Saving cache with stats: 65 ID to type mappings.
	 65 name to SID mappings.
	 0 machine sid mappings.
	 2 sid to domain mappings.
	 0 global catalog mappings.
	2024-07-27T17:21:38.8585270-07:00|INFORMATION|SharpHound Enumeration Completed at 5:21 PM on 7/27/2024! Happy Graphing!
```
	- Size of the env will determine duration of result output
	- This output scanned 106 objects
	- Output saved to `stephanie\Desktop\corp audit`
		- Can delete the .bin cache (used to speed up looping)


### BloodHound

Transfer file from Windows to Kali


- Need to start `neo4j` on Kali
```bash
sudo neo4j start
```

- Browse to http://localhost:7474   Default creds neo4j:neo4j (Will ask you to create new creds)

- Start BloodHound
```bash
bloodhound
```





# OLD Content


## Currently Logged in Users

Must tailor our enumeration to consider not only _Domain Admins_ but also potential avenues of "chained compromise" (local admin of workstations -> local admin of servers -> local admin of AD) including a hunt for a _derivative local admin_.

Need a list of users logged on to a target.  Either:
- Interact with the target to detect this directly
- Track a user's active logon sessions on a domain controller or file server.

#### Windows functions:

_NetWkstaUserEnum_ 
- Reqs admin perms
- Returns list of all users logged onto a target workstation

_NetSessionEnum_
- Can be used from a regular domain user
- Returns a list of active user sessions on servers such as fileservers or domain controllers