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

## PowerShell and .NET classes

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