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

##### Script
```powershell
# Store the domain object in the $domainObj variable
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Store the PdcRoleOwner name to the $PDC variable
$PDC = $domainObj.PdcRoleOwner.Name

<######## Can do those two lines, but better would be
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
#>

# Store the Distinguished Name variable into the $DN variable
$DN = ([adsi]'').distinguishedName


# Prints only members of the Domain Admins group
#Write-Host "Members of Domain Admins group"
#Foreach($obj in $Result)
#{
#       if($obj.Properties.memberof -match 'Domain Admins')
#       {
#               $obj.Properties.name
#       }
#}

# Prints only computers running Windows 10 - USE with line 39->  $Searcher.filter="ObjectClass=computer"
#Write-Host "Computers running Win10"
#Foreach($obj in $Result)
#{
#       if($obj.Properties.operatingsystem -match 'Windows 10')
#       {
#               $obj.Properties.name
#               Write-Host "----------------------------"
#       }
#}
```
	- Once LDAP provider path is build (using $SearchString), we can instantiate the DirectorySearcher class
	- Attributes of a User object are stored in the Properties field

Script's output:
```powershell
LDAP://DC01.corp.com/DC=corp,DC=com
```
	Full provider path needed to perform LDAP queries against the DC

Can now instantiate the _DirectorySearcher_ class with this path
	- Have to specify a *SearchRoot* (node in AD heirarchy where searches start)


NOTE:   Don't forget to set the [Execution Policy](Execution%20Policy.md)


## Nested Groups

Locate all groups ina domain and list them:
```powershell
$Searcher.filter="(objectClass=Group)"

$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
    $obj.Properties.name
}
```

Obtain group members:
```powershell
$Searcher.filter="(name=Secret_Group)"

$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
    $obj.Properties.member
}
```


## Current Logged in Users

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