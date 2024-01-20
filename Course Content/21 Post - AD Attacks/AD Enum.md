

First goal:
- Advance our privilege level until we gain control of one or more domains.
- Enumerate the domain users and learn as much as we can about their group memberships in search of high-value targets

	- Target high-value groups (like compromising a member in *Domain Admins* group)
	- Compromise a DC (all pw hashes, can modify/ run apps on all domain-joined comps)

*Can* use prev learned [auto](Auto%20Enum.md) and [manual](Manual%20Enum.md) enumerations techniques.

Assuming:
	Obtained access to a domain-joined Win10 Workstation
	Compromise of *Offsec* domain member of the local administrator group


## Traditional:   [net.exe](OS%20Commands.md#net)

##### User Enum:
```powershell
net user

	User accounts for \\CLIENT251

-------------------------------------------------------------------------------
	admin                    Administrator            DefaultAccount
	Guest                    offsec                   student
	WDAGUtilityAccount
	The command completed successfully.
```


##### Domain Users Enum:
```powershell
net user /domain
	The request will be processed at a domain controller for domain corp.com.


	User accounts for \\DC01.corp.com

-------------------------------------------------------------------------------
	adam                     Administrator            DefaultAccount
	Guest                    iis_service              jeff_admin
	krbtgt                   offsec                   sql_service
	The command completed successfully.
```
	Notice *jeff_admin* user.


##### Specific User Enum:
```powershell
net user jeff_admin /domain
	The request will be processed at a domain controller for domain corp.com.

	User name                    jeff_admin
	...
	Account active               Yes
	Account expires              Never
	Password last set            2/5/2020 2:52:10 PM
	Password expires             Never
	Password changeable          2/6/2020 2:52:10 PM
	Password required            Yes
	User may change password     Yes
	...
	Last logon                   1/21/2020 9:03:34 PM
	...
	Local Group Memberships
	Global Group memberships     *Domain Admins        *Domain Users
```


##### Domain Group Enum:
```powershell
net group /domain
	The request will be processed at a domain controller for domain corp.com.

	Group Accounts for \\DC01.corp.com

-------------------------------------------------------------------------------
	*Another_Nested_Group
	...
	*Domain Admins
	*Domain Computers
	*Domain Controllers
	*Domain Guests
	*Domain Users
	*Enterprise Admins
	...
	*Key Admins
	*Nested_Group
	*Protected Users
	...
	*Secret_Group
	The command completed successfully.
```
	Note *Another_Nested_Group *Nested_Group *Secret_Group
		- A group (& all its members) can be added as a member

*Note:   [**net.exe**](OS%20Commands.md#net) can only show direct user members, not users of nested groups*


## Modern: 

*okay*-ish cmdlet:
```powershell
Get-ADUser
```
	Only installed by default on DC's w/ RSAT
		*RSAT - Remote Server Admin Tools
	Requires admin privs


Better PS script:
	Query the network for the name of the Primary domain controller emulator and the domain, search Active Directory and filter the output to display user accounts, and then clean up the output for readability.  *Can add features and functions as needed*

Centers around LDAP provider path which serves as input to the DirectorySearcher class to query [LDAP](ldap.md):
```powershell
LDAP://HostName[:PortNumber][/DistinguishedName]
```

Reqs:
- Target hostname (name of the DC)
- Distinguished Name (DN) of the domain
Can find w/ PS query:
```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()


Forest                  : corp.com
DomainControllers       : {DC01.corp.com}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : DC01.corp.com
RidRoleOwner            : DC01.corp.com
InfrastructureRoleOwner : DC01.corp.com
Name                    : corp.com
```
	- Domain class of the _System.DirectoryServices.ActiveDirectory_ namespace
		- Contains method GetCurrentDomain()
			- Retrieves Domain object for the currently logged in user
	 - Name = domain name (corp.com)
	- PdcRoleOwner = Primary domain controller (DC01.corp.com)

Script to build LDAP provider path:
```powershell
# Stores entire domain object
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Stores name of the Primary Domain Controller
$PDC = ($domainObj.PdcRoleOwner).Name

# Builds the provider path for output
$SearchString = "LDAP://"

$SearchString += $PDC + "/"

# Consists of Domain Name broken down into indivudual core components
#   Will output "DC=corp,DC=com"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)

$objDomain = New-Object System.DirectoryServices.DirectoryEntry($SearchString, "corp.com\offsec", "lab")

# Node in the Active Directory hierarchy where searches start
#  When no args are passed to the constructor, search results return from the entire domain
$Searcher.SearchRoot = $objDomain

#Filter out results:

#  All users in the domain:
$Searcher.filter="samAccountType=805306368"

#  Specific account:
#$Searcher.filter="name=Jeff_Admin"

#  All computers in the domain
#$Searcher.filter="ObjectClass=computer"

# Run a search to find all results that matches the filter
$Result = $Searcher.FindAll()

# Prints out all attributes on their own line
Foreach($obj in $Result)
{
        Foreach($prop in $obj.Properties)
        {
                $prop
        }

        Write-Host "-----------------------------"
}


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

_NetWkstaUserEnum_[2](https://portal.offensive-security.com/courses/pen-200/books-and-videos/modal/modules/active-directory-attacks/active-directory-enumeration/currently-logged-on-users#fn2) 
- Reqs admin perms
- Returns list of all users logged onto a target workstation

_NetSessionEnum_[3](https://portal.offensive-security.com/courses/pen-200/books-and-videos/modal/modules/active-directory-attacks/active-directory-enumeration/currently-logged-on-users#fn3)
- Can be used from a regular domain user
- Returns a list of active user sessions on servers such as fileservers or domain controllers