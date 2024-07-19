
# Active Directory Domain Services  
  
Service and management layer.

Allows sysadmins to update and manage OSs, apps, users, & data access on a large scale.
- Massive attack surface.
- Critical dependency on DNS. Typically, ADs will also host an authoritative DNS server for a given domain.
- Can host more than one domain in a *Domain Tree*
- Can host more than one domain tree in a *Domain Forest*
  
>While there is a Domain Admins group for each domain in the forest,
>members of the _Enterprise Admins_ group are granted full control over all the domains in the forest
>and have Administrator privilege on all DCs


Relies heavily on [LDAP](LDAP.md)

  
# Components
## DC - Domain Controller
	Win Server 2000-2019 - w/ ADDS role installed  
- Hub & core of AD as it stores all info about how the specific instance of AD is configured.  
- Enforces a vast variety of rules that govern how objects w/in a given Win domain interact w/ each other & the tools/ services available to end users.  
- Incredibly granular (even down to the wallpaper).
- Contains all pw hashes of every domain user account.
  
## Domain
	such as corp.com - where _corp_ is usually the name of the org.  
- Contains various types of objects:  such as computers, groups, and users  
- Organized with help of _Organizational Units_ (OU)

## Domain Controller
- Used on logging into a domain
- Checks whether or not user is allowed to log in to the domain
- One or more acts as core of the domain
- Stores all OUs, objects, and their attributes

## Organizational Units (OUs)
- Comparable to file system folders
- Containers to store objects within in the domain
  
## Objects
- Computer objects
	- Actual servers, workstations, etc'd that are _domain-joined_  
- User objects
	- Employees in the org
- Contain attributes which vary according to the type of object.
	- Stored in the Properties field
	- ex: User Object may include attributes such as first/ last name, uname, pw, , phone number, etc.
  
Some orgs will have machines that aren't domain-joined. Ex: Internet-facing machines..  

## Groups
- Used by sysadmins to assign objects to a single unit for easier mgmt
	- Target = high-value users. eg: _Domain Admins_ (most privileged) group. 
- Gaining control of a DC allows modification of all domain-joined comps, apps on them, &/ or pw hashes.
- Nesting - Can be added as a member to another group
  
  
Attack typically begins w/ successful exploit or client-side attack against either a domain workstation or server.

Goal is to advance priv level until control's gained of one or more domains.  
  
  
\*\*For the module: Assume Win 10 compromise & use of _Offsec_ domain user (member of local admin group for domain-joined workstation)


## Vocab

***DirectorySearcher***
- Class which queries AD using LDAP protocol
**[*LDAP***](ldap.md)
- Lightweight Directory Access Protocol
- Network protocol for DC which supports search functionality
***PdcRoleOwner***
- Primary DC
***SearchRoot***
- Node in the AD hierarchy where searches start
***Domain Tree***
- Made up of multiple domains that share a common schema and configuration forming a contiguous namespace.
***Domain Forest***
- Collection of one or more domain trees.