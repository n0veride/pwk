

#### Active Directory Domain Services  
  
Allows sysadmins to update and manage OSs, apps, users, & data access on a large scale.
- Massive attack surface.  
  
  
Critical dependency on DNS. Typically, ADs will also host an authoritative DNS server for a given domain.  
  
Several components:  
  
###### DC - Domain Controller
	Win Server 2000-2019 - w/ ADDS role installed  
- Hub & core of AD as it stores all info about how the specific instance of AD is configured.  
- Enforces a vast variety of rules that govern how objects w/in a given Win domain interact w/ each other & the tools/ services available to end users.  
- Incredibly granular (even down to the wallpaper).
- Contains all pw hashes of every domain user account.

  
###### Domain
	such as corp.com - where _corp_ is the name of the org.  
- Can add various types of object, such as computers and users  
- Organized with help of _Organizational Units_ (OU) - containers used to store & group other objects (like folders)  
  
  
###### Objects  
- Computer objects
	- actual servers, workstations, etc'd that are _domain-joined_  
- User objects - employees in the org  
	- Contain attributes which vary according to the type of object.
		- Ex: user object may include attributes such as first/ last name, uname, pw, etc.
		- Attributes are stored in the Properties field
  
  
Some orgs will have machines that aren't domain-joined. Ex: Internet-facing machines..  
  

###### Groups
- Sysadmins use groups to to assign permissions to member users. Target = high-value users. Eg: _Domain Admins_ group.  
- Gaining control of a DC allows modification of all domain-joined comps, apps on them, &/ or pw hashes.
- Nesting - Can be added as a member to another group
  
  
Attack typically begins w/ successful exploit or client-side attack against either a domain workstation or server.

Goal is to advance priv level until control's gained of one or more domains.  
  
  
\*\*For the module: Assume Win 10 compromise & use of _Offsec_ domain user (member of local admin group for domain-joined workstation)


###### Vocab:

*DirectorySearcher* = Class which queries AD using LDAP protocol
[*LDAP*](ldap.md) = Network protocol for DC which supports search functionality
*PdcRoleOwner* = Primary DC
*SearchRoot* = Node in the AD heirarchy where searches start