
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

When a user logs in to the domain, their credentials are cached in memory on the computer they logged in from

  
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

## Object Class
- Defines the object type
- Abstract class
- Structural class
- Auxiliary class

Attack typically begins w/ successful exploit or client-side attack against either a domain workstation or server.

Goal is to advance priv level until control's gained of one or more domains.  
  
\*\*For the module: Assume Win 10 compromise & use of _Offsec_ domain user (member of local admin group for domain-joined workstation)


# _Public Key Infrastructure_ (PKI)

- Exchanges digital certificates between authenticated users and trusted resources

Microsoft provides the AD role `Active Directory Certificate Services` (AD CS) to implement a PKI.

If a server is installed as a `Certification Authority` (CA), it can issue and revoke digital certificates 
- Could issue certificates for web servers to use HTTPS or to authenticate users based on certificates from the CA via _Smart Cards_

Certificates may be marked as having a `non-exportable private key` for security reasons
- A private key associated with a certificate cannot be exported even with administrative privileges.
- Mimikatz' `crypto` module contains the capability to either patch the `CryptoAPI` function with **crypto::capi** or `KeyIso` service with **crypto::cng**, making non-exportable keys exportable.

# Vocab

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

# Attributes
- Stored in the *Properties* field  

*samAccountType*
- Applied to all user, computer, and group objects

| Type                          | Hex        | Dec        |
|:----------------------------- | ---------- | ---------- |
| SAM_DOMAIN_OBJECT             | 0x0        | 0          |
| SAM_GROUP_OBJECT              | 0x10000000 | 268435456  |
| SAM_NON_SECURITY_GROUP_OBJECT | 0x10000001 | 268435457  |
| SAM_ALIAS_OBJECT              | 0x20000000 | 536870912  |
| SAM_NON_SECURITY_ALIAS_OBJECT | 0x20000001 | 536870913  |
| SAM_USER_OBJECT               | 0x30000000 | 805306368  |
| SAM_MACHINE_ACCOUNT           | 0x30000001 | 805306369  |
| SAM_TRUST_ACCOUNT             | 0x30000002 | 805306370  |
| SAM_APP_BASIC_GROUP           | 0x40000000 | 1073741824 |
| SAM_APP_QUERY_GROUP           | 0x40000001 | 1073741825 |

# .NET Classes

_System.DirectoryServices_ namespace contains two classes that help with AD search functionality

## _DirectoryEntry_ class
- Encapsulates an object in the AD service hierarchy.
	- As we want to search from the very top of the AD hierarchy, we'll provide the obtained full LDAP path `LDAP://HostName[:PortNumber][/DistinguishedName]`
- Can pass creds to in order to authenticate to the domain.

## _DirectorySearcher_ class
- Performs queries against AD using LDAP
- When creating an instance, must specify the AD service we want to query in the form of the _SearchRoot_ property.
	- Will pass LDAP path that points to the top of the hierarchy.

### SearchRoot property
- Indicates where the search begins in the AD hierarchy


# Authentication

## NTLM

- Challenge and Response paradigm
- Used when
	- Client authenticates to a server by IP address OR
	- User attempts to authenticate to a hostname that is not registered on the AD-integrated DNS server
- Third-party apps may use instead of Kerberos

**Process:**
- Client initiates auth through the server, once all parts are in place, then server forwards to DC
![](ad_ntlm.png)
1. Client calculates a cyrptographic, NTLM hash of the users's pw
2. Client sends their uname to the server
3. Server returns a nonce
4. Client encrypts the nonce using the NTLM hash (response) and sends it to the server
5. Server sends the uname, nonce, and response to the DC
6. DC performs validation (already knows all NTLM hash of all users)
	- Encrypts the nonce w/ its own NTLM record for the user and compares to the received response


## Kerberos

- Primary Windows authentication system since Win Server 2003
- Ticket paradigm
- Stateless protocol
- Designed to mitigate various network attacks and prevent the use of fake credentials.
- Makes use of single sign-on

**Cred Cache:**
- Hashes stored in lsass
	- *Local Security Authority Subsystem Service*
	- Part of the OS & runs as SYSTEM
	- Data structures used to store the hashes in memory aren't publicly documented  are encrypted with an LSASS-stored key

Lsass can be protected against mimikatz extracting hashes by enabling LSA Protection
- By setting a registry key, Windows prevents reading memory from this process.


**Process:**
- Client initiates auth with KDC
- DC acts as *Key Distribution Center* (KDC)
	- A KDC service runs on each DC & is responsible for session tickets and temporary session keys to users and computers.

![](ad_kerberos.png)
1. User logs in and sends an `Authentication Server Request` (AS-REQ) to DC
	- `AS-REQ` contains a timestamp that is encrypted using a hash derived from the password of the uname & pw
2. DC receives request, looks up the pw hash in its **ntds.dit** file & attempts to decrypt the timestamp and responds back to the client with an `Authentication Server Reply` (AS-REP)
	- If decryption is successful and timestamp is unique, authentication is successful
		- Duplicated timestamps may suggest a replay attack
	- AS-REP contains a `session key` and a `Ticket Granting Ticket` (TGT).
		- `Session Key` is encrypted using the user's pw hash and may be decrypted by the client and then reused
		- `TGT` contains information regarding the user, the domain, a timestamp, the client's IP, and the session key
			- To avoid tampering, the `TGT` is encrypted by a secret key (NTLM hash of the *krbtgt* account) known only to the KDC and cannot be decrypted by the client


`KDC` considers the client auth complete when the client receives the `session key` and `TGT`.
`TGT`s are valid for 10 hours.  Afterward, renewal occurs though the user doesn't need to re-enter their pw.

When a user wants to access a domain resource (network share, mailbox, etc), it contacts the `KDC`:
3. Client sends a `Ticket Granting Service Request` (TGS-REQ) packet to the `KDC`
	- `TGS-REQ` consists of the current user and a timestamp encrypted with the `session key`, the name of the resource, and the encrypted `TGT`.
4. `KDC` receives the `TGS-REQ` and, if the resource exists w/in the domain, decrypts the `TGT` using the `KDC`'s `secret key`
	- `session key` is extracted and used to decrypt the uname & timestamp of request.  `KDC` performs several checks:
		1. `TGT` must have a valid timestamp
		2. uname from the `TGS-REQ` has to match uname from `TGT`
		3. Client IP must match `TGT` IP address.
	- If successful, the ticket granting service responds to the client with a `Ticket Granting Server Reply` (TGS-REP) which contains:
		- Name of the service that's been granted access
			- Encrypted using the original `session key` associated with the creation of the `TGT`
		- `Session key` to be used between client and service
			- Encrypted using the original `session key` associated with the creation of the `TGT`
		- `Service ticket` containing the username and group memberships along with the newly-created session key
			- Encrypted using the password hash of the service account registered with the service in question.


`KDC` involvement is complete once the client has the `session key` and `service ticket`.   Afterwards, service auth begins:
5. Client sends the Application Server an `Application Request` (AP-REQ)
	- `AP-REQ` contains uname and timestamp encrypted with the `session ticket` and `session key` associated w/ the `session ticket`
6. App Server decrypts the `service ticket` using the service account pw hash and extracts the uname and the `session key`.
   Then uses the `session key` to decrypt the uname from the `AP-REQ`
	- If the unames match, then the request is successful
   The service inspects the `service ticket's` group membership, assigns appropriate permissions to the user, and grants access to the requested service

  