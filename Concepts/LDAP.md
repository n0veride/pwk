
Protocol used to communicate with Active Directory.
- When a domain machine searches for an object, like a printer, or when we query user or group objects, LDAP is used as the communication channel for the query

```powershell
LDAP://HostName[:PortNumber][/DistinguishedName]
```
- 3 Parameters for full LDAP path
	- HostName
		- Computer name, IP, domain name, etc
			- A domain may have multiple DCs, so setting the domain name could potentially resolve to the IP address of any DC in the domain.
			- Should look for domain that has most updated info - PDC *Primary Domain Controller*
				- Has `PdcRoleOwner` property.
	- PortNumber
		- Optional
		- Automatically chosen based on whether or not using SSL connection
		- May need to manually add if domain is using non-default ports
	- DistinguishedName (`DN`)
		- Uniquely identifies an object in AD, including the domain itself.

## Naming Convention

For LDAP to function, objects must be formatted to specific naming standards.

The `DN` of a domain with a user `stephanie` and domain name `corp.com` *may* look like this
- `CN=Stephanie,CN=Users,DC=corp,DC=com`


`CN` - Common Name
- Specifies the identifier of an object within the domain
`DC` (When referring to `DN`) - Domain Component
- Represents the top of an LDAP tree

When reading a DN, we start with the Domain Component objects on the right side and move to the left.
With regards to above example, there's 4 components:
- 2 `DC`'s
	- `DC=corp,DC=com`
- `CN=Users`
	- Common Name for the container where the user object is stored (aka 'parent container')
- `CN=Stephanie`
	- Common Name for the user object itself & lowest in hierarchy

> When enumerating, we want to focus on the `DC` object.  Adding `CN=Users` would restrict our enumeration only to objects within that given container.

