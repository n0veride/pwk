

An _Active Directory Service Interfaces_ (ADSI)[6](https://portal.offensive-security.com/courses/pen-200/books-and-videos/modal/modules/active-directory-attacks/active-directory-enumeration/a-modern-approach#fn6) provider (essentially an API) that supports search functionality against an Active Directory.


Network protocol understood by domain controllers also used for communication with third-party applications.


Very specific _LDAP provider path_[7](https://portal.offensive-security.com/courses/pen-200/books-and-videos/modal/modules/active-directory-attacks/active-directory-enumeration/a-modern-approach#fn7) that will serve as input to the _DirectorySearcher_[4](https://portal.offensive-security.com/courses/pen-200/books-and-videos/modal/modules/active-directory-attacks/active-directory-enumeration/a-modern-approach#fn4) .NET class:
```powershell
LDAP://HostName[:PortNumber][/DistinguishedName]
```
