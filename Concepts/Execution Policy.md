
Policy for PowerShell dictating running of scripts.  
  
Set on a per-user basis, not per-system  
  
Can be dictated by one or more ActiveDirectory GPOs.  
- If trying for an [In-Memory injection](In-Memory.md), will need to look for additional bypass vectors  
  
  
View & Change policy:  
```powershell
C:\Users\offsec\Desktop> powershell  
Windows PowerShell  
Copyright (C) 2015 Microsoft Corporation. All rights reserved.  
  
PS C:\Users\offsec\Desktop> Get-ExecutionPolicy -Scope CurrentUser  
Undefined  
  
PS C:\Users\offsec\Desktop> Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser  
  
PS C:\Users\offsec\Desktop> Get-ExecutionPolicy -Scope CurrentUser  
Unrestricted
```
  
Can also bypass the policy on a per-script basis:  
```powershell
ExecutionPolicy -Bypass
```