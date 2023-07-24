

### Windows:  

Privileges refer to perms of a specific account to perform system-related local ops.  
Includes actions like modifying the filesystem, adding users, shutting down the system, etc.  
  
  
#### Access Tokens  
- Generated and assigned on user creation.  
- Contains info describing the security context of a given user (inc privileges)  
- Uniquely identifiable via _SID_  
  
  
#### SID
- Security identifier  
- Unique value assigned to each object (including tokens) like user or group account.  
- Generated & maintained by Windows Local Security Authority  
  
  
#### Integrity Mechanism
- Core component of Win security architecture  
- Assigns _Integrity Levels_ to app processes & securable objects.  
  
  
#### Integrity Levels 
- Describes level of trust the OS has in running apps or securable objects.  
- Dictates what actions an app can perform, including ability to read from or write to local file system.  
- APIs can be blocked from specific integrity levels.  
  
  
#### 4 Integrity Levels:  
1. System integrity process: SYSTEM rights  
2. High integrity process: administrative rights  
3. Medium integrity process: standard user rights  
4. Low integrity process: Very restricgted rights. Often used in sandboxed processes.  
  
  
#### UAC - User Account Control  
Any app that wishes to perform an operation w/ a potential system-wide impact can't do it silently.  
- Access control system intro'd w/ Vista & Server 2008.  
- Not considered to be a security boundary.  
- Forces apps & tasks to run in the context of a non-admin account until an admin authorizes elevated access.  
- Blocks installers & unauth'd apps from running w/o perms of admin  
- Blocks changes to system settings w/o perms of admin  
- Can be bypassed:  
- **Start-Process** cmdlet w/ **-Verb runAs**  
- **fodhelper.exe**  
  
  
Two modes:  
- Credential prompt  
- Standard user req admin approval  
- Consent prompt  
- Admin attempting same task  
  
  
admin user still has two security tokens which are separated by UAC  
- Medium integrity  
- High integrity.  
  
  
View integrity levels of user:  
```powershell
whoami /groups
```

Run a binary with High Integrity Level set to bypass UAC:  
```powershell
powershell.exe Start-Process cmd.exe -Verb runAs
```
	Same as Rt-clicking cmd.exe and Open As Admininistrator  
  
  
Reg key stuffs (why [fodhelper.exe](fodhelper.exe.md) works):  
  
W/ research [11](https://docs.microsoft.com/en-us/windows/win32/shell/launch)), we can infer that **fodhelper** is opening a section of the Windows Settings application (likely the Manage Optional Features presented to the user when fodhelper is launched)  
through the **ms-settings: application protocol.** [12](https://blogs.msdn.microsoft.com/ieinternals/2011/07/13/understanding-protocols/))  
An application protocol on Windows defines the executable to launch when a particular URL is used by a program.  
These URL-Application mappings can be defined through Registry entries similar to the **ms-setting** key we found in **HKCR**.  
  
In this particular case, the application protocol schema for **ms-settings** passes the execution to a **COM** [13](https://docs.microsoft.com/en-us/windows/win32/com/the-component-object-model)) object rather than to a program.  
**This can be done by setting the _DelegateExecute_ key value [14](https://docs.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexa) to a specific COM class ID as detailed in the MSDN documentation.  
  
This is definitely interesting because **fodhelper** tries to access the **ms-setting** registry key within the **HKCU** hive first.  
Previous results from [**procmon**](procmon.md) clearly showed that this key does not exist in HKCU, but we should have the necessary permissions to create it.  
This could allow us to hijack the execution through a properly formatted protocol handler.

[regadd](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/reg-add)