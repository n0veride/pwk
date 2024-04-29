# Windows Privileges

Privileges refer to perms of a specific account to perform system-related local ops.  
Includes actions like modifying the filesystem, adding users, shutting down the system, etc.  
    
## Access Tokens  
- Generated and assigned on user creation.  
- Contains info describing the security context of a given user (inc privileges)  
- Uniquely identifiable via _SID_  

## SID
- Security identifier  
- Unique value assigned to each object (including tokens) like user or group account.  
- Generated & maintained by Windows Local Security Authority    
  
## Integrity Mechanism
- Core component of Win security architecture  
- Assigns _Integrity Levels_ to app processes & securable objects.  


## Integrity Levels 
- Describes level of trust the OS has in running apps or securable objects.  
- Dictates what actions an app can perform, including ability to read from or write to local file system.  
- APIs can be blocked from specific integrity levels.  

1. System integrity process: SYSTEM rights  
2. High integrity process: administrative rights  
3. Medium integrity process: standard user rights  
4. Low integrity process: Very restricted rights. Often used in sandboxed processes.  
  
  
## UAC - User Account Control  
Any app that wishes to perform an operation w/ a potential system-wide impact can't do it silently.  
- Access control system intro'd w/ Vista & Server 2008.  
- Not considered to be a security boundary.  
- Forces apps & tasks to run in the context of a non-admin account until an admin authorizes elevated access.  
- Blocks installers & unauth'd apps from running w/o perms of admin  
- Blocks changes to system settings w/o perms of admin  
- Can be bypassed:  
- **Start-Process** cmdlet w/ **-Verb runAs**  
- **fodhelper.exe**  
  
  
### Two modes
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
  
  
## Reg key stuffs
(why [fodhelper.exe](fodhelper.exe.md) works) 
  
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



# Linux Permissions

Access level that the system processes, users, and groups have to files/ directories
![[permissions.png]]

From [GeekDiary](https://www.thegeekdiary.com/linux-unix-examples-of-find-command-to-find-files-with-specific-sets-of-permissions/):  
  
1st bit is for special permission e.g. [SUID](Perms.md#SUID) [SGID](Perms.md#SgID) or [sticky bit](Perms.md#Sticky%20Bit)
4th bit is for others permission  
  
4 - Read Permission (r)
2 - Write Permission (w)
1 - Executable Permission (x)
  
  
Find existing binaries w/ SUID or GUID perms on them:  
```bash
find / -perm -u=s -type f 2>/dev/null; find / -perm -4000 -o- -perm -2000 -o- -perm -6000
```

1. Command to find files with (group or other or both) writable permission and SET UID set .  
```bash
find / -perm /022 -and -perm -4000 -exec ls -ldb {} ;
``` 
						^^^^           ^  
						| | | |        |-- So the SUID is 4  
						| | | |-- Other is writable (2)  
						| | |--Group permission is writable (2)  
						| |-- No owner permission mentioned (0)  
						|-- As the logic is OR - group or other or both  
So the logic is : ( group writable OR other writable ) AND SUID set  

2. Command to list files with other writable excluding sticky bit set.  
```bash
find / -perm -002 -not -perm -1000 -exec ls -ldb {} ;
```  
						^^^^           ^  
						| | | |        |-- So the sticky bit is set (1)  
						| | | |-- Other is writable (2)  
						| | |--No group permission mentioned (0)  
						| |-- No owner permission mentioned (0)  
						|-- Well it does not matter if it is "-" or "/" as there is only one condition mentioned  
Now the logic here is : Other writable NOT sticky bit set  
  
  
****  
It is often the case that admins aren't familiar with their apps but still assign the SUID/GUID bits, which leads to a high-security risk.  

Such programs may contain functions that allow the execution of a shell from the pager, such as the application "journalctl."  

If the admin sets the SUID bit to "journalctl", any user with access to this application could execute a shell as root.


## SGID

The effective GID of the command/ script being run becomes that of the group the file is a member of rather than the group of the user who's running it.  
  
When SGID permission is set on a directory, files created in the directory belong to the group of which the directory is a member.  
  
Permission is displayed as an **s** in the group's execute field  
If a lowercase **l** is displayed, it indicates that the setgid bit is on, but the execute bit for the group of the file is off or denied  

```bash
ls -l /usr/bin/mlocate  
-rwxr-sr-x 1 root mlocate 47496 Jan  6  2021 /usr/bin/mlocate  
ls -l /usr/bin/passwd  
-rwsr-xr-x 1 root root 59976 Jul 14 15:57 /usr/bin/passwd
```

To set SGID on a file:  
```bash
chmod 2xxx [path-to-file]
```

To set SGID on a directory:  
```bash
chmod g+s [path_to_directory]
```


## Sticky Bit

Gives only the owner of the file/directory or the root user permission to delete or rename the file.  
  
Permission is displayed as a **t** in the owner's execute field  
If a capital **T** is displayed, it indicates that the sticky bit is on, but the execute bit for others of the file is off or denied  

```bash
ls -ld /var/tmp  
drwxrwxrwt 8 root root 4096 Oct  9 13:20 /var/tmp
```

To set sticky bit on a file:  
```bash
chmod 1xxx [path-to-file/directory]  
chmod +t [path-to-file/directory]
```

## SUID

The effective UID of the command/ script being run becomes that of the owner of the file rather than the user who's running it.  
  
Permission is displayed as an **s** in the owner's execute field  
If a capital **S** is displayed, it indicates that the setuid bit is on, but the execute bit for the owner of the file is off or denied  
  
```bash
ls -l /usr/bin/passwd  
-rwsr-xr-x 1 root root 59976 Jul 14 15:57 /usr/bin/passwd
```

To set SUID on a file:  
```bash
chmod 4xxx  [path-to-file]
```