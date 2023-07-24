
Searches for given files and directories  
  
  
**2>/dev/null** - Sinkholes stderr messages to null  
**-exec** -  
**{}** - Ran w/ **exec**. Expands command to the filename of each of the files/ directories found by **find**  
**\;** - Ends command ran by **exec**. Must be escaped (hence **\**). Runs command per file  
**+** - Ends command ran by **exec**. Appends found files to end of the command so command is run only once. More efficient than **\;**  
  
```bash
find / -size 64c -exec grep -Hi base64 {} \;
```

**-mmin** _n_ - Searches for files modified >,<,= _n_ minutes ago ( +_n_ for greater than, -_n_ for less than, _n_ for exactly)  
**-mtime** _n_ - Searches for files modified >,<,= _n_ * 24 hrs ago ( +_n_ for greater than, -_n_ for less than, _n_ for exactly)  
**-perm** _mode_ - File's [permission bits](Perms.md) are exactly set to _mode_  
**-**_mode_ - All file's permission bits are set to _mode_  
**/**_mode_ - Any file's permission bits are set to _mode_  
**-empty** - Finds all empty files and directories  
**-type** **d**_/_ **f** - Only match directories/ files.  
**-delete** - Delete files. Always put this option at the end of the find command  

  
Looks for files/ dirs with the SUID bit set:
```bash
find / -perm -u=s.....
```
