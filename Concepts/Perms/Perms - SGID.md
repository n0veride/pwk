
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