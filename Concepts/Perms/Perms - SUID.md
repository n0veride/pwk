

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