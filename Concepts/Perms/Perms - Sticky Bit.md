
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