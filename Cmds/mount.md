
Mount a filesystem.  
  
Standard form:  
```bash
mount <device> <dir>
```

_/etc/fstab_ may contain lines describing what devices are usually mounted, where, and using which options.  
  
To override mount options from _/etc/fstab_, you need to use the **-o** switch ---- Multiple options can be strung together with a _**,**_  


**-o** - Override mount options from /etc/fstab  
**nolock** - Disable file locking (used w/ **-o**)  
**vers=<**_**n**_> - Mounts via NFS version _n_ (used w/ **-o**)  


to remove a persistant share:  
```bash
unmount -f -l /mnt/dir
```
