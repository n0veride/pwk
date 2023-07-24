
Securely Transfer Files  
  
Relies **ssh** for data transfer. **:** is how **scp** distinguishes btw local and remote locations  
  
Local file to remote system:
```bash
scp [OPTION] file remote_user@IP:/path/to/save
```

Remote file to local system:
```bash
scp [OPTION] remote_user@IP:/remote/file /local/path/to/save
```

Remote file to remote system:
```bash
scp [OPTION] remote1@IP:/remote/file remote2@IP:/path/to/save
```
	* to route traffic through the local machine, add the **-3** option  
  
  
**-P** **-** Specifies remote host ssh port  
**-p -** Preserves file's modification and access times  
**-q -** Suppress the progress meter and non-error messages  
**-C -** Forces compressing the data as it's sent to the dest machine  
**-r -** Copy directories recursively