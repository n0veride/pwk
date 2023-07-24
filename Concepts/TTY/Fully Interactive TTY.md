

When bind/ reverse bind doesn't allow full execution & view of binaries, check shell:  
```bash
echo $SHELL
```  

if it comes back w/ something like /usr/bin/nologin, you may need a full TTY:  
  

## Fully interactive TTY shell with Python
  
  
Shell to Bash #  
Upgrade from shell to bash.  
```bash
SHELL=/bin/bash script -q /dev/null
```
	Should work enough
  
Python PTY Module 1 #  
Spawn /bin/bash using Python's PTY module, and connect the controlling shell with its standard I/O:  
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

Fully Interactive TTY #  
Background the current remote shell (^Z), update the local terminal line settings with stty2 and bring the remote shell back.  
```bash
stty raw -echo && fg
```