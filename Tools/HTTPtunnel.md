

Linux - Encapsulates traffic w/in HTTP requests creating an HTTP tunnel.  
  
Uses a client/ server model.  
  
Usage Ex:  
```bash
hts --forward-port localhost:8888 1234  
  
htc --forward-port 8080 10.11.0.128:1234
``` 
	**hts** - Server  
	**htc** - Client  
  
  
• stunnel is similar & can be used in similar ways.  
	◇ Multiplatform GNU/GPL-licensed proxy that encrypts arbitrary TCP connections w/ SSL/TLS  
  
  
-c, --content-length BYTES      Use HTTP PUT requests of BYTES size (k, M, and G postfixes recognized)  
-d, --device DEVICE      Use DEVICE for input and output  
-F, --forward-port HOST:PORT      Connect to PORT at HOST and use it for input and output  
-h, --help      Display this help and exit  
-k, --keep-alive SECONDS      Send keepalive bytes every SECONDS seconds (default is 5)  
-M, --max-connection-age SEC      Maximum time a connection will stay open is SEC seconds (default is 300)  
-r, --chroot ROOT      Change root to ROOT  
-s, --stdin-stdout      Use stdin/stdout for communication (implies --no-daemon)  
-S, --strict-content-length      Always write Content-Length bytes in requests  
-u, --user USER      Change user to USER  
-V, --version      Output version information and exit  
-w, --no-daemon      Don't fork into the background  
-p, --pid-file      LOCATION Write a PID file to LOCATION