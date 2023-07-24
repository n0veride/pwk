
Network authentication cracking tool (primarily designed to leverage SSH keys rather than pws)  
  
*As RDP doesn't reliably handle multiple threads, make sure to **-n 1** if you're attacking it.  
  
  
**-h**, --help :      Show this help message and exit  
**-b** {openvpn,rdp,sshkey,vnckey}, --brute {openvpn,rdp,sshkey,vnckey} :      Target service  
**-s** SERVER, --server SERVER :      Static target  
**-S** SERVER_FILE, --serverfile SERVER_FILE :      Multiple targets stored in a file  
**-u** USERNAME \[USERNAME ...\], --username USERNAME \[USERNAME ...\] :      Static name to login with  
**-U** USERNAME_FILE, --usernamefile USERNAME_FILE :      Multiple names to login with, stored in a file  
**-n** THREAD, --number THREAD :      Number of threads to be active at once  
**-l** FILE, --log FILE :      Log file (only write attempts)  
**-o** FILE, --output FILE :      Output file (write everything else)  
**-c** PASSWD, --passwd :      PASSWD Static password to login with  
**-C** FILE, --passwdfile FILE :      Multiple passwords to login with, stored in a file  
**-t** TIMEOUT, --timeout TIMEOUT :      \[SSH\] How long to wait for each thread (seconds)  
**-p** PORT, --port PORT :      Alter the port if the service is not using the default value  
**-k** KEY_FILE, --keyfile KEY_FILE :      \[SSH/VNC\] (Private) Key file or folder containing multiple files  
**-m** CONFIG, --config CONFIG :      \[OpenVPN\] Configuration file  
**-d**, --discover :      Port scan before attacking open ports  
**-v**, --verbose :      Enable verbose output (-vv for more)  
**-D**, --debug :      Enable debug mode  
**-q**, --quiet :      Only display successful logins