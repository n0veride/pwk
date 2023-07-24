

Cmdline SSH client (part of PUTTY)  
  
  
Usage Ex:  
```bash
cmd.exe /c echo y | plink.exe -ssh -l kali -pw <kali_pw> <r_ip>:<r_port>:127.0.0.1:<l_port> <r_ip>
```


**cmd.exe /c echo y** - As first time plink connects to a host, it'll attempt to cache the host key in the registry.  
	Likely we won't have the necessary interactivity w/in our remote shell, hence this addition.  
	If doing through rdesktop, there's no need.  
  
  
**-V**      Print version information and exit  
**-pgpfp**      Print PGP key fingerprints and exit  
**-v**      Show verbose messages  
**-load**      _sessname_ Load settings from saved session  
**-ssh -telnet -rlogin -raw**      Force use of a particular protocol  
**-P** _port_      Connect to specified port  
**-l** _user_      Connect with specified username  
**-batch**      Disable all interactive prompts  
  
The following options only apply to SSH connections:  
  
**-pw**      Passw login with specified password  
**-D** _\[listen-IP\:\]listen-port_      Dynamic SOCKS-based port forwarding  
**-L** _\[listen-IP\:\]listen-port:host:port_      Forward local port to remote address  
**-R** _\[listen-IP\:\]listen-port:host:port_      Forward remote port to local address  
**-X** / **-x**      Enable / disable X11 forwarding  
**-A** / **-a**      Enable / disable agent forwarding  
**-t** / **-T**      Enable / disable pty allocation  
**-1** / **-2**      Force use of particular protocol version  
**-4** / **-6**      Force use of IPv4 or IPv6  
**-C**      Enable compression  
**-i** _keyfile_      Private key file for authentication  
**-noagent**      Disable use of Pageant  
**-agent**      Enable use of Pageant  
**-m** _file_      Read remote command(s) from file  
**-s**      Semote command is an SSH subsystem (SSH-2 only)  
**-N**      Don't start a shell/command (SSH-2 only)  
**-nc** _host:port_      Open tunnel in place of session (SSH-2 only)