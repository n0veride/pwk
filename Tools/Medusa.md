
“Speedy, massively parallel, modular, login brute forcer”  
  
  
Usage:
```bash
Medusa [-h host|-H file] [-u username|-U file] [-p password|-P file] [-C file] -M module [OPT]
```


**-h** \[TEXT\] :      Target hostname or IP address  
**-H** \[FILE\] :      File containing target hostnames or IP addresses  
**-u** \[TEXT\] :      Username to test  
**-U** \[FILE\] :      File containing usernames to test  
**-p** \[TEXT\] :      Password to test  
**-P** \[FILE\] :      File containing passwords to test  
**-C** \[FILE\] :      File containing combo entries. See README for more information.  
**-O** \[FILE\] :      File to append log information to  
**-e** \[n/s/ns\] :      Additional password checks (\[n\] No Password, \[s\] Password = Username)  
**-M** \[TEXT\] :      Name of the module to execute (without the .mod extension)  
**-m** \[TEXT\] :      Parameter to pass to the module. This can be passed multiple times with a different parameter each time and they will all be sent to the module (i.e. -m Param1 -m Param2, etc.)  
**-d** :      Dump all known modules  
**-n** \[NUM\] :      Use for non-default TCP port number  
**-s** : Enable SSL  
**-g** \[NUM\] :      Give up after trying to connect for NUM seconds (default 3)  
**-r** \[NUM\] :      Sleep NUM seconds between retry attempts (default 3)  
**-R** \[NUM\] :      Attempt NUM retries before giving up. The total number of attempts will be NUM + 1.  
**-c** \[NUM\] :      Time to wait in usec to verify socket is available (default 500 usec).  
**-t** \[NUM\] :      Total number of logins to be tested concurrently  
**-T** \[NUM\] :      Total number of hosts to be tested concurrently  
**-L** :      Parallelize logins using one username per thread. The default is to process the entire username before proceeding.  
**-f** :      Stop scanning host after first valid username/password found.  
**-F** :      Stop audit after first valid username/password found on any host.  
**-b** :      Suppress startup banner  
**-q** :      Display module's usage information  
**-v** \[NUM\] :      Verbose level \[0 - 6 (more)\]  
**-w** \[NUM\] :      Error debug level \[0 - 10 (more)\]  
**-V** :      Display version  
**-Z** \[TEXT\] :      Resume scan based on map of previous scan  
  

Modules:  
  
Available modules in "_/usr/lib/x86_64-linux-gnu/medusa/modules_" :  
+ cvs.mod :      Brute force module for CVS sessions : version 2.0  
+ ftp.mod :      Brute force module for FTP/FTPS sessions : version 2.1  
+ http.mod :      Brute force module for HTTP : version 2.1  
+ imap.mod :      Brute force module for IMAP sessions : version 2.0  
+ mssql.mod :      Brute force module for M$-SQL sessions : version 2.0  
+ mysql.mod :      Brute force module for MySQL sessions : version 2.0  
+ nntp.mod :      Brute force module for NNTP sessions : version 2.0  
+ pcanywhere.mod :      Brute force module for PcAnywhere sessions : version 2.0  
+ pop3.mod :      Brute force module for POP3 sessions : version 2.0  
+ postgres.mod :      Brute force module for PostgreSQL sessions : version 2.0  
+ rexec.mod :      Brute force module for REXEC sessions : version 2.0  
+ rlogin.mod :      Brute force module for RLOGIN sessions : version 2.0  
+ rsh.mod :      Brute force module for RSH sessions : version 2.0  
+ smbnt.mod :      Brute force module for SMB (LM/NTLM/LMv2/NTLMv2) sessions : version 2.1  
+ smtp-vrfy.mod :      Brute force module for verifying SMTP accounts (VRFY/EXPN/RCPT TO) : version 2.1  
+ smtp.mod :      Brute force module for SMTP Authentication with TLS : version 2.0  
+ snmp.mod :      Brute force module for SNMP Community Strings : version 2.1  
+ ssh.mod :      Brute force module for SSH v2 sessions : version 2.1  
+ svn.mod :      Brute force module for Subversion sessions : version 2.1  
+ telnet.mod :      Brute force module for telnet sessions : version 2.0  
+ vmauthd.mod :      Brute force module for the VMware Authentication Daemon : version 2.0  
+ vnc.mod :      Brute force module for VNC sessions : version 2.1  
+ web-form.mod :      Brute force module for web forms : version 2.1  
+ wrapper.mod :      Generic Wrapper Module : version 2.0