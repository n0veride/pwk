

Network Service attack tool  
  
Usage Ex:  
```bash
hydra 192.168.180.10 http-form-post "/form /frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f
```


-l LOGIN or -L FILE :      Login with LOGIN name, or load several logins from FILE  
-p PASS or -P FILE :      Try password PASS, or load several passwords from FILE  
-C FILE :      Colon separated "login:pass" format, instead of -L/-P options  
-M FILE :      List of servers to attack, one entry per line, ':' to specify port  
-t TASKS :      Run TASKS number of connects in parallel per target (default: 16)  
-U :      Service module usage details  
-m OPT :      Options specific for a module, see -U output for information  
-h :      More command line options (COMPLETE HELP)  
server :      The target: DNS, IP or 192.168.0.0/24 (this OR the -M option)  
service :      The service to crack (see below for supported protocols)  
OPT :      Some service modules support additional input (-U for module help)  
  

Supported services:  
  
adam6500, asterisk, cisco, cisco-enable, cobaltstrike, cvs, firebird, ftp[s], http[s]-{head|get|post}, http[s]-{get|post}-form, http-proxy, http-proxy-urlenum,  
icq, imap[s], irc, ldap2[s], ldap3[-{cram|digest}, md5][s], memcached, mongodb, mssql, mysql, nntp, oracle-listener, oracle-sid, pcanywhere, pcnfs, pop3[s],  
postgres, radmin2, rdp, redis, rexec, rlogin, rpcap, rsh, rtsp, s7-300, sip, smb, smtp[s], smtp-enum, snmp, socks5, ssh, sshkey, svn, teamspeak, telnet[s], vmauthd, vnc, xmpp  
  
  
To view info about a service's required args:
```bash
hydra <service> -U
```