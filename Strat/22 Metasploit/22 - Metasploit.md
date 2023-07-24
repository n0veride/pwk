

#### Setup:

Depends on *postgresql* to be active:
```bash
sudo systemctl start postgresql.service

#enable at boot time
sudo systemctl enable postgresql.service
```

Need to create and initialize MSF database:
```bash
sudo msfdb init
```

Should update as often as possible as it's always being updated:
```bash
sudo apt update; sudo apt install metasploit-framework
```

Launch:
```bash
msfconsole
```


#### Syntax:

Includes several thousand modules divided into categories.

Can view on splashscreen or w/:
```bash
show -h
```

Activate/ Switch/ Leave a module:
```bash
# use <module name>
msf6 > use auxiliary/scanner/portscan/tcp

# switch
msf6 auxiliary(scanner/portscan/tcp) > use auxiliary/scanner/portscan/syn
msf6 auxiliary(scanner/portscan/syn) > previous
msf6 auxiliary(scanner/portscan/tcp) >

# leave
msf6 auxiliary(scanner/portscan/tcp) > back
msf6 > 
```

Show/ Configure options:
```bash
#Show
show options

#Configure options - set & remove
set LHOST
unset RHOST

#Configure global options - set & remove
setg LHOST
unsetg LPORT
```

Run:
```bash
#two ways to send exploit
run
exploit
```