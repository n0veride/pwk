

# Setup
Uses a postgreSQL db for storing information about target hosts and keeping track of successful exploitation attempts, etc.

- Start postgreSQL service
```bash
sudo systemctl start postgresql.service

#enable at boot time
sudo systemctl enable postgresql.service
```

- Create and initialize MSF database
```bash
sudo msfdb init
	[i] Database already started
	[+] Creating database user 'msf'
	[+] Creating databases 'msf'
	[+] Creating databases 'msf_test'
	[+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
	[+] Creating initial database schema
```

- Should update as often as possible as it's always being updated
```bash
sudo apt update; sudo apt install metasploit-framework
```

- Launch
```bash
msfconsole
```

- Check status of db
```bash
db_status
	[*] Connected to msf. Connection type: postgresql.
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